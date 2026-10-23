//! BitTorrent v1 metainfo: parse and validate, strip/inject announce, and build.
//!
//! The server never trusts client-supplied metadata: it derives the infohash, name,
//! size and file list from the torrent itself with [`parse`] (spec §4.4).

use std::fs::File;
use std::io::{BufReader, Read};
use std::ops::ControlFlow;
use std::path::{Path, PathBuf};

use sha1::{Digest, Sha1};

use crate::api::{FileEntry, limits};
use crate::bencode::{self, BencodeError, Value};

#[derive(Debug, thiserror::Error)]
pub enum TorrentError {
    #[error("not a valid torrent file: {0}")]
    Bencode(#[from] BencodeError),
    #[error("not a valid torrent file: {0}")]
    Invalid(&'static str),
    #[error("torrent must be private (info.private = 1)")]
    NotPrivate,
    #[error("unsafe file name or path: {0:?}")]
    UnsafePath(String),
    #[error("torrent is too large or has too many files")]
    TooLarge,
    #[error("nothing to share: {0}")]
    Empty(String),
    #[error("cancelled")]
    Cancelled,
    #[error("{0}: {1}")]
    Io(PathBuf, std::io::Error),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedTorrent {
    /// Lowercase hex SHA-1 of the bencoded `info` dictionary.
    pub infohash: String,
    pub name: String,
    pub size: u64,
    /// Paths relative to the torrent root, `/`-separated. For a single-file torrent
    /// this is one entry whose path is the name.
    pub files: Vec<FileEntry>,
    pub private: bool,
    pub piece_length: u64,
    pub announce: Option<String>,
}

impl ParsedTorrent {
    pub fn is_multi_file(&self) -> bool {
        !(self.files.len() == 1 && self.files[0].path == self.name)
    }
}

/// Is this a safe single path component (file or directory name)?
pub fn is_safe_component(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= limits::MAX_PATH_COMPONENT_LEN
        && s != "."
        && s != ".."
        && !s.chars().any(|c| c == '/' || c == '\\' || c.is_control())
}

pub fn infohash_of(info_bytes: &[u8]) -> String {
    hex::encode(Sha1::digest(info_bytes))
}

/// Parse and validate a v1 torrent. Does not require `private`; see [`parse_private`].
pub fn parse(bytes: &[u8]) -> Result<ParsedTorrent, TorrentError> {
    if bytes.len() > limits::MAX_TORRENT_BYTES {
        return Err(TorrentError::TooLarge);
    }
    let top = bencode::decode_dict_raw(bytes)?;
    let info_raw = top
        .iter()
        .find(|(k, _)| k == b"info")
        .map(|(_, v)| *v)
        .ok_or(TorrentError::Invalid("missing info dictionary"))?;
    let announce = top
        .iter()
        .find(|(k, _)| k == b"announce")
        .and_then(|(_, v)| bencode::decode(v).ok())
        .and_then(|v| v.as_str().map(str::to_owned));

    let info = bencode::decode(info_raw)?;
    if info.as_dict().is_none() {
        return Err(TorrentError::Invalid("info is not a dictionary"));
    }

    let name = info
        .get("name")
        .and_then(Value::as_str)
        .ok_or(TorrentError::Invalid("missing or non-UTF-8 name"))?
        .to_owned();
    if !is_safe_component(&name) {
        return Err(TorrentError::UnsafePath(name));
    }

    let piece_length = info
        .get("piece length")
        .and_then(Value::as_int)
        .filter(|&n| n > 0)
        .ok_or(TorrentError::Invalid("missing piece length"))? as u64;
    let pieces = info
        .get("pieces")
        .and_then(Value::as_bytes)
        .ok_or(TorrentError::Invalid(
            "missing pieces (v2-only torrents are not supported)",
        ))?;
    if pieces.len() % 20 != 0 {
        return Err(TorrentError::Invalid(
            "pieces length is not a multiple of 20",
        ));
    }

    let files = match (info.get("length"), info.get("files")) {
        (Some(len), None) => {
            let size = non_negative(len)?;
            vec![FileEntry {
                path: name.clone(),
                size,
            }]
        }
        (None, Some(files)) => parse_files(files)?,
        _ => {
            return Err(TorrentError::Invalid(
                "needs exactly one of length or files",
            ));
        }
    };
    let size = files
        .iter()
        .try_fold(0u64, |acc, f| acc.checked_add(f.size))
        .ok_or(TorrentError::TooLarge)?;
    let expected_pieces = size.div_ceil(piece_length);
    if expected_pieces != (pieces.len() / 20) as u64 {
        return Err(TorrentError::Invalid(
            "piece count doesn't match total size",
        ));
    }

    let private = info.get("private").and_then(Value::as_int) == Some(1);

    Ok(ParsedTorrent {
        infohash: infohash_of(info_raw),
        name,
        size,
        files,
        private,
        piece_length,
        announce,
    })
}

/// [`parse`], and also require `info.private = 1`.
pub fn parse_private(bytes: &[u8]) -> Result<ParsedTorrent, TorrentError> {
    let t = parse(bytes)?;
    if !t.private {
        return Err(TorrentError::NotPrivate);
    }
    Ok(t)
}

fn non_negative(v: &Value) -> Result<u64, TorrentError> {
    v.as_int()
        .filter(|&n| n >= 0)
        .map(|n| n as u64)
        .ok_or(TorrentError::Invalid("bad file length"))
}

fn parse_files(files: &Value) -> Result<Vec<FileEntry>, TorrentError> {
    let list = files
        .as_list()
        .ok_or(TorrentError::Invalid("files is not a list"))?;
    if list.is_empty() {
        return Err(TorrentError::Invalid("empty file list"));
    }
    if list.len() > limits::MAX_FILES {
        return Err(TorrentError::TooLarge);
    }
    let mut out = Vec::with_capacity(list.len());
    for f in list {
        let size = non_negative(
            f.get("length")
                .ok_or(TorrentError::Invalid("file without length"))?,
        )?;
        let parts = f
            .get("path")
            .and_then(Value::as_list)
            .filter(|p| !p.is_empty())
            .ok_or(TorrentError::Invalid("file without path"))?;
        let mut comps = Vec::with_capacity(parts.len());
        for p in parts {
            let c = p.as_str().ok_or(TorrentError::Invalid("non-UTF-8 path"))?;
            if !is_safe_component(c) {
                return Err(TorrentError::UnsafePath(c.to_owned()));
            }
            comps.push(c);
        }
        out.push(FileEntry {
            path: comps.join("/"),
            size,
        });
    }
    Ok(out)
}

/// Keep only what peers need: `info` (byte for byte) and `creation date`. Drops
/// announce, announce-list, comment, created by, url-list and anything unknown.
pub fn strip(bytes: &[u8]) -> Result<Vec<u8>, TorrentError> {
    let top = bencode::decode_dict_raw(bytes)?;
    let kept: Vec<(Vec<u8>, Vec<u8>)> = top
        .into_iter()
        .filter(|(k, _)| k == b"info" || k == b"creation date")
        .map(|(k, v)| (k, v.to_vec()))
        .collect();
    Ok(bencode::encode_dict_raw(&kept))
}

/// Return the torrent with `announce` set to `url` (replacing any existing one).
/// The infohash is unchanged because `info` is copied verbatim.
pub fn with_announce(bytes: &[u8], url: &str) -> Result<Vec<u8>, TorrentError> {
    let top = bencode::decode_dict_raw(bytes)?;
    let mut entries: Vec<(Vec<u8>, Vec<u8>)> = top
        .into_iter()
        .filter(|(k, _)| k != b"announce" && k != b"announce-list")
        .map(|(k, v)| (k, v.to_vec()))
        .collect();
    entries.push((b"announce".to_vec(), Value::from(url).encode()));
    Ok(bencode::encode_dict_raw(&entries))
}

/// Pick a piece length: a power of two from 16 KiB to 16 MiB, aiming for at most
/// about 1500 pieces.
pub fn auto_piece_length(total: u64) -> u64 {
    let mut pl: u64 = 16 * 1024;
    while pl < 16 * 1024 * 1024 && total.div_ceil(pl) > 1500 {
        pl *= 2;
    }
    pl
}

#[derive(Debug, Clone)]
pub struct BuildOptions {
    pub private: bool,
    pub piece_length: Option<u64>,
    pub announce: Option<String>,
    pub created_by: Option<String>,
    pub creation_date: Option<i64>,
}

impl Default for BuildOptions {
    fn default() -> Self {
        Self {
            private: true,
            piece_length: None,
            announce: None,
            created_by: Some(concat!("lemonwire/", env!("CARGO_PKG_VERSION")).to_owned()),
            creation_date: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct BuiltTorrent {
    pub bytes: Vec<u8>,
    pub parsed: ParsedTorrent,
}

/// Build a torrent from a file or a directory. Directories are walked recursively in
/// sorted order; symlinks and special files are skipped so nothing outside `path` is
/// shared. `progress` is called with (bytes hashed, total) after each piece; returning
/// [`ControlFlow::Break`] stops hashing with [`TorrentError::Cancelled`].
pub fn build(
    path: &Path,
    opts: &BuildOptions,
    mut progress: impl FnMut(u64, u64) -> ControlFlow<()>,
) -> Result<BuiltTorrent, TorrentError> {
    let io = |e| TorrentError::Io(path.to_owned(), e);
    let meta = std::fs::symlink_metadata(path).map_err(io)?;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| TorrentError::UnsafePath(path.display().to_string()))?
        .to_owned();
    if !is_safe_component(&name) {
        return Err(TorrentError::UnsafePath(name));
    }

    // (path on disk, components relative to root, size)
    let mut files: Vec<(PathBuf, Vec<String>, u64)> = Vec::new();
    if meta.is_file() {
        files.push((path.to_owned(), vec![], meta.len()));
    } else if meta.is_dir() {
        walk(path, &mut Vec::new(), &mut files)?;
        if files.is_empty() {
            return Err(TorrentError::Empty(format!(
                "{} has no files",
                path.display()
            )));
        }
    } else {
        return Err(TorrentError::Empty(format!(
            "{} is not a regular file or directory",
            path.display()
        )));
    }
    if files.len() > limits::MAX_FILES {
        return Err(TorrentError::TooLarge);
    }

    let total: u64 = files.iter().map(|f| f.2).sum();
    let piece_length = opts
        .piece_length
        .unwrap_or_else(|| auto_piece_length(total));
    let pieces = hash_pieces(&files, piece_length, total, &mut progress)?;

    let mut info = std::collections::BTreeMap::new();
    info.insert(b"name".to_vec(), Value::from(name.as_str()));
    info.insert(b"piece length".to_vec(), Value::Int(piece_length as i64));
    info.insert(b"pieces".to_vec(), Value::Bytes(pieces));
    if opts.private {
        info.insert(b"private".to_vec(), Value::Int(1));
    }
    if meta.is_file() {
        info.insert(b"length".to_vec(), Value::Int(total as i64));
    } else {
        let list = files
            .iter()
            .map(|(_, comps, size)| {
                let mut d = std::collections::BTreeMap::new();
                d.insert(b"length".to_vec(), Value::Int(*size as i64));
                d.insert(
                    b"path".to_vec(),
                    Value::List(comps.iter().map(|c| Value::from(c.as_str())).collect()),
                );
                Value::Dict(d)
            })
            .collect();
        info.insert(b"files".to_vec(), Value::List(list));
    }

    let mut top = std::collections::BTreeMap::new();
    top.insert(b"info".to_vec(), Value::Dict(info));
    if let Some(a) = &opts.announce {
        top.insert(b"announce".to_vec(), Value::from(a.as_str()));
    }
    if let Some(c) = &opts.created_by {
        top.insert(b"created by".to_vec(), Value::from(c.as_str()));
    }
    if let Some(d) = opts.creation_date {
        top.insert(b"creation date".to_vec(), Value::Int(d));
    }
    let bytes = Value::Dict(top).encode();
    let parsed = parse(&bytes)?;
    Ok(BuiltTorrent { bytes, parsed })
}

fn walk(
    dir: &Path,
    prefix: &mut Vec<String>,
    out: &mut Vec<(PathBuf, Vec<String>, u64)>,
) -> Result<(), TorrentError> {
    let io = |e| TorrentError::Io(dir.to_owned(), e);
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .map_err(io)?
        .collect::<Result<_, _>>()
        .map_err(io)?;
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        let name = e.file_name();
        let name = name
            .to_str()
            .ok_or_else(|| TorrentError::UnsafePath(e.path().display().to_string()))?
            .to_owned();
        if !is_safe_component(&name) {
            return Err(TorrentError::UnsafePath(name));
        }
        let ft = e.file_type().map_err(io)?;
        prefix.push(name);
        if ft.is_dir() {
            walk(&e.path(), prefix, out)?;
        } else if ft.is_file() {
            let len = e.metadata().map_err(io)?.len();
            out.push((e.path(), prefix.clone(), len));
            if out.len() > limits::MAX_FILES {
                return Err(TorrentError::TooLarge);
            }
        }
        prefix.pop();
    }
    Ok(())
}

fn hash_pieces(
    files: &[(PathBuf, Vec<String>, u64)],
    piece_length: u64,
    total: u64,
    progress: &mut impl FnMut(u64, u64) -> ControlFlow<()>,
) -> Result<Vec<u8>, TorrentError> {
    let mut pieces = Vec::with_capacity((total.div_ceil(piece_length) * 20) as usize);
    let mut hasher = Sha1::new();
    let mut in_piece: u64 = 0;
    let mut done: u64 = 0;
    let mut buf = vec![0u8; 1 << 20];
    for (path, _, expected) in files {
        let io = |e| TorrentError::Io(path.clone(), e);
        let mut r = BufReader::new(File::open(path).map_err(io)?);
        let mut read_total = 0u64;
        loop {
            let want = buf.len().min((piece_length - in_piece) as usize);
            let n = r.read(&mut buf[..want]).map_err(io)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            in_piece += n as u64;
            read_total += n as u64;
            done += n as u64;
            if in_piece == piece_length {
                pieces.extend_from_slice(&hasher.finalize_reset());
                in_piece = 0;
                if progress(done, total).is_break() {
                    return Err(TorrentError::Cancelled);
                }
            }
        }
        if read_total != *expected {
            return Err(TorrentError::Io(
                path.clone(),
                std::io::Error::other("file changed while it was being hashed"),
            ));
        }
    }
    if in_piece > 0 {
        pieces.extend_from_slice(&hasher.finalize());
    }
    if progress(done, total).is_break() {
        return Err(TorrentError::Cancelled);
    }
    Ok(pieces)
}

/// Join a torrent-relative `/`-separated path onto `dest`, refusing anything that
/// could escape it. Used by clients as a second check after the server's.
pub fn safe_join(dest: &Path, relative: &str) -> Result<PathBuf, TorrentError> {
    let mut out = dest.to_owned();
    for c in relative.split('/') {
        if !is_safe_component(c) {
            return Err(TorrentError::UnsafePath(relative.to_owned()));
        }
        out.push(c);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn torrent(info: Value, extra: &[(&str, Value)]) -> Vec<u8> {
        let mut top = BTreeMap::new();
        top.insert(b"info".to_vec(), info);
        for (k, v) in extra {
            top.insert(k.as_bytes().to_vec(), v.clone());
        }
        Value::Dict(top).encode()
    }

    fn single(name: &str, private: bool) -> Value {
        let mut info = BTreeMap::new();
        info.insert(b"name".to_vec(), Value::from(name));
        info.insert(b"piece length".to_vec(), Value::Int(16384));
        info.insert(b"pieces".to_vec(), Value::Bytes(vec![0; 20]));
        info.insert(b"length".to_vec(), Value::Int(10));
        if private {
            info.insert(b"private".to_vec(), Value::Int(1));
        }
        Value::Dict(info)
    }

    #[test]
    fn parses_and_requires_private() {
        let t = torrent(single("a.txt", true), &[]);
        let p = parse_private(&t).unwrap();
        assert_eq!(p.name, "a.txt");
        assert_eq!(p.size, 10);
        assert!(!p.is_multi_file());
        let t = torrent(single("a.txt", false), &[]);
        assert!(matches!(parse_private(&t), Err(TorrentError::NotPrivate)));
    }

    #[test]
    fn rejects_unsafe_names() {
        for bad in ["..", ".", "a/b", "a\\b", "", "x\u{0}y"] {
            let t = torrent(single(bad, true), &[]);
            assert!(parse(&t).is_err(), "accepted {bad:?}");
        }
        let mut info = BTreeMap::new();
        info.insert(b"name".to_vec(), Value::from("dir"));
        info.insert(b"piece length".to_vec(), Value::Int(16384));
        info.insert(b"pieces".to_vec(), Value::Bytes(vec![0; 20]));
        info.insert(b"private".to_vec(), Value::Int(1));
        let mut f = BTreeMap::new();
        f.insert(b"length".to_vec(), Value::Int(1));
        f.insert(
            b"path".to_vec(),
            Value::List(vec![Value::from(".."), Value::from("etc")]),
        );
        info.insert(b"files".to_vec(), Value::List(vec![Value::Dict(f)]));
        assert!(matches!(
            parse(&torrent(Value::Dict(info), &[])),
            Err(TorrentError::UnsafePath(_))
        ));
    }

    #[test]
    fn strip_and_inject_keep_infohash() {
        let t = torrent(
            single("a.txt", true),
            &[
                ("announce", Value::from("http://t/announce?passkey=SECRET")),
                ("comment", Value::from("hi")),
                ("created by", Value::from("someone")),
                ("announce-list", Value::List(vec![])),
            ],
        );
        let before = parse(&t).unwrap();
        let stripped = strip(&t).unwrap();
        let s = String::from_utf8_lossy(&stripped);
        assert!(!s.contains("SECRET") && !s.contains("comment") && !s.contains("created by"));
        assert_eq!(parse(&stripped).unwrap().infohash, before.infohash);
        let injected = with_announce(&stripped, "http://t/announce?passkey=MINE").unwrap();
        let after = parse(&injected).unwrap();
        assert_eq!(after.infohash, before.infohash);
        assert_eq!(
            after.announce.as_deref(),
            Some("http://t/announce?passkey=MINE")
        );
    }

    #[test]
    fn build_file_and_dir() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("share");
        std::fs::create_dir_all(root.join("sub")).unwrap();
        std::fs::write(root.join("b.bin"), vec![7u8; 40_000]).unwrap();
        std::fs::write(root.join("sub/a.txt"), b"hello").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("/etc/passwd", root.join("link")).unwrap();

        let built = build(&root, &BuildOptions::default(), |_, _| {
            ControlFlow::Continue(())
        })
        .unwrap();
        let p = parse_private(&built.bytes).unwrap();
        assert_eq!(p.name, "share");
        assert_eq!(p.size, 40_005);
        let paths: Vec<_> = p.files.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(paths, ["b.bin", "sub/a.txt"]);
        assert!(p.is_multi_file());

        let single = build(&root.join("b.bin"), &BuildOptions::default(), |_, _| {
            ControlFlow::Continue(())
        })
        .unwrap();
        assert_eq!(single.parsed.files.len(), 1);
        assert!(!single.parsed.is_multi_file());
        // 40000 bytes at 16 KiB pieces = 3 pieces.
        assert_eq!(single.parsed.piece_length, 16384);
    }

    #[test]
    fn piece_hashes_are_correct() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("x");
        let data: Vec<u8> = (0..50_000u32).map(|i| (i % 251) as u8).collect();
        std::fs::write(&f, &data).unwrap();
        let built = build(&f, &BuildOptions::default(), |_, _| {
            ControlFlow::Continue(())
        })
        .unwrap();
        let v = bencode::decode(&built.bytes).unwrap();
        let pieces = v
            .get("info")
            .unwrap()
            .get("pieces")
            .unwrap()
            .as_bytes()
            .unwrap();
        for (i, chunk) in data.chunks(16384).enumerate() {
            assert_eq!(&pieces[i * 20..i * 20 + 20], Sha1::digest(chunk).as_slice());
        }
    }

    #[test]
    fn build_can_be_cancelled() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("x");
        std::fs::write(&f, vec![0u8; 100_000]).unwrap();
        let r = build(&f, &BuildOptions::default(), |done, _| {
            if done > 20_000 {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            }
        });
        assert!(matches!(r, Err(TorrentError::Cancelled)));
    }

    #[test]
    fn auto_piece_length_bounds() {
        assert_eq!(auto_piece_length(0), 16 * 1024);
        assert_eq!(auto_piece_length(1_000_000), 16 * 1024);
        let pl = auto_piece_length(10 * 1024 * 1024 * 1024);
        assert!(pl.is_power_of_two() && (10u64 << 30).div_ceil(pl) <= 1500);
        assert_eq!(auto_piece_length(u64::MAX / 2), 16 * 1024 * 1024);
    }

    #[test]
    fn safe_join_blocks_escape() {
        let d = Path::new("/dl");
        assert_eq!(safe_join(d, "a/b").unwrap(), Path::new("/dl/a/b"));
        assert!(safe_join(d, "../x").is_err());
        assert!(safe_join(d, "a//b").is_err());
    }
}
