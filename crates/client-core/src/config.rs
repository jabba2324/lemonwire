//! On-disk client state: `profiles.json` and `transfers.json` in the config directory.
//! Secret keys are never stored here (see [`crate::keystore`]).

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::command::{ProfileView, TransferKind};
use crate::error::{ClientError, Result};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Profile {
    pub name: String,
    pub url: String,
    /// The pinned server key; every login verifies the server against it.
    pub server_pubkey: String,
    /// Your name on the index, once known.
    #[serde(default, alias = "display_name")]
    pub member_name: Option<String>,
    pub public_key: String,
    #[serde(default)]
    pub default: bool,
    /// The user allowed plain http:// to a public host for this index.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub allow_insecure: bool,
}

impl Profile {
    pub fn view(&self) -> ProfileView {
        ProfileView {
            name: self.name.clone(),
            url: self.url.clone(),
            member_name: self.member_name.clone(),
            public_key: self.public_key.clone(),
            public_key_fingerprint: lemonwire_proto::keys::fingerprint(&self.public_key),
            server_pubkey: self.server_pubkey.clone(),
            server_fingerprint: lemonwire_proto::keys::fingerprint(&self.server_pubkey),
            default: self.default,
        }
    }
}

/// A transfer the client should keep running across restarts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TransferRecord {
    pub infohash: String,
    pub name: String,
    pub profile: String,
    pub kind: TransferKind,
    /// For a seed, the shared file or folder. For a download, the destination folder.
    pub path: PathBuf,
    /// The .torrent, including this member's announce URL (so the file is 0600).
    pub torrent_b64: String,
    #[serde(default)]
    pub paused: bool,
    /// For a download, only these file indexes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub files: Option<Vec<usize>>,
    pub added_at: i64,
}

#[derive(Debug, Clone)]
pub struct ConfigDir {
    root: PathBuf,
}

impl ConfigDir {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// `~/.config/lemonwire` on Linux, the platform equivalent elsewhere.
    pub fn default_location() -> Result<Self> {
        let dirs = directories::ProjectDirs::from("", "", "lemonwire")
            .ok_or_else(|| ClientError::Invalid("can't find a home directory".into()))?;
        Ok(Self::new(dirs.config_dir()))
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn keys_dir(&self) -> PathBuf {
        self.root.join("keys")
    }

    pub fn engine_dir(&self) -> PathBuf {
        self.root.join("engine")
    }

    /// Take the engine lock: only one process per config dir runs a torrent engine, so
    /// two never fight over the peer port or the transfer list. Held until dropped.
    pub fn lock_engine(&self) -> Result<EngineLock> {
        self.ensure()?;
        let path = self.root.join("engine.lock");
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&path)
            .map_err(|e| ClientError::Io(path.clone(), e))?;
        match file.try_lock() {
            Ok(()) => Ok(EngineLock { _file: file }),
            Err(std::fs::TryLockError::WouldBlock) => Err(ClientError::EngineBusy),
            Err(std::fs::TryLockError::Error(e)) => Err(ClientError::Io(path, e)),
        }
    }

    pub fn ensure(&self) -> Result<()> {
        create_private_dir(&self.root)
    }

    pub fn load_profiles(&self) -> Result<Vec<Profile>> {
        read_json(&self.root.join("profiles.json"))
    }

    pub fn save_profiles(&self, profiles: &[Profile]) -> Result<()> {
        self.ensure()?;
        write_json_private(&self.root.join("profiles.json"), &profiles)
    }

    pub fn load_transfers(&self) -> Result<Vec<TransferRecord>> {
        read_json(&self.root.join("transfers.json"))
    }

    pub fn save_transfers(&self, transfers: &[TransferRecord]) -> Result<()> {
        self.ensure()?;
        write_json_private(&self.root.join("transfers.json"), &transfers)
    }
}

/// Proof that this process owns the config dir's torrent engine (see
/// [`ConfigDir::lock_engine`]). The OS releases it when the file is closed.
#[derive(Debug)]
pub struct EngineLock {
    _file: std::fs::File,
}

pub fn create_private_dir(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir).map_err(|e| ClientError::Io(dir.to_owned(), e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| ClientError::Io(dir.to_owned(), e))?;
    }
    Ok(())
}

fn read_json<T: for<'de> Deserialize<'de> + Default>(path: &Path) -> Result<T> {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map_err(|e| ClientError::Invalid(format!("{}: {e}", path.display()))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(T::default()),
        Err(e) => Err(ClientError::Io(path.to_owned(), e)),
    }
}

/// Write via a temp file and rename, so a crash never leaves a half-written file.
/// The file is created 0600.
pub fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let io = |e| ClientError::Io(path.to_owned(), e);
    let tmp = path.with_extension("tmp");
    {
        use std::io::Write;
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp).map_err(io)?;
        f.write_all(bytes).map_err(io)?;
        f.sync_all().map_err(io)?;
    }
    std::fs::rename(&tmp, path).map_err(io)
}

fn write_json_private<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value).expect("serialisable");
    write_private(path, &bytes)
}

pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
