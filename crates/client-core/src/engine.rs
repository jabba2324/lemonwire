//! The torrent engine abstraction (spec §5.5), plus an in-memory mock for tests.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::error::{ClientError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TransferId(pub u64);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferState {
    /// Checking existing data against piece hashes.
    Checking,
    Downloading,
    Seeding,
    Paused,
    Error(String),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TransferStatus {
    pub id: TransferId,
    pub infohash: String,
    pub name: String,
    pub state: TransferState,
    pub progress_bytes: u64,
    pub total_bytes: u64,
    pub uploaded_bytes: u64,
    pub download_bps: u64,
    pub upload_bps: u64,
    pub peers: u32,
    pub finished: bool,
}

#[async_trait]
pub trait TorrentEngine: Send + Sync {
    /// Seed existing data. `data_path` is the shared file or folder itself.
    async fn add_seed(&self, torrent: &[u8], data_path: &Path) -> Result<TransferId>;
    /// Download into `dest`. A folder torrent lands in `dest/<name>`, a file in `dest`.
    /// `only_files` limits it to those indexes of the torrent's file list.
    async fn add_download(
        &self,
        torrent: &[u8],
        dest: &Path,
        only_files: Option<&[usize]>,
    ) -> Result<TransferId>;
    async fn status(&self) -> Result<Vec<TransferStatus>>;
    async fn pause(&self, id: TransferId) -> Result<()>;
    async fn resume(&self, id: TransferId) -> Result<()>;
    async fn remove(&self, id: TransferId, delete_data: bool) -> Result<()>;
    /// Engine-wide speed limits in bytes per second (`None` = unlimited).
    async fn set_limits(&self, _upload_bps: Option<u32>, _download_bps: Option<u32>) -> Result<()> {
        Ok(())
    }
    /// How long a finished download must keep running for the tracker to hear it's
    /// complete (one announce). `share` relies on that to know a friend has a copy.
    fn completion_grace(&self) -> std::time::Duration {
        std::time::Duration::ZERO
    }
    async fn shutdown(&self) {}
}

/// Records calls and pretends every transfer completes instantly. Downloads copy
/// nothing; tests check the bookkeeping, not the bytes.
#[derive(Default)]
pub struct MockEngine {
    inner: Mutex<MockInner>,
}

#[derive(Default)]
struct MockInner {
    next: u64,
    transfers: HashMap<TransferId, (TransferStatus, PathBuf)>,
    only_files: HashMap<String, Vec<usize>>,
    limits: (Option<u32>, Option<u32>),
}

impl MockEngine {
    fn add(&self, torrent: &[u8], path: &Path, seeding: bool) -> Result<TransferId> {
        let parsed = lemonwire_proto::metainfo::parse(torrent)?;
        let mut inner = self.inner.lock().expect("mock lock");
        if inner
            .transfers
            .values()
            .any(|(s, _)| s.infohash == parsed.infohash)
        {
            return Err(ClientError::Engine("already managed".into()));
        }
        inner.next += 1;
        let id = TransferId(inner.next);
        let status = TransferStatus {
            id,
            infohash: parsed.infohash,
            name: parsed.name,
            state: if seeding {
                TransferState::Seeding
            } else {
                TransferState::Downloading
            },
            progress_bytes: if seeding { parsed.size } else { 0 },
            total_bytes: parsed.size,
            uploaded_bytes: 0,
            download_bps: 0,
            upload_bps: 0,
            peers: 0,
            finished: seeding,
        };
        inner.transfers.insert(id, (status, path.to_owned()));
        Ok(id)
    }

    /// Pretend a download finished, and that `uploaded` bytes were seeded back.
    pub fn complete(&self, infohash: &str, uploaded: u64) {
        let mut inner = self.inner.lock().expect("mock lock");
        if let Some((s, _)) = inner
            .transfers
            .values_mut()
            .find(|(s, _)| s.infohash == infohash)
        {
            s.finished = true;
            s.progress_bytes = s.total_bytes;
            s.uploaded_bytes = uploaded;
            s.state = TransferState::Seeding;
        }
    }

    pub fn only_files_of(&self, infohash: &str) -> Option<Vec<usize>> {
        self.inner
            .lock()
            .expect("mock lock")
            .only_files
            .get(infohash)
            .cloned()
    }

    pub fn limits(&self) -> (Option<u32>, Option<u32>) {
        self.inner.lock().expect("mock lock").limits
    }

    pub fn path_of(&self, infohash: &str) -> Option<PathBuf> {
        self.inner
            .lock()
            .expect("mock lock")
            .transfers
            .values()
            .find(|(s, _)| s.infohash == infohash)
            .map(|(_, p)| p.clone())
    }

    fn with<T>(&self, id: TransferId, f: impl FnOnce(&mut TransferStatus) -> T) -> Result<T> {
        let mut inner = self.inner.lock().expect("mock lock");
        let (s, _) = inner
            .transfers
            .get_mut(&id)
            .ok_or_else(|| ClientError::Engine("no such transfer".into()))?;
        Ok(f(s))
    }
}

#[async_trait]
impl TorrentEngine for MockEngine {
    async fn add_seed(&self, torrent: &[u8], data_path: &Path) -> Result<TransferId> {
        self.add(torrent, data_path, true)
    }

    async fn add_download(
        &self,
        torrent: &[u8],
        dest: &Path,
        only_files: Option<&[usize]>,
    ) -> Result<TransferId> {
        let id = self.add(torrent, dest, false)?;
        if let Some(files) = only_files {
            let infohash = lemonwire_proto::metainfo::parse(torrent)?.infohash;
            self.inner
                .lock()
                .expect("mock lock")
                .only_files
                .insert(infohash, files.to_vec());
        }
        Ok(id)
    }

    async fn status(&self) -> Result<Vec<TransferStatus>> {
        let inner = self.inner.lock().expect("mock lock");
        let mut v: Vec<_> = inner.transfers.values().map(|(s, _)| s.clone()).collect();
        v.sort_by_key(|s| s.id.0);
        Ok(v)
    }

    async fn pause(&self, id: TransferId) -> Result<()> {
        self.with(id, |s| s.state = TransferState::Paused)
    }

    async fn resume(&self, id: TransferId) -> Result<()> {
        self.with(id, |s| {
            s.state = if s.finished {
                TransferState::Seeding
            } else {
                TransferState::Downloading
            }
        })
    }

    async fn set_limits(&self, upload_bps: Option<u32>, download_bps: Option<u32>) -> Result<()> {
        self.inner.lock().expect("mock lock").limits = (upload_bps, download_bps);
        Ok(())
    }

    async fn remove(&self, id: TransferId, _delete_data: bool) -> Result<()> {
        self.inner
            .lock()
            .expect("mock lock")
            .transfers
            .remove(&id)
            .map(|_| ())
            .ok_or_else(|| ClientError::Engine("no such transfer".into()))
    }
}
