//! [`TorrentEngine`] backed by librqbit (cargo feature `librqbit`).
//!
//! Configured for private, tracker-only swarms: no DHT, no local service discovery,
//! no session persistence (our own state file is the source of truth). librqbit
//! also skips PEX and ut_metadata for torrents marked private.

use std::net::{Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use lemonwire_proto::metainfo;
use std::num::NonZeroU32;

use librqbit::api::TorrentIdOrHash;
use librqbit::limits::LimitsConfig;
use librqbit::{
    AddTorrent, AddTorrentOptions, AddTorrentResponse, ListenerMode, ListenerOptions,
    ManagedTorrent, Session, SessionOptions, TorrentStatsState,
};

use crate::engine::{TorrentEngine, TransferId, TransferState, TransferStatus};
use crate::error::{ClientError, Result};

#[derive(Debug, Clone)]
pub struct RqbitOptions {
    /// Scratch folder for the session (not used for transfer data).
    pub state_dir: PathBuf,
    /// TCP port for incoming peers; 0 picks a free one. If the port is busy, a random
    /// one is used instead (outgoing connections still work).
    pub listen_port: u16,
    /// Ask the router to forward the listen port (UPnP).
    pub upnp: bool,
    /// Speed limits in bytes per second (`None` = unlimited).
    pub upload_bps: Option<u32>,
    pub download_bps: Option<u32>,
}

const ANNOUNCE_EVERY: std::time::Duration = std::time::Duration::from_secs(10);

pub struct RqbitEngine {
    session: Arc<Session>,
}

fn engine_err(e: impl std::fmt::Display) -> ClientError {
    ClientError::Engine(e.to_string())
}

fn limits(upload_bps: Option<u32>, download_bps: Option<u32>) -> LimitsConfig {
    LimitsConfig {
        upload_bps: upload_bps.and_then(NonZeroU32::new),
        download_bps: download_bps.and_then(NonZeroU32::new),
    }
}

impl RqbitEngine {
    pub async fn new(opts: RqbitOptions) -> Result<Self> {
        match Self::start(&opts, opts.listen_port).await {
            Err(e) if opts.listen_port != 0 => {
                tracing::warn!(port = opts.listen_port, error = %e, "port busy, using a random one");
                Self::start(&opts, 0).await
            }
            r => r,
        }
    }

    async fn start(opts: &RqbitOptions, port: u16) -> Result<Self> {
        std::fs::create_dir_all(&opts.state_dir)
            .map_err(|e| ClientError::Io(opts.state_dir.clone(), e))?;
        let session_opts = SessionOptions {
            dht: None,
            persistence: None,
            fastresume: false,
            disable_local_service_discovery: true,
            listen: Some(ListenerOptions {
                mode: ListenerMode::TcpOnly,
                listen_addr: SocketAddr::from((Ipv6Addr::UNSPECIFIED, port)),
                enable_upnp_port_forwarding: opts.upnp,
                ..Default::default()
            }),
            client_name_and_version: Some(concat!("lemonwire/", env!("CARGO_PKG_VERSION")).into()),
            ratelimits: limits(opts.upload_bps, opts.download_bps),
            ..Default::default()
        };
        let session = Session::new_with_opts(opts.state_dir.clone(), session_opts)
            .await
            .map_err(engine_err)?;
        Ok(Self { session })
    }

    pub fn listen_addr(&self) -> Option<SocketAddr> {
        self.session.listen_addr()
    }

    async fn add(
        &self,
        torrent: &[u8],
        output_folder: &Path,
        only_files: Option<&[usize]>,
    ) -> Result<TransferId> {
        let opts = AddTorrentOptions {
            only_files: only_files.map(<[usize]>::to_vec),
            // Announce often: swarms are tiny and one-shot peers come and go, and the
            // sharer waits on the tracker hearing that a download completed.
            force_tracker_interval: Some(ANNOUNCE_EVERY),
            // Check existing data and seed/resume it rather than refusing because
            // files exist. Client core has already refused to clobber unrelated files.
            overwrite: true,
            output_folder: Some(output_folder.to_string_lossy().into_owned()),
            ..Default::default()
        };
        let res = self
            .session
            .add_torrent(AddTorrent::from_bytes(torrent.to_vec()), Some(opts))
            .await
            .map_err(engine_err)?;
        match res {
            AddTorrentResponse::Added(id, _) | AddTorrentResponse::AlreadyManaged(id, _) => {
                Ok(TransferId(id as u64))
            }
            AddTorrentResponse::ListOnly(_) => {
                Err(ClientError::Engine("list-only response".into()))
            }
        }
    }

    fn handle(&self, id: TransferId) -> Result<Arc<ManagedTorrent>> {
        self.session
            .get(TorrentIdOrHash::Id(id.0 as usize))
            .ok_or_else(|| ClientError::Engine("no such transfer".into()))
    }
}

fn status_of(id: usize, h: &ManagedTorrent) -> TransferStatus {
    let stats = h.stats();
    let state = match (&stats.state, &stats.error) {
        (_, Some(e)) => TransferState::Error(e.clone()),
        (TorrentStatsState::Error, None) => TransferState::Error("unknown error".into()),
        (TorrentStatsState::Initializing { .. }, _) => TransferState::Checking,
        (TorrentStatsState::Paused, _) => TransferState::Paused,
        (TorrentStatsState::Live, _) if stats.finished => TransferState::Seeding,
        (TorrentStatsState::Live, _) => TransferState::Downloading,
    };
    let (down, up, peers) = stats
        .live
        .as_ref()
        .map(|l| {
            (
                (l.download_speed.mbps * 1024.0 * 1024.0) as u64,
                (l.upload_speed.mbps * 1024.0 * 1024.0) as u64,
                l.snapshot.peer_stats.live,
            )
        })
        .unwrap_or((0, 0, 0));
    TransferStatus {
        id: TransferId(id as u64),
        infohash: h.info_hash().as_string(),
        name: h.name().unwrap_or_default(),
        state,
        progress_bytes: stats.progress_bytes,
        total_bytes: stats.total_bytes,
        uploaded_bytes: stats.uploaded_bytes,
        download_bps: down,
        upload_bps: up,
        peers,
        finished: stats.finished,
    }
}

#[async_trait]
impl TorrentEngine for RqbitEngine {
    async fn add_seed(&self, torrent: &[u8], data_path: &Path) -> Result<TransferId> {
        // librqbit puts a single file at <folder>/<name> and a multi-file torrent's
        // files directly under <folder>, so seed from the parent or the folder itself.
        let parsed = metainfo::parse(torrent)?;
        let folder = if parsed.is_multi_file() {
            data_path.to_owned()
        } else {
            data_path
                .parent()
                .ok_or_else(|| ClientError::Invalid("shared file has no parent folder".into()))?
                .to_owned()
        };
        self.add(torrent, &folder, None).await
    }

    async fn add_download(
        &self,
        torrent: &[u8],
        dest: &Path,
        only_files: Option<&[usize]>,
    ) -> Result<TransferId> {
        let parsed = metainfo::parse(torrent)?;
        let folder = if parsed.is_multi_file() {
            metainfo::safe_join(dest, &parsed.name)?
        } else {
            dest.to_owned()
        };
        self.add(torrent, &folder, only_files).await
    }

    async fn status(&self) -> Result<Vec<TransferStatus>> {
        Ok(self
            .session
            .with_torrents(|it| it.map(|(id, h)| status_of(id, h)).collect::<Vec<_>>()))
    }

    async fn pause(&self, id: TransferId) -> Result<()> {
        let h = self.handle(id)?;
        if h.is_paused() {
            return Ok(());
        }
        self.session.pause(&h).await.map_err(engine_err)
    }

    async fn resume(&self, id: TransferId) -> Result<()> {
        let h = self.handle(id)?;
        if !h.is_paused() {
            return Ok(());
        }
        self.session.unpause(&h).await.map_err(engine_err)
    }

    async fn remove(&self, id: TransferId, delete_data: bool) -> Result<()> {
        self.session
            .delete(TorrentIdOrHash::Id(id.0 as usize), delete_data)
            .await
            .map_err(engine_err)
    }

    async fn set_limits(&self, upload_bps: Option<u32>, download_bps: Option<u32>) -> Result<()> {
        let l = limits(upload_bps, download_bps);
        self.session.ratelimits.set_upload_bps(l.upload_bps);
        self.session.ratelimits.set_download_bps(l.download_bps);
        Ok(())
    }

    fn completion_grace(&self) -> std::time::Duration {
        ANNOUNCE_EVERY + std::time::Duration::from_secs(2)
    }

    async fn shutdown(&self) {
        self.session.stop().await;
    }
}
