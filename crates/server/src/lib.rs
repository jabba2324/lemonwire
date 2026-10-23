//! Lemon Wire index server: SQLite index, `/v1` HTTP API and a passkey tracker.

pub mod api;
pub mod db;
pub mod net;
pub mod testing;
pub mod tracker;

use std::collections::HashSet;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use tokio::net::TcpListener;

use crate::api::{AppState, Shared};
use crate::db::Db;

pub const DB_FILE: &str = "index.db";

/// Open (creating if needed) the data directory and its database. The directory is
/// private to the server's user because the database holds the server's secret key.
pub fn open_data_dir(dir: &Path) -> anyhow::Result<Db> {
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    let db_path = dir.join(DB_FILE);
    let db = Db::open(&db_path).with_context(|| format!("opening {}", db_path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        std::fs::set_permissions(&db_path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(db)
}

pub struct ServeOptions {
    pub data_dir: PathBuf,
    pub trust_proxy: bool,
    /// Most entries one member may have in the index (0 = no limit).
    pub max_shares_per_member: u64,
    /// The LAN's public IP, or a hostname that resolves to it (re-resolved every
    /// minute, so a DDNS name works). See `net::advertised`.
    pub nat_public_addr: Option<String>,
}

/// Bound listeners for the API and the tracker.
pub struct Listeners {
    pub api: TcpListener,
    pub tracker: TcpListener,
}

impl Listeners {
    pub async fn bind(api: &str, tracker: &str) -> anyhow::Result<Self> {
        Ok(Self {
            api: TcpListener::bind(api)
                .await
                .with_context(|| format!("binding API to {api}"))?,
            tracker: TcpListener::bind(tracker)
                .await
                .with_context(|| format!("binding tracker to {tracker}"))?,
        })
    }
}

/// Run the API and tracker until `shutdown` completes.
pub async fn serve(
    opts: ServeOptions,
    listeners: Listeners,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    let db = open_data_dir(&opts.data_dir)?;
    anyhow::ensure!(
        db.is_initialized()?,
        "{} is not initialised: run `lemonwire-server init` first",
        opts.data_dir.display()
    );
    let state: Shared = Arc::new(AppState::new(
        db,
        opts.trust_proxy,
        opts.max_shares_per_member,
    )?);
    tracing::info!(
        name = %state.name,
        api = %listeners.api.local_addr()?,
        tracker = %listeners.tracker.local_addr()?,
        tracker_url = %state.tracker_url,
        "serving"
    );

    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        shutdown.await;
        let _ = stop_tx.send(true);
    });
    let stopped = |mut rx: tokio::sync::watch::Receiver<bool>| async move {
        let _ = rx.wait_for(|v| *v).await;
    };

    let purge = tokio::spawn(purge_loop(
        state.clone(),
        stop_rx.clone(),
        opts.nat_public_addr.clone(),
    ));
    let api = axum::serve(
        listeners.api,
        api::router(state.clone()).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(stopped(stop_rx.clone()));
    let tracker = axum::serve(
        listeners.tracker,
        tracker::router(state.clone()).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(stopped(stop_rx.clone()));

    let (a, t) = tokio::join!(api, tracker);
    purge.abort();
    a.context("API server")?;
    t.context("tracker")?;
    tracing::info!("stopped");
    Ok(())
}

async fn resolve_public(addr: &str) -> Option<IpAddr> {
    if let Ok(ip) = addr.parse::<IpAddr>() {
        return Some(ip);
    }
    let addrs = tokio::net::lookup_host((addr, 0)).await.ok()?;
    let addrs: Vec<_> = addrs.map(|a| a.ip()).collect();
    addrs
        .iter()
        .find(|ip| ip.is_ipv4())
        .or(addrs.first())
        .copied()
}

async fn purge_loop(
    state: Shared,
    mut stop: tokio::sync::watch::Receiver<bool>,
    nat_public_addr: Option<String>,
) {
    let mut tick = tokio::time::interval(Duration::from_secs(60));
    loop {
        tokio::select! {
            _ = tick.tick() => {}
            _ = stop.wait_for(|v| *v) => return,
        }
        if let Some(addr) = &nat_public_addr {
            let ip = resolve_public(addr).await;
            let mut cur = state.nat_public.write().unwrap_or_else(|e| e.into_inner());
            if ip.is_some() && *cur != ip {
                tracing::info!(public_ip = ?ip, "LAN public address");
                *cur = ip;
            } else if ip.is_none() {
                tracing::warn!(%addr, "couldn't resolve the LAN public address");
            }
        }
        let members: Option<HashSet<String>> = {
            let db = state.db();
            if let Err(e) = db.purge_expired() {
                tracing::warn!(error = %e, "purge failed");
            }
            db.members()
                .ok()
                .map(|m| m.into_iter().map(|u| u.pubkey).collect())
        };
        state.auth_limiter.purge();
        if let Some(members) = members {
            state.swarms.purge(&members);
        }
    }
}

/// Resolves on Ctrl-C or SIGTERM.
pub async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {}
        _ = term => {}
    }
    tracing::info!("shutting down");
}
