//! Transfers: the long-running share/download/seed commands and their seeding
//! policies, plus the saved transfer list. This is the behaviour the CLI and a GUI
//! share; front-ends only render the [`Event`]s and cancel.

use std::collections::HashMap;
use std::ops::ControlFlow;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use lemonwire_proto::api::PublishRequest;
use lemonwire_proto::keys;
use lemonwire_proto::metainfo::{self, BuildOptions, TorrentError};
use tokio_util::sync::CancellationToken;

use crate::client::{Client, check_infohash};
use crate::command::{Event, Output, SeedBack, SeedUntil, StopReason, TransferKind, TransferView};
use crate::config::{Profile, TransferRecord, now};
use crate::engine::{TransferId, TransferState, TransferStatus};
use crate::error::{ClientError, Result};

/// How often long-running commands report progress.
const TICK: Duration = Duration::from_secs(1);
/// How often `share` asks the tracker for copies, and `seed` re-reads the list.
const SLOW_TICK_EVERY: u32 = 5;
/// Seed-back checks for remaining downloaders this often...
const IDLE_CHECK: Duration = Duration::from_secs(15);
/// ...and stops after this many checks in a row find none.
const IDLE_CHECKS_TO_STOP: u32 = 2;

/// Wait one tick; `true` if cancelled meanwhile.
async fn tick(cancel: &CancellationToken) -> bool {
    tokio::select! {
        _ = tokio::time::sleep(TICK) => false,
        _ = cancel.cancelled() => true,
    }
}

/// Counts a running `Seed` for as long as it lives.
struct Serving<'a>(&'a Client);

impl<'a> Serving<'a> {
    fn start(client: &'a Client) -> Self {
        client.serving.fetch_add(1, Ordering::SeqCst);
        Self(client)
    }
}

impl Drop for Serving<'_> {
    fn drop(&mut self) {
        self.0.serving.fetch_sub(1, Ordering::SeqCst);
    }
}

impl Client {
    // ---- share -------------------------------------------------------------

    pub(crate) async fn share(
        &self,
        profile: Option<&str>,
        path: &Path,
        tags: Vec<String>,
        until: SeedUntil,
        cancel: &CancellationToken,
    ) -> Result<Output> {
        let p = self.profile(profile)?;
        let path = std::fs::canonicalize(path).map_err(|e| ClientError::Io(path.to_owned(), e))?;
        let (api, login) = self.session(&p).await?;

        let opts = BuildOptions {
            announce: Some(login.announce_url.clone()),
            creation_date: Some(now()),
            ..BuildOptions::default()
        };
        let events = self.events.clone();
        let build_path = path.clone();
        let stop = cancel.clone();
        let built = tokio::task::spawn_blocking(move || {
            metainfo::build(&build_path, &opts, |done, total| {
                let _ = events.send(Event::Hashing {
                    path: build_path.clone(),
                    done,
                    total,
                });
                if stop.is_cancelled() {
                    ControlFlow::Break(())
                } else {
                    ControlFlow::Continue(())
                }
            })
        })
        .await
        .map_err(|e| ClientError::Invalid(e.to_string()))?
        .map_err(|e| match e {
            TorrentError::Cancelled => ClientError::Cancelled,
            e => e.into(),
        })?;

        let infohash = built.parsed.infohash.clone();
        let publish = PublishRequest {
            tags,
            torrent_b64: keys::b64_encode(&built.bytes),
        };
        let (entry, already_indexed) = match api.publish(&login.token, &publish).await {
            Ok(e) => (e, false),
            Err(ClientError::Server { status: 409, .. }) => {
                (api.fetch(&login.token, &infohash).await?.entry, true)
            }
            Err(e) => return Err(e),
        };
        self.emit(Event::Published {
            infohash: infohash.clone(),
            name: entry.name.clone(),
        });

        let record = TransferRecord {
            infohash: infohash.clone(),
            name: entry.name.clone(),
            profile: p.name.clone(),
            kind: TransferKind::Seed,
            path,
            torrent_b64: keys::b64_encode(&built.bytes),
            paused: false,
            files: None,
            added_at: now(),
        };
        self.save_record(record.clone()).await?;

        let stopped = if until == SeedUntil::PublishOnly || self.engine.is_none() {
            StopReason::NotSeeded
        } else {
            self.ensure_running(&record).await?;
            let r = self.seed_until(&p, &infohash, until, cancel).await;
            self.release(&infohash).await;
            r?
        };
        Ok(Output::Shared {
            entry,
            already_indexed,
            stopped,
        })
    }

    async fn seed_until(
        &self,
        p: &Profile,
        infohash: &str,
        until: SeedUntil,
        cancel: &CancellationToken,
    ) -> Result<StopReason> {
        let wanted = match until {
            SeedUntil::Copies { count } => Some(count),
            _ => None,
        };
        let mut n: u32 = 0;
        loop {
            if tick(cancel).await {
                return Ok(StopReason::Cancelled);
            }
            n += 1;
            self.report_progress(infohash).await;
            if !n.is_multiple_of(SLOW_TICK_EVERY) {
                continue;
            }
            // complete_members counts us too, once our first announce lands.
            let Ok((_, leechers, members)) = self.scrape(p, infohash).await else {
                continue;
            };
            let copies = members.saturating_sub(1);
            self.emit(Event::Waiting {
                infohash: infohash.to_owned(),
                copies,
                wanted: wanted.unwrap_or(0),
                leechers,
            });
            if wanted.is_some_and(|w| copies >= w) {
                return Ok(StopReason::CopiesReached { copies });
            }
        }
    }

    // ---- download ----------------------------------------------------------

    pub(crate) async fn download(
        &self,
        profile: Option<&str>,
        infohash: &str,
        dest: Option<PathBuf>,
        files: Option<Vec<usize>>,
        seed_back: Option<SeedBack>,
        cancel: &CancellationToken,
    ) -> Result<Output> {
        if self.engine.is_none() {
            return Err(ClientError::NoEngine);
        }
        let infohash = check_infohash(infohash)?;
        // A saved download resumes in place (after a cancel, say); a share is already ours.
        let existing = self
            .config
            .load_transfers()?
            .into_iter()
            .find(|t| t.infohash == infohash);
        if let Some(t) = &existing {
            if t.kind == TransferKind::Seed {
                return Err(ClientError::Invalid(format!(
                    "you're sharing {} from {}; nothing to download",
                    t.name,
                    t.path.display()
                )));
            }
            if dest.as_ref().is_some_and(|d| d != &t.path) {
                return Err(ClientError::Invalid(format!(
                    "{} is already downloading to {}; cancel it first to change folders",
                    t.name,
                    t.path.display()
                )));
            }
        }
        let p = self.profile(profile)?;
        let (api, login) = self.session(&p).await?;
        let fetched = api.fetch(&login.token, &infohash).await?;
        let torrent = keys::b64_decode(&fetched.torrent_b64)?;

        // Check the torrent ourselves too: right infohash, private, and every path
        // stays inside the destination.
        let parsed = metainfo::parse_private(&torrent)?;
        if parsed.infohash != infohash {
            return Err(ClientError::Invalid(
                "server returned a torrent with a different infohash".into(),
            ));
        }
        let files = match files.or_else(|| existing.as_ref().and_then(|t| t.files.clone())) {
            None => None,
            Some(mut f) => {
                f.sort_unstable();
                f.dedup();
                if f.is_empty() {
                    return Err(ClientError::Invalid("no files selected".into()));
                }
                if let Some(bad) = f.iter().find(|&&i| i >= parsed.files.len()) {
                    return Err(ClientError::Invalid(format!(
                        "file {bad} doesn't exist: this torrent has {} files (0 to {})",
                        parsed.files.len(),
                        parsed.files.len() - 1
                    )));
                }
                Some(f)
            }
        };
        let dest = match &existing {
            Some(t) => t.path.clone(),
            None => dest.unwrap_or_else(|| self.download_dir.clone()),
        };
        let root = metainfo::safe_join(&dest, &parsed.name)?;
        if parsed.is_multi_file() {
            for f in &parsed.files {
                metainfo::safe_join(&root, &f.path)?;
            }
        }
        // Only a resumed download may find its files already there.
        if existing.is_none() && root.exists() {
            return Err(ClientError::DestinationExists(root));
        }
        std::fs::create_dir_all(&dest).map_err(|e| ClientError::Io(dest.clone(), e))?;

        let record = TransferRecord {
            infohash: infohash.clone(),
            name: parsed.name.clone(),
            profile: p.name.clone(),
            kind: TransferKind::Download,
            path: dest,
            torrent_b64: fetched.torrent_b64,
            paused: false,
            files,
            added_at: existing.as_ref().map_or_else(now, |t| t.added_at),
        };
        self.save_record(record.clone()).await?;
        self.ensure_running(&record).await?;

        // Download.
        loop {
            // Cancelled from elsewhere (the transfer list), not by our token.
            if self.engine_id(&infohash).is_none() {
                return Err(ClientError::Cancelled);
            }
            if let Some(s) = self.report_progress(&infohash).await {
                if let TransferState::Error(e) = &s.state {
                    self.stop_running(&infohash).await;
                    return Err(ClientError::Engine(e.clone()));
                }
                if s.finished {
                    break;
                }
            }
            if tick(cancel).await {
                self.release(&infohash).await;
                return Err(ClientError::Cancelled);
            }
        }
        self.emit(Event::DownloadFinished {
            infohash: infohash.clone(),
            name: parsed.name.clone(),
        });

        // Seed back, or at least stay until the tracker has heard we're complete.
        let started = Instant::now();
        let seed_back = match seed_back {
            Some(sb) if sb.ratio > 0.0 && sb.max_secs > 0 => {
                Some(self.seed_back(&p, &infohash, sb, cancel).await)
            }
            _ => None,
        };
        let grace = self
            .engine
            .as_ref()
            .map(|e| e.completion_grace())
            .unwrap_or_default()
            .saturating_sub(started.elapsed());
        if !grace.is_zero() {
            tokio::select! {
                _ = tokio::time::sleep(grace) => {}
                _ = cancel.cancelled() => {}
            }
        }
        self.release(&infohash).await;
        Ok(Output::Downloaded {
            entry: fetched.entry,
            dest: root,
            seed_back,
        })
    }

    async fn seed_back(
        &self,
        p: &Profile,
        infohash: &str,
        policy: SeedBack,
        cancel: &CancellationToken,
    ) -> StopReason {
        let start = Instant::now();
        let limit = Duration::from_secs(policy.max_secs);
        let mut last_idle_check = Instant::now();
        let mut idle = 0;
        loop {
            if tick(cancel).await {
                return StopReason::Cancelled;
            }
            if let Some(s) = self.live_status(infohash).await {
                self.emit(Event::SeedingBack {
                    infohash: infohash.to_owned(),
                    uploaded: s.uploaded_bytes,
                    total: s.total_bytes,
                    peers: s.peers,
                });
                if s.uploaded_bytes as f64 >= policy.ratio * s.total_bytes as f64 {
                    return StopReason::RatioReached;
                }
            }
            if start.elapsed() >= limit {
                return StopReason::TimeLimit;
            }
            if last_idle_check.elapsed() >= IDLE_CHECK {
                last_idle_check = Instant::now();
                match self.scrape(p, infohash).await {
                    Ok((_, 0, _)) => {
                        idle += 1;
                        if idle >= IDLE_CHECKS_TO_STOP {
                            return StopReason::NobodyDownloading;
                        }
                    }
                    _ => idle = 0,
                }
            }
        }
    }

    // ---- seed --------------------------------------------------------------

    /// Serve every saved transfer until cancelled, following changes other commands
    /// (or processes) make to the list.
    pub(crate) async fn seed(&self, cancel: &CancellationToken) -> Result<Output> {
        if self.engine.is_none() {
            return Err(ClientError::NoEngine);
        }
        let serving = Serving::start(self);
        let mut n: u32 = 0;
        let mut running = self.sync().await?;
        loop {
            if n.is_multiple_of(SLOW_TICK_EVERY) {
                match self.sync().await {
                    Ok(r) => running = r,
                    Err(e) => tracing::warn!(error = %e, "couldn't sync transfers"),
                }
                let live = self.live_statuses().await;
                for s in &live {
                    self.emit(Event::Progress { status: s.clone() });
                }
                self.emit(Event::Serving {
                    transfers: live.len(),
                    downloading: live.iter().filter(|s| !s.finished).count(),
                    upload_bps: live.iter().map(|s| s.upload_bps).sum(),
                    download_bps: live.iter().map(|s| s.download_bps).sum(),
                    peers: live.iter().map(|s| s.peers).sum(),
                });
            }
            if tick(cancel).await {
                break;
            }
            n += 1;
        }
        drop(serving);
        if self.serving.load(Ordering::SeqCst) > 0 {
            // Another `Seed` is still serving everything.
            return Ok(Output::Served { transfers: running });
        }
        let ids: Vec<String> = self
            .transfer_ids
            .lock()
            .expect("ids lock")
            .keys()
            .cloned()
            .collect();
        for infohash in ids {
            self.stop_running(&infohash).await;
        }
        Ok(Output::Served { transfers: running })
    }

    /// Bring the engine in line with the state file, which other one-shot commands
    /// may have changed: start new transfers, drop cancelled ones, apply pause/resume.
    /// Returns how many transfers are running afterwards.
    pub async fn sync(&self) -> Result<usize> {
        let Some(engine) = &self.engine else {
            return Err(ClientError::NoEngine);
        };
        let records = self.config.load_transfers()?;
        let running: HashMap<String, TransferId> =
            self.transfer_ids.lock().expect("ids lock").clone();
        for infohash in running.keys() {
            if !records.iter().any(|r| &r.infohash == infohash) {
                self.stop_running(infohash).await;
                self.emit(Event::TransferRemoved {
                    infohash: infohash.clone(),
                });
            }
        }
        let status = engine.status().await?;
        for r in &records {
            match running.get(&r.infohash) {
                None => {
                    if self.sync_failed.lock().expect("lock").contains(&r.infohash) {
                        continue;
                    }
                    if let Err(e) = self.ensure_running(r).await {
                        tracing::warn!(name = %r.name, error = %e, "couldn't start transfer");
                        self.sync_failed
                            .lock()
                            .expect("lock")
                            .insert(r.infohash.clone());
                    }
                }
                Some(id) => {
                    let paused_now = status
                        .iter()
                        .any(|s| s.id == *id && s.state == TransferState::Paused);
                    if r.paused && !paused_now {
                        engine.pause(*id).await?;
                    } else if !r.paused && paused_now {
                        engine.resume(*id).await?;
                    }
                }
            }
        }
        Ok(self.transfer_ids.lock().expect("ids lock").len())
    }

    // ---- the saved transfer list -------------------------------------------

    async fn save_record(&self, record: TransferRecord) -> Result<()> {
        let _guard = self.state_lock.lock().await;
        let mut all = self.config.load_transfers()?;
        let added = !all.iter().any(|t| t.infohash == record.infohash);
        all.retain(|t| t.infohash != record.infohash);
        all.push(record.clone());
        self.config.save_transfers(&all)?;
        if added {
            self.emit(Event::TransferAdded {
                infohash: record.infohash,
                name: record.name,
            });
        }
        Ok(())
    }

    /// Start the record in the engine unless it's already running there.
    async fn ensure_running(&self, record: &TransferRecord) -> Result<()> {
        let Some(engine) = &self.engine else {
            return Err(ClientError::NoEngine);
        };
        let _starting = self.start_lock.lock().await;
        if self.engine_id(&record.infohash).is_some() {
            return Ok(());
        }
        let torrent = keys::b64_decode(&record.torrent_b64)?;
        let id = match record.kind {
            TransferKind::Seed => engine.add_seed(&torrent, &record.path).await?,
            TransferKind::Download => {
                // Tell the tracker a selective download isn't a full copy, or a sharer
                // waiting for copies would stop too soon. (Announce is outside `info`,
                // so the infohash is unchanged.)
                let torrent = match &record.files {
                    Some(_) => {
                        let parsed = metainfo::parse(&torrent)?;
                        let announce = parsed.announce.unwrap_or_default();
                        metainfo::with_announce(&torrent, &format!("{announce}&lw_partial=1"))?
                    }
                    None => torrent,
                };
                engine
                    .add_download(&torrent, &record.path, record.files.as_deref())
                    .await?
            }
        };
        if record.paused {
            engine.pause(id).await?;
        }
        self.transfer_ids
            .lock()
            .expect("ids lock")
            .insert(record.infohash.clone(), id);
        Ok(())
    }

    /// A share or download is done with its transfer: stop it, unless a `Seed` is
    /// serving everything anyway (a GUI does while open), so it keeps running.
    async fn release(&self, infohash: &str) {
        if self.serving.load(Ordering::SeqCst) == 0 {
            self.stop_running(infohash).await;
        }
    }

    /// Stop the engine running it (the saved record stays).
    async fn stop_running(&self, infohash: &str) {
        let id = self.transfer_ids.lock().expect("ids lock").remove(infohash);
        if let (Some(engine), Some(id)) = (&self.engine, id)
            && let Err(e) = engine.remove(id, false).await
        {
            tracing::warn!(%infohash, error = %e, "couldn't stop transfer");
        }
    }

    fn engine_id(&self, infohash: &str) -> Option<TransferId> {
        self.transfer_ids
            .lock()
            .expect("ids lock")
            .get(infohash)
            .copied()
    }

    async fn live_statuses(&self) -> Vec<TransferStatus> {
        match &self.engine {
            Some(e) => e.status().await.unwrap_or_default(),
            None => vec![],
        }
    }

    async fn live_status(&self, infohash: &str) -> Option<TransferStatus> {
        self.live_statuses()
            .await
            .into_iter()
            .find(|s| s.infohash == infohash)
    }

    async fn report_progress(&self, infohash: &str) -> Option<TransferStatus> {
        let s = self.live_status(infohash).await?;
        self.emit(Event::Progress { status: s.clone() });
        Some(s)
    }

    pub async fn transfers(&self) -> Result<Vec<TransferView>> {
        let records = self.config.load_transfers()?;
        let live = self.live_statuses().await;
        Ok(records
            .into_iter()
            .map(|r| TransferView {
                status: live.iter().find(|s| s.infohash == r.infohash).cloned(),
                infohash: r.infohash,
                name: r.name,
                profile: r.profile,
                kind: r.kind,
                path: r.path,
                paused: r.paused,
                files: r.files,
            })
            .collect())
    }

    async fn update_record(
        &self,
        infohash: &str,
        f: impl FnOnce(&mut Vec<TransferRecord>, usize),
    ) -> Result<TransferRecord> {
        let _guard = self.state_lock.lock().await;
        let mut all = self.config.load_transfers()?;
        let pos = all
            .iter()
            .position(|t| t.infohash == infohash)
            .ok_or_else(|| ClientError::NoSuchTransfer(infohash.to_owned()))?;
        let record = all[pos].clone();
        f(&mut all, pos);
        self.config.save_transfers(&all)?;
        Ok(record)
    }

    pub(crate) async fn set_paused(&self, infohash: &str, paused: bool) -> Result<Output> {
        let infohash = check_infohash(infohash)?;
        let record = self
            .update_record(&infohash, |all, i| all[i].paused = paused)
            .await?;
        if let (Some(engine), Some(id)) = (&self.engine, self.engine_id(&infohash)) {
            if paused {
                engine.pause(id).await?;
            } else {
                engine.resume(id).await?;
            }
        }
        Ok(Output::Done {
            message: format!(
                "{} {}.",
                if paused { "Paused" } else { "Resumed" },
                record.name
            ),
        })
    }

    pub(crate) async fn cancel_transfer(
        &self,
        infohash: &str,
        delete_data: bool,
    ) -> Result<Output> {
        let infohash = check_infohash(infohash)?;
        let record = self
            .update_record(&infohash, |all, i| {
                all.remove(i);
            })
            .await?;
        // Never delete a shared original.
        let delete = delete_data && record.kind == TransferKind::Download;
        let id = self
            .transfer_ids
            .lock()
            .expect("ids lock")
            .remove(&infohash);
        match (&self.engine, id) {
            (Some(engine), Some(id)) => engine.remove(id, delete).await?,
            _ if delete => {
                let target = metainfo::safe_join(&record.path, &record.name)?;
                let res = if target.is_dir() {
                    std::fs::remove_dir_all(&target)
                } else {
                    std::fs::remove_file(&target)
                };
                match res {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => return Err(ClientError::Io(target, e)),
                }
            }
            _ => {}
        }
        self.emit(Event::TransferRemoved {
            infohash: infohash.clone(),
        });
        Ok(Output::Done {
            message: format!(
                "Stopped {}{}.",
                record.name,
                if delete { " and deleted its data" } else { "" }
            ),
        })
    }

    pub(crate) async fn unpublish(&self, profile: Option<&str>, infohash: &str) -> Result<Output> {
        let infohash = check_infohash(infohash)?;
        let (api, login) = self.session_for(profile).await?;
        api.unpublish(&login.token, &infohash).await?;
        // The tracker no longer serves it, so forget it locally too.
        let local = self
            .config
            .load_transfers()?
            .iter()
            .any(|t| t.infohash == infohash);
        if local {
            self.cancel_transfer(&infohash, false).await?;
        }
        Ok(Output::Done {
            message: format!("Removed {infohash} from the index."),
        })
    }
}
