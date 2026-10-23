//! [`Client`]: executes [`Command`]s. No printing or prompting happens here, so the CLI
//! and a GUI behave identically. Long-running commands (share, download, seed) live in
//! [`crate::transfers`].

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;

use futures::{Stream, StreamExt};
use lemonwire_proto::api::{AddMemberRequest, CreateInviteRequest, LoginResponse};
use lemonwire_proto::keys::{self, KeyPair, PublicKey};
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

use crate::api::{ApiClient, normalize_url};
use crate::command::{Command, Event, Output};
use crate::config::{ConfigDir, EngineLock, Profile, now};
use crate::engine::{TorrentEngine, TransferId};
use crate::error::{ClientError, Result};
use crate::keystore::KeyStore;

/// For [`Client::new`], with an engine you built yourself (tests use `MockEngine`).
pub struct ClientOptions {
    pub config: ConfigDir,
    pub engine: Option<Arc<dyn TorrentEngine>>,
    /// Where downloads go when no destination is given.
    pub download_dir: Option<PathBuf>,
    /// Opens passphrase-protected keys, and protects new ones.
    pub passphrase: Option<String>,
}

/// Settings for the built-in librqbit engine (see [`Client::open`]).
#[derive(Debug, Clone)]
pub struct EngineSettings {
    /// TCP port for incoming peers (falls back to a random one if busy).
    pub port: u16,
    /// Ask the router to open `port` via UPnP while the engine runs.
    pub upnp: bool,
    pub upload_kib: Option<u32>,
    pub download_kib: Option<u32>,
}

impl Default for EngineSettings {
    fn default() -> Self {
        Self {
            port: 6881,
            upnp: true,
            upload_kib: None,
            download_kib: None,
        }
    }
}

/// For [`Client::open`]: the usual way for a front-end to make a client.
pub struct OpenOptions {
    pub config: ConfigDir,
    /// `Some` to run a torrent engine (needed for share, download and seed).
    pub engine: Option<EngineSettings>,
    pub download_dir: Option<PathBuf>,
    /// Opens passphrase-protected keys, and protects new ones.
    pub passphrase: Option<String>,
}

pub struct Client {
    pub(crate) config: ConfigDir,
    pub(crate) keys: KeyStore,
    pub(crate) http: reqwest::Client,
    pub(crate) engine: Option<Arc<dyn TorrentEngine>>,
    pub(crate) download_dir: PathBuf,
    pub(crate) sessions: tokio::sync::Mutex<HashMap<String, LoginResponse>>,
    /// Infohash → engine id for transfers this client's engine is running.
    pub(crate) transfer_ids: std::sync::Mutex<HashMap<String, TransferId>>,
    /// Transfers `sync` couldn't start (e.g. data moved); not retried every pass.
    pub(crate) sync_failed: std::sync::Mutex<HashSet<String>>,
    /// Serialises read-modify-write of the state files.
    pub(crate) state_lock: tokio::sync::Mutex<()>,
    pub(crate) events: broadcast::Sender<Event>,
    /// Serialises "is it running? if not, add it" against the engine.
    pub(crate) start_lock: tokio::sync::Mutex<()>,
    /// How many `Seed` commands are running. While one is, transfers stay in the
    /// engine after the share or download that started them returns.
    pub(crate) serving: std::sync::atomic::AtomicUsize,
    _engine_lock: Option<EngineLock>,
}

fn validate_profile_name(name: &str) -> Result<()> {
    let ok = !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if ok {
        Ok(())
    } else {
        Err(ClientError::InvalidProfileName(name.to_owned()))
    }
}

pub(crate) fn check_infohash(h: &str) -> Result<String> {
    let h = h.trim().to_ascii_lowercase();
    if h.len() == 40 && h.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(h)
    } else {
        Err(ClientError::Invalid(format!(
            "{h:?} isn't an infohash (40 hex characters)"
        )))
    }
}

impl Client {
    /// Make a client with the built-in torrent engine (if `engine` is set). Takes the
    /// config dir's engine lock first, so the CLI and a GUI never run two engines.
    #[cfg(feature = "librqbit")]
    pub async fn open(opts: OpenOptions) -> Result<Self> {
        use crate::rqbit::{RqbitEngine, RqbitOptions};
        let Some(settings) = opts.engine else {
            return Self::build(opts.config, None, opts.download_dir, None, opts.passphrase);
        };
        let lock = opts.config.lock_engine()?;
        let engine = RqbitEngine::new(RqbitOptions {
            state_dir: opts.config.engine_dir(),
            listen_port: settings.port,
            upnp: settings.upnp,
            upload_bps: settings.upload_kib.map(|k| k.saturating_mul(1024)),
            download_bps: settings.download_kib.map(|k| k.saturating_mul(1024)),
        })
        .await?;
        if let Some(addr) = engine.listen_addr() {
            tracing::info!(%addr, "listening for peers");
        }
        Self::build(
            opts.config,
            Some(Arc::new(engine)),
            opts.download_dir,
            Some(lock),
            opts.passphrase,
        )
    }

    /// Make a client without the built-in engine, or with one you supply.
    pub fn new(opts: ClientOptions) -> Result<Self> {
        let lock = match &opts.engine {
            Some(_) => Some(opts.config.lock_engine()?),
            None => None,
        };
        Self::build(
            opts.config,
            opts.engine,
            opts.download_dir,
            lock,
            opts.passphrase,
        )
    }

    fn build(
        config: ConfigDir,
        engine: Option<Arc<dyn TorrentEngine>>,
        download_dir: Option<PathBuf>,
        lock: Option<EngineLock>,
        passphrase: Option<String>,
    ) -> Result<Self> {
        let http = reqwest::Client::builder()
            .user_agent(concat!("lemonwire/", env!("CARGO_PKG_VERSION")))
            .timeout(std::time::Duration::from_secs(60))
            .build()?;
        // The desktop's Downloads folder, or ~/Downloads where none is configured
        // (never the working directory: a GUI's can be anywhere, even /).
        let download_dir = download_dir
            .or_else(|| {
                let user = directories::UserDirs::new()?;
                let downloads = user
                    .download_dir()
                    .map(|d| d.to_owned())
                    .unwrap_or_else(|| user.home_dir().join("Downloads"));
                Some(downloads.join("lemonwire"))
            })
            .unwrap_or_else(|| PathBuf::from("lemonwire-downloads"));
        Ok(Self {
            keys: KeyStore::new(config.root(), passphrase),
            config,
            http,
            engine,
            download_dir,
            sessions: Default::default(),
            transfer_ids: Default::default(),
            sync_failed: Default::default(),
            state_lock: Default::default(),
            events: broadcast::channel(1024).0,
            start_lock: Default::default(),
            serving: Default::default(),
            _engine_lock: lock,
        })
    }

    pub fn config(&self) -> &ConfigDir {
        &self.config
    }

    pub fn has_engine(&self) -> bool {
        self.engine.is_some()
    }

    /// Set the passphrase for protected keys, e.g. after asking for it when a command
    /// failed with [`ClientError::PassphraseRequired`].
    pub fn set_passphrase(&self, passphrase: Option<String>) {
        self.keys.set_passphrase(passphrase);
    }

    /// Progress events. Slow subscribers miss events rather than block the client.
    pub fn subscribe(&self) -> impl Stream<Item = Event> + Send + 'static {
        tokio_stream::wrappers::BroadcastStream::new(self.events.subscribe())
            .filter_map(|e| async move { e.ok() })
    }

    pub(crate) fn emit(&self, e: Event) {
        let _ = self.events.send(e);
    }

    /// Run a command to completion. Long-running commands (share, download, seed) can't
    /// be cancelled this way; use [`Client::execute_cancellable`].
    pub async fn execute(&self, cmd: Command) -> Result<Output> {
        self.execute_cancellable(cmd, &CancellationToken::new())
            .await
    }

    /// Run a command until it finishes or `cancel` fires. Cancelling a share or
    /// download keeps its saved transfer, so it can resume later; a command that
    /// returns after cancelling reports `StopReason::Cancelled` or
    /// `ClientError::Cancelled`.
    pub async fn execute_cancellable(
        &self,
        cmd: Command,
        cancel: &CancellationToken,
    ) -> Result<Output> {
        // A cached session can go stale (revoked, server restarted with a cleared
        // database). On a 401, forget sessions and try once more with a fresh login.
        let had_sessions = !self.sessions.lock().await.is_empty();
        match self.execute_once(cmd.clone(), cancel).await {
            Err(ClientError::Server { status: 401, .. }) if had_sessions => {
                self.sessions.lock().await.clear();
                self.execute_once(cmd, cancel).await
            }
            other => other,
        }
    }

    async fn execute_once(&self, cmd: Command, cancel: &CancellationToken) -> Result<Output> {
        match cmd {
            Command::KeysGenerate { profile } => self.keys_generate(&profile),
            Command::ProfileList => self.profile_list(),
            Command::ProfileAdd {
                profile,
                url,
                server_key,
                invite,
                member_name,
                allow_insecure,
            } => {
                self.profile_add(
                    &profile,
                    &url,
                    server_key,
                    invite,
                    member_name,
                    allow_insecure,
                )
                .await
            }
            Command::KeysProtect {
                profile,
                new_passphrase,
            } => {
                self.keys.protect(&profile, new_passphrase.as_deref())?;
                Ok(Output::Done {
                    message: match new_passphrase {
                        Some(_) => format!("Protected the key for {profile:?} with a passphrase."),
                        None => format!("Removed the passphrase from the key for {profile:?}."),
                    },
                })
            }
            Command::ProfileRemove { name } => self.profile_remove(&name).await,
            Command::ProfileSetDefault { name } => self.profile_set_default(&name).await,
            Command::Info { profile } => self.info(profile.as_deref()).await,
            Command::Whoami { profile } => {
                let mut p = self.profile(profile.as_deref())?;
                let (api, login) = self.session(&p).await?;
                let member = api.me(&login.token).await?;
                if p.member_name.as_deref() != Some(member.name.as_str()) {
                    p.member_name = Some(member.name.clone());
                    self.remember_member_name(&p.name, &member.name).await?;
                }
                Ok(Output::Me {
                    profile: p.view(),
                    member,
                })
            }
            Command::Search {
                profile,
                query,
                limit,
                offset,
                mine,
            } => {
                let p = self.profile(profile.as_deref())?;
                let (api, login) = self.session(&p).await?;
                let r = api
                    .search(&login.token, &query, limit, offset, mine)
                    .await?;
                Ok(Output::Results {
                    profile: p.name,
                    offset: offset.unwrap_or(0),
                    results: r.results,
                    next_offset: r.next_offset,
                })
            }
            Command::Details { profile, infohash } => {
                let infohash = check_infohash(&infohash)?;
                let (api, login) = self.session_for(profile.as_deref()).await?;
                Ok(Output::Details {
                    entry: api.fetch(&login.token, &infohash).await?.entry,
                })
            }
            Command::Share {
                profile,
                path,
                tags,
                until,
            } => {
                self.share(profile.as_deref(), &path, tags, until, cancel)
                    .await
            }
            Command::Download {
                profile,
                infohash,
                dest,
                files,
                seed_back,
            } => {
                self.download(
                    profile.as_deref(),
                    &infohash,
                    dest,
                    files,
                    seed_back,
                    cancel,
                )
                .await
            }
            Command::Seed => self.seed(cancel).await,
            Command::Unpublish { profile, infohash } => {
                self.unpublish(profile.as_deref(), &infohash).await
            }
            Command::Swarm { profile, infohash } => {
                let infohash = check_infohash(&infohash)?;
                let p = self.profile(profile.as_deref())?;
                let (seeders, leechers, complete_members) = self.scrape(&p, &infohash).await?;
                Ok(Output::Swarm {
                    infohash,
                    seeders,
                    leechers,
                    complete_members,
                })
            }
            Command::Transfers => Ok(Output::Transfers {
                transfers: self.transfers().await?,
            }),
            Command::Pause { infohash } => self.set_paused(&infohash, true).await,
            Command::Resume { infohash } => self.set_paused(&infohash, false).await,
            Command::Cancel {
                infohash,
                delete_data,
            } => self.cancel_transfer(&infohash, delete_data).await,
            Command::SetLimits {
                upload_kib,
                download_kib,
            } => {
                let engine = self.engine.as_ref().ok_or(ClientError::NoEngine)?;
                engine
                    .set_limits(
                        upload_kib.map(|k| k.saturating_mul(1024)),
                        download_kib.map(|k| k.saturating_mul(1024)),
                    )
                    .await?;
                let show = |k: Option<u32>| k.map_or("unlimited".into(), |k| format!("{k} KiB/s"));
                Ok(Output::Done {
                    message: format!(
                        "Limits: up {}, down {}.",
                        show(upload_kib),
                        show(download_kib)
                    ),
                })
            }
            Command::MembersList { profile } => {
                let (api, login) = self.session_for(profile.as_deref()).await?;
                Ok(Output::Members {
                    members: api.members(&login.token).await?.members,
                })
            }
            Command::MembersAdd {
                profile,
                pubkey,
                name,
                admin,
            } => {
                let (api, login) = self.session_for(profile.as_deref()).await?;
                let member = api
                    .add_member(
                        &login.token,
                        &AddMemberRequest {
                            pubkey,
                            name,
                            is_admin: admin,
                        },
                    )
                    .await?;
                Ok(Output::Member { member })
            }
            Command::MembersRevoke { profile, member } => {
                let (api, login) = self.session_for(profile.as_deref()).await?;
                api.revoke_member(&login.token, &member).await?;
                Ok(Output::Done {
                    message: format!("Revoked {member}."),
                })
            }
            Command::InviteCreate {
                profile,
                admin,
                ttl_hours,
            } => {
                let (api, login) = self.session_for(profile.as_deref()).await?;
                let invite = api
                    .create_invite(
                        &login.token,
                        &CreateInviteRequest {
                            is_admin: admin,
                            ttl_hours,
                        },
                    )
                    .await?;
                Ok(Output::Invite { invite })
            }
            Command::InviteList { profile } => {
                let (api, login) = self.session_for(profile.as_deref()).await?;
                Ok(Output::Invites {
                    invites: api.invites(&login.token).await?.invites,
                })
            }
        }
    }

    // ---- profiles ----------------------------------------------------------

    pub(crate) fn profile(&self, name: Option<&str>) -> Result<Profile> {
        let profiles = self.config.load_profiles()?;
        match name {
            Some(n) => profiles
                .into_iter()
                .find(|p| p.name == n)
                .ok_or_else(|| ClientError::NoSuchProfile(n.to_owned())),
            None => {
                if profiles.is_empty() {
                    return Err(ClientError::NoProfiles);
                }
                if profiles.len() == 1 {
                    return Ok(profiles.into_iter().next().expect("one"));
                }
                profiles
                    .into_iter()
                    .find(|p| p.default)
                    .ok_or(ClientError::AmbiguousProfile)
            }
        }
    }

    fn key(&self, profile: &str) -> Result<KeyPair> {
        self.keys.get(profile)?.ok_or_else(|| {
            ClientError::KeyStore(format!("no secret key found for profile {profile:?}"))
        })
    }

    fn keys_generate(&self, profile: &str) -> Result<Output> {
        validate_profile_name(profile)?;
        if self
            .config
            .load_profiles()?
            .iter()
            .any(|p| p.name == profile)
        {
            return Err(ClientError::ProfileExists(profile.to_owned()));
        }
        // Idempotent: never replace a key that may already have been sent to an admin.
        let key = match self.keys.get(profile)? {
            Some(k) => k,
            None => {
                let k = KeyPair::generate()?;
                self.keys.put(profile, &k)?;
                k
            }
        };
        Ok(Output::PublicKey {
            profile: profile.to_owned(),
            public_key: key.public().to_b64(),
        })
    }

    fn profile_list(&self) -> Result<Output> {
        let profiles = self
            .config
            .load_profiles()?
            .iter()
            .map(Profile::view)
            .collect();
        Ok(Output::Profiles { profiles })
    }

    async fn profile_add(
        &self,
        name: &str,
        url: &str,
        server_key: Option<String>,
        invite: Option<String>,
        member_name: Option<String>,
        allow_insecure: bool,
    ) -> Result<Output> {
        validate_profile_name(name)?;
        let url = normalize_url(url, allow_insecure)?;
        let _guard = self.state_lock.lock().await;
        let mut profiles = self.config.load_profiles()?;
        if profiles.iter().any(|p| p.name == name) {
            return Err(ClientError::ProfileExists(name.to_owned()));
        }

        // 1. Key pair: reuse one made earlier with `keys generate`, else make one.
        let key = match self.keys.get(name)? {
            Some(k) => k,
            None => {
                let k = KeyPair::generate()?;
                self.keys.put(name, &k)?;
                k
            }
        };

        // 2. Fetch the server key and pin it, or check it against --server-key.
        let api = ApiClient::new(self.http.clone(), &url)?;
        let info = api.info().await?;
        let presented = PublicKey::from_b64(&info.server_pubkey)?;
        // An invite code carries the index key too; check whichever we were given.
        let invite_key = invite
            .as_deref()
            .and_then(|c| lemonwire_proto::api::parse_invite_code(c).1)
            .map(str::to_owned);
        let expected_keys: Vec<&String> = server_key.iter().chain(invite_key.iter()).collect();
        let pinned_out_of_band = !expected_keys.is_empty();
        for expected in expected_keys {
            let expected = PublicKey::from_b64(expected)?;
            if expected != presented {
                return Err(ClientError::ServerKeyMismatch {
                    expected: expected.fingerprint(),
                    actual: presented.fingerprint(),
                });
            }
        }

        // 3. Redeem an invite if we have one: it adds our public key to the members
        //    list under our member name.
        let joined_with_invite = if let Some(inv) = &invite {
            let shown = member_name.clone().unwrap_or_else(|| name.to_owned());
            api.join(inv, &key, &shown).await?;
            true
        } else {
            false
        };

        // 4. Try to log in: works now if we joined, or the admin already added this key.
        //    If it does, learn the member name the index has for us.
        let (member, member_name) = match api.login(&key, &presented).await {
            Ok(login) => {
                let me = api.me(&login.token).await.ok().map(|m| m.name);
                self.sessions.lock().await.insert(name.to_owned(), login);
                (true, me.or(member_name))
            }
            Err(ClientError::NotAMember) => (false, member_name),
            Err(e) => return Err(e),
        };

        let profile = Profile {
            name: name.to_owned(),
            url,
            server_pubkey: presented.to_b64(),
            member_name,
            public_key: key.public().to_b64(),
            default: profiles.is_empty(),
            allow_insecure,
        };
        profiles.push(profile.clone());
        self.config.save_profiles(&profiles)?;
        Ok(Output::ProfileAdded {
            profile: profile.view(),
            pinned_out_of_band,
            joined_with_invite,
            member,
        })
    }

    async fn remember_member_name(&self, profile: &str, member_name: &str) -> Result<()> {
        let _guard = self.state_lock.lock().await;
        let mut profiles = self.config.load_profiles()?;
        if let Some(p) = profiles.iter_mut().find(|p| p.name == profile) {
            p.member_name = Some(member_name.to_owned());
            self.config.save_profiles(&profiles)?;
        }
        Ok(())
    }

    async fn profile_remove(&self, name: &str) -> Result<Output> {
        let _guard = self.state_lock.lock().await;
        let mut profiles = self.config.load_profiles()?;
        let Some(pos) = profiles.iter().position(|p| p.name == name) else {
            return Err(ClientError::NoSuchProfile(name.to_owned()));
        };
        if self
            .config
            .load_transfers()?
            .iter()
            .any(|t| t.profile == name)
        {
            return Err(ClientError::Invalid(format!(
                "profile {name:?} has transfers; cancel them first (`lemonwire transfers`)"
            )));
        }
        let removed = profiles.remove(pos);
        if removed.default && profiles.len() == 1 {
            profiles[0].default = true;
        }
        self.config.save_profiles(&profiles)?;
        self.keys.delete(name)?;
        self.sessions.lock().await.remove(name);
        Ok(Output::Done {
            message: format!("Removed profile {name:?} and its key."),
        })
    }

    async fn profile_set_default(&self, name: &str) -> Result<Output> {
        let _guard = self.state_lock.lock().await;
        let mut profiles = self.config.load_profiles()?;
        if !profiles.iter().any(|p| p.name == name) {
            return Err(ClientError::NoSuchProfile(name.to_owned()));
        }
        for p in &mut profiles {
            p.default = p.name == name;
        }
        self.config.save_profiles(&profiles)?;
        Ok(Output::Done {
            message: format!("{name:?} is now the default profile."),
        })
    }

    /// A logged-in API client for a profile, reusing a cached session while valid.
    pub(crate) async fn session(&self, p: &Profile) -> Result<(ApiClient, LoginResponse)> {
        let api = ApiClient::new(self.http.clone(), &p.url)?;
        let mut sessions = self.sessions.lock().await;
        if let Some(s) = sessions.get(&p.name)
            && s.expires_at > now() + 60
        {
            return Ok((api, s.clone()));
        }
        let pinned = PublicKey::from_b64(&p.server_pubkey)?;
        let key = self.key(&p.name)?;
        let login = api.login(&key, &pinned).await?;
        // The announce URL carries our passkey: same rule as the index URL.
        let announce = url::Url::parse(&login.announce_url)
            .map_err(|_| ClientError::InvalidUrl(login.announce_url.clone()))?;
        crate::api::check_plain_http(&announce, p.allow_insecure)?;
        sessions.insert(p.name.clone(), login.clone());
        Ok((api, login))
    }

    pub(crate) async fn session_for(
        &self,
        profile: Option<&str>,
    ) -> Result<(ApiClient, LoginResponse)> {
        let p = self.profile(profile)?;
        self.session(&p).await
    }

    /// (seeders, leechers, members with a full copy) from the tracker.
    pub(crate) async fn scrape(&self, p: &Profile, infohash: &str) -> Result<(u64, u64, u64)> {
        let (api, login) = self.session(p).await?;
        api.scrape(&login.announce_url, infohash).await
    }

    async fn info(&self, profile: Option<&str>) -> Result<Output> {
        let p = self.profile(profile)?;
        let api = ApiClient::new(self.http.clone(), &p.url)?;
        let server = api.info().await?;
        if server.server_pubkey != p.server_pubkey {
            return Err(ClientError::ServerKeyMismatch {
                expected: keys::fingerprint(&p.server_pubkey),
                actual: keys::fingerprint(&server.server_pubkey),
            });
        }
        let member = match self.session(&p).await {
            Ok(_) => true,
            Err(ClientError::NotAMember) => false,
            Err(e) => return Err(e),
        };
        Ok(Output::Info {
            profile: p.view(),
            server,
            member,
        })
    }

    pub async fn shutdown(&self) {
        if let Some(e) = &self.engine {
            e.shutdown().await;
        }
    }
}
