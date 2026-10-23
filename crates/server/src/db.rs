//! SQLite storage (spec §4.2). All SQL is parameterised; the only dynamic SQL is the
//! FTS query, which is built from alphanumeric tokens (see [`fts_query`]).
//!
//! Nothing in the database lets someone in on its own: session tokens and invite
//! tokens are stored as SHA-256 hashes, and passkeys are derived from the server's
//! secret key (kept in a separate `server.key` file) and stored only as hashes.

use std::path::{Path, PathBuf};

use hmac::{Hmac, KeyInit, Mac};
use lemonwire_proto::api::{FileEntry, Invite, Member, TorrentEntry};
use lemonwire_proto::keys::{self, KeyPair};
use lemonwire_proto::metainfo::ParsedTorrent;
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};

pub const CHALLENGE_TTL_SECS: i64 = 120;
pub const SESSION_TTL_SECS: i64 = 12 * 3600;
pub const KEY_FILE: &str = "server.key";
/// Invite codes look like `lw1.<token>.<server public key>`.
pub const INVITE_PREFIX: &str = "lw1";

#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error("{0}")]
    Conflict(String),
    #[error("{0}")]
    NotFound(String),
    #[error("{0}")]
    Invalid(String),
    #[error("{0}: {1}")]
    Io(String, std::io::Error),
}

pub type Result<T> = std::result::Result<T, DbError>;

pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after 1970")
        .as_secs() as i64
}

fn random_token() -> Result<String> {
    keys::random_token().map_err(|e| DbError::Invalid(e.to_string()))
}

/// Secrets are stored as SHA-256 hashes, so a copy of the database can't be used to
/// log in, redeem an invite or announce.
pub fn secret_hash(secret: &str) -> String {
    hex::encode(Sha256::digest(secret.as_bytes()))
}

/// The token part of an invite: accepts the full `lw1.<token>.<key>` code or a bare
/// token.
pub fn invite_token(code: &str) -> &str {
    let code = code.trim();
    match code.split('.').collect::<Vec<_>>().as_slice() {
        [prefix, token, _key] if *prefix == INVITE_PREFIX => token,
        _ => code,
    }
}

#[derive(Debug, Clone)]
pub struct User {
    pub pubkey: String,
    pub name: String,
    pub is_admin: bool,
    /// Bumped by rotate-passkey; part of the passkey derivation.
    pub passkey_gen: i64,
    pub created_at: i64,
}

impl User {
    pub fn member(&self) -> Member {
        Member {
            pubkey: self.pubkey.clone(),
            name: self.name.clone(),
            is_admin: self.is_admin,
            created_at: self.created_at,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct SearchQuery {
    pub text: String,
    pub limit: u32,
    pub offset: u32,
    /// Only entries uploaded by this public key.
    pub uploader: Option<String>,
}

pub struct InitParams<'a> {
    pub name: &'a str,
    pub admin_pubkey: &'a str,
    pub admin_name: &'a str,
    pub public_url: &'a str,
    pub tracker_url: &'a str,
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS users (
    pubkey TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE COLLATE NOCASE,
    is_admin INTEGER NOT NULL DEFAULT 0,
    passkey_hash TEXT NOT NULL UNIQUE,
    passkey_gen INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS invites (
    token_hash TEXT PRIMARY KEY,
    is_admin INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    used_by TEXT
);
CREATE TABLE IF NOT EXISTS challenges (
    nonce TEXT PRIMARY KEY,
    pubkey TEXT NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    pubkey TEXT NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_pubkey ON sessions(pubkey);
CREATE TABLE IF NOT EXISTS torrents (
    infohash TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    size INTEGER NOT NULL,
    files_json TEXT NOT NULL,
    tags_json TEXT NOT NULL,
    uploader_pubkey TEXT NOT NULL,
    uploader_name TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    torrent_blob BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS torrents_created ON torrents(created_at);
CREATE INDEX IF NOT EXISTS torrents_uploader ON torrents(uploader_pubkey);
CREATE VIRTUAL TABLE IF NOT EXISTS torrents_fts USING fts5(
    infohash UNINDEXED, name, tags, files,
    tokenize = 'unicode61 remove_diacritics 2'
);
"#;

pub struct Db {
    conn: Connection,
    /// Where the server's secret key lives (`None` in memory: tests).
    key_path: Option<PathBuf>,
    server: Option<KeyPair>,
}

fn has_column(conn: &Connection, table: &str, column: &str) -> Result<bool> {
    let mut st = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let cols = st.query_map([], |r| r.get::<_, String>(1))?;
    for c in cols {
        if c? == column {
            return Ok(true);
        }
    }
    Ok(false)
}

fn write_key_file(path: &Path, key: &KeyPair) -> Result<()> {
    use std::io::Write;
    let io = |e| DbError::Io(path.display().to_string(), e);
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path).map_err(io)?;
    f.write_all(key.secret_b64().as_bytes()).map_err(io)?;
    f.sync_all().map_err(io)
}

impl Db {
    /// Open `index.db`; the server key is read from `server.key` next to it.
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        let key_path = path.with_file_name(KEY_FILE);
        let mut db = Self {
            conn,
            key_path: Some(key_path),
            server: None,
        };
        db.prepare()?;
        Ok(db)
    }

    pub fn open_in_memory() -> Result<Self> {
        let mut db = Self {
            conn: Connection::open_in_memory()?,
            key_path: None,
            server: None,
        };
        db.prepare()?;
        Ok(db)
    }

    /// Load the server key, migrate older databases, and create missing tables.
    fn prepare(&mut self) -> Result<()> {
        // Older versions kept the secret key in `meta`: move it out to its own file.
        let legacy_secret: Option<String> = self
            .conn
            .query_row(
                "SELECT value FROM meta WHERE key = 'server_secret'",
                [],
                |r| r.get(0),
            )
            .optional()
            .or_else(|e| match e {
                // No meta table yet: a brand new database.
                rusqlite::Error::SqliteFailure(..) => Ok(None),
                e => Err(e),
            })?;
        if let Some(path) = &self.key_path {
            match std::fs::read_to_string(path) {
                Ok(s) => {
                    self.server = Some(
                        KeyPair::from_secret_b64(s.trim())
                            .map_err(|e| DbError::Invalid(format!("{}: {e}", path.display())))?,
                    )
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    if let Some(secret) = &legacy_secret {
                        let key = KeyPair::from_secret_b64(secret)
                            .map_err(|e| DbError::Invalid(e.to_string()))?;
                        write_key_file(path, &key)?;
                        self.server = Some(key);
                    }
                }
                Err(e) => return Err(DbError::Io(path.display().to_string(), e)),
            }
        } else if let Some(secret) = &legacy_secret {
            self.server = Some(
                KeyPair::from_secret_b64(secret).map_err(|e| DbError::Invalid(e.to_string()))?,
            );
        }
        if legacy_secret.is_some() && self.key_path.is_some() {
            self.conn
                .execute("DELETE FROM meta WHERE key = 'server_secret'", [])?;
        }
        self.migrate_plaintext_secrets()?;
        self.conn.execute_batch(SCHEMA)?;
        Ok(())
    }

    /// Older versions stored passkeys and invite tokens in plain text.
    fn migrate_plaintext_secrets(&mut self) -> Result<()> {
        let old_users = has_column(&self.conn, "users", "passkey")?;
        let old_invites = has_column(&self.conn, "invites", "token")?;
        if !old_users && !old_invites {
            return Ok(());
        }
        let server = self.server.clone().ok_or_else(|| {
            DbError::Invalid("can't migrate the database without its server key".into())
        })?;
        let tx = self.conn.transaction()?;
        if old_users {
            tx.execute_batch("ALTER TABLE users RENAME TO users_old;")?;
            tx.execute_batch(SCHEMA)?;
            let rows: Vec<(String, String, bool, i64)> = {
                let mut st =
                    tx.prepare("SELECT pubkey, name, is_admin, created_at FROM users_old")?;
                st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
                    .collect::<rusqlite::Result<_>>()?
            };
            for (pubkey, name, is_admin, created_at) in rows {
                // Passkeys are now derived, so every member gets a new one (they pick it
                // up at their next login).
                let hash = secret_hash(&derive_passkey(&server, &pubkey, 0));
                tx.execute(
                    "INSERT INTO users (pubkey, name, is_admin, passkey_hash, passkey_gen, created_at)
                     VALUES (?1, ?2, ?3, ?4, 0, ?5)",
                    params![pubkey, name, is_admin, hash, created_at],
                )?;
            }
            tx.execute_batch("DROP TABLE users_old;")?;
        }
        if old_invites {
            tx.execute_batch("ALTER TABLE invites RENAME TO invites_old;")?;
            tx.execute_batch(SCHEMA)?;
            let rows: Vec<(String, bool, i64, i64, Option<String>)> = {
                let mut st = tx.prepare(
                    "SELECT token, is_admin, created_at, expires_at, used_by FROM invites_old",
                )?;
                st.query_map([], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
                })?
                .collect::<rusqlite::Result<_>>()?
            };
            for (token, is_admin, created_at, expires_at, used_by) in rows {
                tx.execute(
                    "INSERT INTO invites (token_hash, is_admin, created_at, expires_at, used_by)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![
                        secret_hash(&token),
                        is_admin,
                        created_at,
                        expires_at,
                        used_by
                    ],
                )?;
            }
            tx.execute_batch("DROP TABLE invites_old;")?;
        }
        tx.commit()?;
        Ok(())
    }

    // ---- meta / init ---------------------------------------------------------

    pub fn meta(&self, key: &str) -> Result<Option<String>> {
        Ok(self
            .conn
            .query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get(0))
            .optional()?)
    }

    fn set_meta(&self, key: &str, value: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO meta (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            [key, value],
        )?;
        Ok(())
    }

    pub fn is_initialized(&self) -> Result<bool> {
        Ok(self.meta("server_pub")?.is_some())
    }

    /// Create the server key pair and the admin member. Refuses to run twice.
    pub fn init(&mut self, p: &InitParams) -> Result<KeyPair> {
        if self.is_initialized()? || self.key_path.as_ref().is_some_and(|k| k.exists()) {
            return Err(DbError::Conflict(
                "this data directory is already initialised".into(),
            ));
        }
        let admin = keys::PublicKey::from_b64(p.admin_pubkey)
            .map_err(|e| DbError::Invalid(format!("admin public key: {e}")))?;
        validate_name(p.admin_name)?;
        let server = KeyPair::generate().map_err(|e| DbError::Invalid(e.to_string()))?;
        if let Some(path) = &self.key_path {
            write_key_file(path, &server)?;
        }
        self.server = Some(server.clone());
        let tx = self.conn.transaction()?;
        {
            let set = |k: &str, v: &str| {
                tx.execute("INSERT INTO meta (key, value) VALUES (?1, ?2)", [k, v])
            };
            set("name", p.name)?;
            set("server_pub", &server.public().to_b64())?;
            set("public_url", p.public_url.trim_end_matches('/'))?;
            set("tracker_url", p.tracker_url.trim_end_matches('/'))?;
            insert_user(&tx, &server, &admin.to_b64(), p.admin_name, true)?;
        }
        tx.commit()?;
        Ok(server)
    }

    pub fn server_keypair(&self) -> Result<KeyPair> {
        self.server
            .clone()
            .ok_or_else(|| DbError::NotFound("not initialised: run `lemonwire-server init`".into()))
    }

    pub fn set_tracker_url(&self, url: &str) -> Result<()> {
        self.set_meta("tracker_url", url.trim_end_matches('/'))
    }

    pub fn set_public_url(&self, url: &str) -> Result<()> {
        self.set_meta("public_url", url.trim_end_matches('/'))
    }

    // ---- members -------------------------------------------------------------

    fn user_from_row(r: &rusqlite::Row) -> rusqlite::Result<User> {
        Ok(User {
            pubkey: r.get(0)?,
            name: r.get(1)?,
            is_admin: r.get(2)?,
            passkey_gen: r.get(3)?,
            created_at: r.get(4)?,
        })
    }

    const USER_COLS: &'static str = "pubkey, name, is_admin, passkey_gen, created_at";

    /// This member's tracker passkey. Derived from the server key, so it's never stored.
    pub fn passkey(&self, user: &User) -> Result<String> {
        Ok(derive_passkey(
            &self.server_keypair()?,
            &user.pubkey,
            user.passkey_gen,
        ))
    }

    pub fn members(&self) -> Result<Vec<User>> {
        let mut st = self.conn.prepare(&format!(
            "SELECT {} FROM users ORDER BY created_at, name",
            Self::USER_COLS
        ))?;
        let rows = st.query_map([], Self::user_from_row)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn user(&self, pubkey: &str) -> Result<Option<User>> {
        Ok(self
            .conn
            .query_row(
                &format!("SELECT {} FROM users WHERE pubkey = ?1", Self::USER_COLS),
                [pubkey],
                Self::user_from_row,
            )
            .optional()?)
    }

    pub fn user_by_passkey(&self, passkey: &str) -> Result<Option<User>> {
        Ok(self
            .conn
            .query_row(
                &format!(
                    "SELECT {} FROM users WHERE passkey_hash = ?1",
                    Self::USER_COLS
                ),
                [secret_hash(passkey)],
                Self::user_from_row,
            )
            .optional()?)
    }

    pub fn add_member(&self, pubkey: &str, name: &str, is_admin: bool) -> Result<User> {
        let key = keys::PublicKey::from_b64(pubkey)
            .map_err(|e| DbError::Invalid(format!("public key: {e}")))?;
        validate_name(name)?;
        insert_user(
            &self.conn,
            &self.server_keypair()?,
            &key.to_b64(),
            name,
            is_admin,
        )?;
        Ok(self.user(&key.to_b64())?.expect("just inserted"))
    }

    /// Resolve a member by full public key, exact name, or unique public-key prefix
    /// (at least 6 characters).
    pub fn resolve_member(&self, selector: &str) -> Result<User> {
        if let Some(u) = self.user(selector)? {
            return Ok(u);
        }
        let all = self.members()?;
        if let Some(u) = all.iter().find(|u| u.name.eq_ignore_ascii_case(selector)) {
            return Ok(u.clone());
        }
        if selector.len() >= 6 {
            let matches: Vec<_> = all
                .iter()
                .filter(|u| u.pubkey.starts_with(selector))
                .collect();
            match matches.len() {
                1 => return Ok(matches[0].clone()),
                n if n > 1 => {
                    return Err(DbError::Invalid(format!(
                        "{selector:?} matches {n} members; use more of the key"
                    )));
                }
                _ => {}
            }
        }
        Err(DbError::NotFound(format!("no member matches {selector:?}")))
    }

    /// Delete a member and their sessions and pending challenges. Their passkey goes
    /// with them, so the tracker stops serving them immediately.
    pub fn revoke(&mut self, pubkey: &str) -> Result<()> {
        let tx = self.conn.transaction()?;
        let admins: i64 = tx.query_row(
            "SELECT COUNT(*) FROM users WHERE is_admin = 1 AND pubkey != ?1",
            [pubkey],
            |r| r.get(0),
        )?;
        let is_admin: Option<bool> = tx
            .query_row(
                "SELECT is_admin FROM users WHERE pubkey = ?1",
                [pubkey],
                |r| r.get(0),
            )
            .optional()?;
        match is_admin {
            None => return Err(DbError::NotFound("no such member".into())),
            Some(true) if admins == 0 => {
                return Err(DbError::Invalid("refusing to revoke the last admin".into()));
            }
            _ => {}
        }
        tx.execute("DELETE FROM sessions WHERE pubkey = ?1", [pubkey])?;
        tx.execute("DELETE FROM challenges WHERE pubkey = ?1", [pubkey])?;
        tx.execute("DELETE FROM users WHERE pubkey = ?1", [pubkey])?;
        tx.commit()?;
        Ok(())
    }

    /// Issue a new passkey (the old one stops working at once).
    pub fn rotate_passkey(&self, pubkey: &str) -> Result<()> {
        let user = self
            .user(pubkey)?
            .ok_or_else(|| DbError::NotFound("no such member".into()))?;
        let gen_ = user.passkey_gen + 1;
        let hash = secret_hash(&derive_passkey(&self.server_keypair()?, pubkey, gen_));
        self.conn.execute(
            "UPDATE users SET passkey_gen = ?1, passkey_hash = ?2 WHERE pubkey = ?3",
            params![gen_, hash, pubkey],
        )?;
        Ok(())
    }

    // ---- invites -------------------------------------------------------------

    /// Create an invite. The returned `code` (`lw1.<token>.<server key>`) is the only
    /// time the token is visible: only its hash is stored.
    pub fn create_invite(&self, is_admin: bool, ttl_hours: u32) -> Result<Invite> {
        let token = random_token()?;
        let server_pub = self.server_keypair()?.public().to_b64();
        let hash = secret_hash(&token);
        let created_at = now();
        let expires_at = created_at + i64::from(ttl_hours.clamp(1, 24 * 30)) * 3600;
        self.conn.execute(
            "INSERT INTO invites (token_hash, is_admin, created_at, expires_at) VALUES (?1, ?2, ?3, ?4)",
            params![hash, is_admin, created_at, expires_at],
        )?;
        Ok(Invite {
            id: hash[..12].to_owned(),
            code: Some(format!("{INVITE_PREFIX}.{token}.{server_pub}")),
            is_admin,
            created_at,
            expires_at,
            used_by: None,
        })
    }

    pub fn invites(&self) -> Result<Vec<Invite>> {
        let mut st = self.conn.prepare(
            "SELECT token_hash, is_admin, created_at, expires_at, used_by FROM invites ORDER BY created_at",
        )?;
        let rows = st.query_map([], |r| {
            let hash: String = r.get(0)?;
            Ok(Invite {
                id: hash[..12].to_owned(),
                code: None,
                is_admin: r.get(1)?,
                created_at: r.get(2)?,
                expires_at: r.get(3)?,
                used_by: r.get(4)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Redeem an invite (full code or bare token) and create the member, atomically.
    /// An invite works once.
    pub fn redeem_invite(&mut self, code: &str, pubkey: &str, name: &str) -> Result<User> {
        let key = keys::PublicKey::from_b64(pubkey)
            .map_err(|e| DbError::Invalid(format!("public key: {e}")))?;
        validate_name(name)?;
        let server = self.server_keypair()?;
        let tx = self.conn.transaction()?;
        let is_admin: Option<bool> = tx
            .query_row(
                "UPDATE invites SET used_by = ?1
                 WHERE token_hash = ?2 AND used_by IS NULL AND expires_at > ?3
                 RETURNING is_admin",
                params![key.to_b64(), secret_hash(invite_token(code)), now()],
                |r| r.get(0),
            )
            .optional()?;
        let Some(is_admin) = is_admin else {
            return Err(DbError::NotFound(
                "invite is invalid, expired or already used".into(),
            ));
        };
        insert_user(&tx, &server, &key.to_b64(), name, is_admin)?;
        tx.commit()?;
        Ok(self.user(&key.to_b64())?.expect("just inserted"))
    }

    // ---- challenges and sessions -------------------------------------------

    pub fn create_challenge(&self, pubkey: &str) -> Result<String> {
        let nonce = random_token()?;
        self.conn.execute(
            "INSERT INTO challenges (nonce, pubkey, expires_at) VALUES (?1, ?2, ?3)",
            params![nonce, pubkey, now() + CHALLENGE_TTL_SECS],
        )?;
        Ok(nonce)
    }

    /// Consume a nonce. Returns the public key it was issued to, if it existed and
    /// hadn't expired. Either way the nonce is gone afterwards.
    pub fn take_challenge(&self, nonce: &str) -> Result<Option<String>> {
        let row: Option<(String, i64)> = self
            .conn
            .query_row(
                "DELETE FROM challenges WHERE nonce = ?1 RETURNING pubkey, expires_at",
                [nonce],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        Ok(row.filter(|(_, exp)| *exp > now()).map(|(pk, _)| pk))
    }

    pub fn create_session(&self, pubkey: &str) -> Result<(String, i64)> {
        let token = random_token()?;
        let expires_at = now() + SESSION_TTL_SECS;
        self.conn.execute(
            "INSERT INTO sessions (token, pubkey, expires_at) VALUES (?1, ?2, ?3)",
            params![secret_hash(&token), pubkey, expires_at],
        )?;
        Ok((token, expires_at))
    }

    /// The member a session token belongs to, if the session is current.
    pub fn session_user(&self, token: &str) -> Result<Option<User>> {
        Ok(self
            .conn
            .query_row(
                "SELECT u.pubkey, u.name, u.is_admin, u.passkey_gen, u.created_at
                 FROM users u JOIN sessions s ON s.pubkey = u.pubkey
                 WHERE s.token = ?1 AND s.expires_at > ?2",
                params![secret_hash(token), now()],
                Self::user_from_row,
            )
            .optional()?)
    }

    pub fn purge_expired(&self) -> Result<usize> {
        let t = now();
        let mut n = self
            .conn
            .execute("DELETE FROM challenges WHERE expires_at <= ?1", [t])?;
        n += self
            .conn
            .execute("DELETE FROM sessions WHERE expires_at <= ?1", [t])?;
        n += self.conn.execute(
            "DELETE FROM invites WHERE used_by IS NULL AND expires_at <= ?1",
            [t],
        )?;
        Ok(n)
    }

    pub fn torrents_by(&self, uploader_pubkey: &str) -> Result<u64> {
        Ok(self.conn.query_row(
            "SELECT COUNT(*) FROM torrents WHERE uploader_pubkey = ?1",
            [uploader_pubkey],
            |r| r.get::<_, i64>(0),
        )? as u64)
    }

    // ---- torrents ------------------------------------------------------------

    pub fn insert_torrent(
        &mut self,
        t: &ParsedTorrent,
        stripped: &[u8],
        tags: &[String],
        uploader: &User,
    ) -> Result<TorrentEntry> {
        let entry = TorrentEntry {
            infohash: t.infohash.clone(),
            name: t.name.clone(),
            size: t.size,
            files: t.files.clone(),
            tags: tags.to_vec(),
            uploader: uploader.name.clone(),
            created_at: now(),
        };
        let files_json = serde_json::to_string(&entry.files).expect("serialisable");
        let tags_json = serde_json::to_string(&entry.tags).expect("serialisable");
        let tx = self.conn.transaction()?;
        let inserted = tx.execute(
            "INSERT INTO torrents (infohash, name, size, files_json, tags_json, uploader_pubkey,
                                   uploader_name, created_at, torrent_blob)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT(infohash) DO NOTHING",
            params![
                entry.infohash,
                entry.name,
                entry.size as i64,
                files_json,
                tags_json,
                uploader.pubkey,
                uploader.name,
                entry.created_at,
                stripped
            ],
        )?;
        if inserted == 0 {
            return Err(DbError::Conflict(
                "this torrent is already in the index".into(),
            ));
        }
        tx.execute(
            "INSERT INTO torrents_fts (infohash, name, tags, files) VALUES (?1, ?2, ?3, ?4)",
            params![
                entry.infohash,
                entry.name,
                entry.tags.join(" "),
                entry
                    .files
                    .iter()
                    .map(|f| f.path.as_str())
                    .collect::<Vec<_>>()
                    .join(" ")
            ],
        )?;
        tx.commit()?;
        Ok(entry)
    }

    fn entry_from_row(r: &rusqlite::Row) -> rusqlite::Result<TorrentEntry> {
        let files_json: String = r.get(3)?;
        let tags_json: String = r.get(4)?;
        Ok(TorrentEntry {
            infohash: r.get(0)?,
            name: r.get(1)?,
            size: r.get::<_, i64>(2)? as u64,
            files: serde_json::from_str::<Vec<FileEntry>>(&files_json).unwrap_or_default(),
            tags: serde_json::from_str(&tags_json).unwrap_or_default(),
            uploader: r.get(5)?,
            created_at: r.get(6)?,
        })
    }

    const ENTRY_COLS: &'static str =
        "t.infohash, t.name, t.size, t.files_json, t.tags_json, t.uploader_name, t.created_at";

    /// Returns the entry, the stored (stripped) torrent and the uploader's public key.
    pub fn torrent(&self, infohash: &str) -> Result<Option<(TorrentEntry, Vec<u8>, String)>> {
        Ok(self
            .conn
            .query_row(
                &format!(
                    "SELECT {}, t.torrent_blob, t.uploader_pubkey FROM torrents t WHERE t.infohash = ?1",
                    Self::ENTRY_COLS
                ),
                [infohash],
                |r| Ok((Self::entry_from_row(r)?, r.get(7)?, r.get(8)?)),
            )
            .optional()?)
    }

    pub fn torrent_exists(&self, infohash: &str) -> Result<bool> {
        Ok(self
            .conn
            .query_row(
                "SELECT 1 FROM torrents WHERE infohash = ?1",
                [infohash],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    pub fn delete_torrent(&mut self, infohash: &str) -> Result<()> {
        let tx = self.conn.transaction()?;
        let n = tx.execute("DELETE FROM torrents WHERE infohash = ?1", [infohash])?;
        tx.execute("DELETE FROM torrents_fts WHERE infohash = ?1", [infohash])?;
        tx.commit()?;
        if n == 0 {
            return Err(DbError::NotFound("no such torrent".into()));
        }
        Ok(())
    }

    pub fn recent(&self, limit: u32) -> Result<Vec<TorrentEntry>> {
        self.search(&SearchQuery {
            limit,
            ..Default::default()
        })
    }

    /// Ranked full-text search, or newest first for an empty query. Optionally only
    /// one uploader's entries.
    pub fn search(&self, q: &SearchQuery) -> Result<Vec<TorrentEntry>> {
        let uploader = q.uploader.as_deref();
        let rows = match fts_query(&q.text) {
            None => {
                let mut st = self.conn.prepare(&format!(
                    "SELECT {} FROM torrents t
                     WHERE (?3 IS NULL OR t.uploader_pubkey = ?3)
                     ORDER BY t.created_at DESC, t.rowid DESC LIMIT ?1 OFFSET ?2",
                    Self::ENTRY_COLS
                ))?;
                st.query_map(params![q.limit, q.offset, uploader], Self::entry_from_row)?
                    .collect::<rusqlite::Result<_>>()?
            }
            Some(fts) => {
                let mut st = self.conn.prepare(&format!(
                    "SELECT {} FROM torrents_fts f JOIN torrents t ON t.infohash = f.infohash
                     WHERE torrents_fts MATCH ?1 AND (?4 IS NULL OR t.uploader_pubkey = ?4)
                     ORDER BY f.rank LIMIT ?2 OFFSET ?3",
                    Self::ENTRY_COLS
                ))?;
                st.query_map(
                    params![fts, q.limit, q.offset, uploader],
                    Self::entry_from_row,
                )?
                .collect::<rusqlite::Result<_>>()?
            }
        };
        Ok(rows)
    }
}

/// Passkey = HMAC-SHA256(server secret, protocol | pubkey | generation), base64.
fn derive_passkey(server: &KeyPair, pubkey: &str, generation: i64) -> String {
    let secret = keys::b64_decode(&server.secret_b64()).expect("valid secret");
    let mut mac = Hmac::<Sha256>::new_from_slice(&secret).expect("any key length");
    mac.update(format!("lemonwire-v1|passkey|{pubkey}|{generation}").as_bytes());
    keys::b64_encode(&mac.finalize().into_bytes())
}

fn insert_user(
    conn: &Connection,
    server: &KeyPair,
    pubkey: &str,
    name: &str,
    is_admin: bool,
) -> Result<()> {
    let r = conn.execute(
        "INSERT INTO users (pubkey, name, is_admin, passkey_hash, passkey_gen, created_at)
         VALUES (?1, ?2, ?3, ?4, 0, ?5)",
        params![
            pubkey,
            name,
            is_admin,
            secret_hash(&derive_passkey(server, pubkey, 0)),
            now()
        ],
    );
    match r {
        Ok(_) => Ok(()),
        Err(rusqlite::Error::SqliteFailure(e, msg))
            if e.code == rusqlite::ErrorCode::ConstraintViolation =>
        {
            let what = if msg.as_deref().unwrap_or("").contains("users.name") {
                "that name is already taken"
            } else {
                "that key is already a member"
            };
            Err(DbError::Conflict(what.into()))
        }
        Err(e) => Err(e.into()),
    }
}

/// Display names: 1–64 characters, no control characters, not blank.
pub fn validate_name(name: &str) -> Result<()> {
    let ok = !name.trim().is_empty()
        && name.chars().count() <= lemonwire_proto::api::limits::MAX_NAME_LEN
        && !name.chars().any(char::is_control);
    if ok {
        Ok(())
    } else {
        Err(DbError::Invalid(
            "names must be 1-64 characters with no control characters".into(),
        ))
    }
}

/// Build a safe FTS5 query: split on anything non-alphanumeric and turn each token
/// into a quoted prefix term (`"tok"*`), ANDed together. `None` means "no terms".
pub fn fts_query(q: &str) -> Option<String> {
    let terms: Vec<String> = q
        .split(|c: char| !c.is_alphanumeric())
        .filter(|t| !t.is_empty())
        .take(16)
        .map(|t| format!("\"{}\"*", t.to_lowercase()))
        .collect();
    (!terms.is_empty()).then(|| terms.join(" "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use lemonwire_proto::metainfo;

    fn init_db() -> (Db, KeyPair) {
        let mut db = Db::open_in_memory().unwrap();
        let admin = KeyPair::generate().unwrap();
        db.init(&InitParams {
            name: "test",
            admin_pubkey: &admin.public().to_b64(),
            admin_name: "admin",
            public_url: "http://localhost:8080",
            tracker_url: "http://localhost:6969",
        })
        .unwrap();
        (db, admin)
    }

    fn pubkey() -> String {
        KeyPair::generate().unwrap().public().to_b64()
    }

    #[test]
    fn init_once_and_validates_admin_key() {
        let (mut db, _) = init_db();
        assert!(db.server_keypair().is_ok());
        let err = db.init(&InitParams {
            name: "x",
            admin_pubkey: &pubkey(),
            admin_name: "a",
            public_url: "",
            tracker_url: "",
        });
        assert!(matches!(err, Err(DbError::Conflict(_))));

        let mut fresh = Db::open_in_memory().unwrap();
        let err = fresh.init(&InitParams {
            name: "x",
            admin_pubkey: "not-a-key",
            admin_name: "a",
            public_url: "",
            tracker_url: "",
        });
        assert!(matches!(err, Err(DbError::Invalid(_))));
        assert!(!fresh.is_initialized().unwrap());
    }

    #[test]
    fn fts_query_is_sanitised() {
        assert_eq!(fts_query(""), None);
        assert_eq!(fts_query("  -- ** "), None);
        assert_eq!(
            fts_query("The Pitt S01"),
            Some(r#""the"* "pitt"* "s01"*"#.into())
        );
        assert_eq!(
            fts_query(r#"a" OR name:* NEAR(x"#),
            Some(r#""a"* "or"* "name"* "near"* "x"*"#.into())
        );
    }

    #[test]
    fn invite_is_single_use() {
        let (mut db, _) = init_db();
        let inv = db.create_invite(false, 24).unwrap();
        db.redeem_invite(inv.code.as_deref().unwrap(), &pubkey(), "alice")
            .unwrap();
        let again = db.redeem_invite(inv.code.as_deref().unwrap(), &pubkey(), "bob");
        assert!(matches!(again, Err(DbError::NotFound(_))));
        // A failed redemption (name taken) doesn't burn the invite.
        let inv2 = db.create_invite(false, 24).unwrap();
        assert!(
            db.redeem_invite(inv2.code.as_deref().unwrap(), &pubkey(), "ALICE")
                .is_err()
        );
        db.redeem_invite(inv2.code.as_deref().unwrap(), &pubkey(), "carol")
            .unwrap();
    }

    #[test]
    fn revoke_kills_sessions_and_protects_last_admin() {
        let (mut db, admin) = init_db();
        let bob = db.add_member(&pubkey(), "bob", false).unwrap();
        let (token, _) = db.create_session(&bob.pubkey).unwrap();
        let pk = db.passkey(&bob).unwrap();
        assert!(db.session_user(&token).unwrap().is_some());
        assert!(db.user_by_passkey(&pk).unwrap().is_some());
        db.revoke(&bob.pubkey).unwrap();
        assert!(db.session_user(&token).unwrap().is_none());
        assert!(db.user_by_passkey(&pk).unwrap().is_none());
        assert!(db.revoke(&admin.public().to_b64()).is_err());
    }

    #[test]
    fn no_usable_secrets_in_the_database() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("index.db");
        let mut db = Db::open(&path).unwrap();
        let admin = KeyPair::generate().unwrap();
        let server = db
            .init(&InitParams {
                name: "t",
                admin_pubkey: &admin.public().to_b64(),
                admin_name: "admin",
                public_url: "",
                tracker_url: "",
            })
            .unwrap();
        let user = db.user(&admin.public().to_b64()).unwrap().unwrap();
        let passkey = db.passkey(&user).unwrap();
        let invite = db.create_invite(false, 24).unwrap();
        let code = invite.code.clone().unwrap();
        let (session, _) = db.create_session(&user.pubkey).unwrap();
        drop(db);

        // The server key is in its own 0600 file, not the database.
        let key_file = dir.path().join(KEY_FILE);
        assert_eq!(
            std::fs::read_to_string(&key_file).unwrap(),
            server.secret_b64()
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&key_file).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        // No secret appears anywhere in the database file.
        let _ = Connection::open(&path)
            .unwrap()
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);");
        let raw = String::from_utf8_lossy(&std::fs::read(&path).unwrap()).into_owned();
        for secret in [
            server.secret_b64(),
            passkey.clone(),
            invite_token(&code).to_owned(),
            session,
        ] {
            assert!(!raw.contains(&secret), "found a secret in index.db");
        }
        // And the invite code carries the server key.
        let (_, key) = lemonwire_proto::api::parse_invite_code(&code);
        assert_eq!(key, Some(server.public().to_b64().as_str()));

        // Reopening finds the key again; init refuses to run twice.
        let mut db = Db::open(&path).unwrap();
        assert_eq!(db.server_keypair().unwrap().public(), server.public());
        assert!(db.passkey(&user).unwrap() == passkey);
        assert!(matches!(
            db.init(&InitParams {
                name: "t",
                admin_pubkey: &admin.public().to_b64(),
                admin_name: "admin",
                public_url: "",
                tracker_url: "",
            }),
            Err(DbError::Conflict(_))
        ));
    }

    #[test]
    fn rotating_a_passkey_retires_the_old_one() {
        let (db, admin) = init_db();
        let user = db.user(&admin.public().to_b64()).unwrap().unwrap();
        let old = db.passkey(&user).unwrap();
        db.rotate_passkey(&user.pubkey).unwrap();
        let user = db.user(&user.pubkey).unwrap().unwrap();
        let new = db.passkey(&user).unwrap();
        assert_ne!(old, new);
        assert!(db.user_by_passkey(&old).unwrap().is_none());
        assert!(db.user_by_passkey(&new).unwrap().is_some());
    }

    #[test]
    fn migrates_old_plaintext_databases() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("index.db");
        let server = KeyPair::generate().unwrap();
        let member = KeyPair::generate().unwrap().public().to_b64();
        {
            let c = Connection::open(&path).unwrap();
            c.execute_batch(
                "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                 CREATE TABLE users (pubkey TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE COLLATE NOCASE,
                     is_admin INTEGER NOT NULL DEFAULT 0, passkey TEXT NOT NULL UNIQUE,
                     created_at INTEGER NOT NULL);
                 CREATE TABLE invites (token TEXT PRIMARY KEY, is_admin INTEGER NOT NULL DEFAULT 0,
                     created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, used_by TEXT);",
            )
            .unwrap();
            c.execute(
                "INSERT INTO meta VALUES ('server_secret', ?1), ('server_pub', ?2)",
                [server.secret_b64(), server.public().to_b64()],
            )
            .unwrap();
            c.execute(
                "INSERT INTO users VALUES (?1, 'old', 1, 'PLAINPASSKEY', 1)",
                [&member],
            )
            .unwrap();
            c.execute(
                "INSERT INTO invites VALUES ('PLAININVITE', 0, 1, 99999999999, NULL)",
                [],
            )
            .unwrap();
        }
        let mut db = Db::open(&path).unwrap();
        assert_eq!(db.server_keypair().unwrap().public(), server.public());
        assert!(db.meta("server_secret").unwrap().is_none());
        assert!(dir.path().join(KEY_FILE).exists());
        let user = db.user(&member).unwrap().unwrap();
        assert!(db.user_by_passkey("PLAINPASSKEY").unwrap().is_none());
        let pk = db.passkey(&user).unwrap();
        assert_eq!(db.user_by_passkey(&pk).unwrap().unwrap().name, "old");
        // The old invite still works, now looked up by hash.
        db.redeem_invite("PLAININVITE", &pubkey(), "newbie")
            .unwrap();
    }

    #[test]
    fn challenges_are_single_use() {
        let (db, admin) = init_db();
        let pk = admin.public().to_b64();
        let nonce = db.create_challenge(&pk).unwrap();
        assert_eq!(db.take_challenge(&nonce).unwrap(), Some(pk));
        assert_eq!(db.take_challenge(&nonce).unwrap(), None);
    }

    #[test]
    fn resolve_member_by_name_and_prefix() {
        let (db, _) = init_db();
        let bob = db.add_member(&pubkey(), "Bob", false).unwrap();
        assert_eq!(db.resolve_member("bob").unwrap().pubkey, bob.pubkey);
        assert_eq!(
            db.resolve_member(&bob.pubkey[..10]).unwrap().pubkey,
            bob.pubkey
        );
        assert!(db.resolve_member("nobody").is_err());
    }

    #[test]
    fn search_pages() {
        let (mut db, admin) = init_db();
        let user = db.user(&admin.public().to_b64()).unwrap().unwrap();
        let dir = tempfile::tempdir().unwrap();
        for i in 0..5 {
            let f = dir.path().join(format!("song{i}.mp3"));
            std::fs::write(&f, format!("tune {i}")).unwrap();
            let b = metainfo::build(&f, &Default::default(), |_, _| {
                std::ops::ControlFlow::Continue(())
            })
            .unwrap();
            let stripped = metainfo::strip(&b.bytes).unwrap();
            db.insert_torrent(&b.parsed, &stripped, &[], &user).unwrap();
        }
        for text in ["", "mp3"] {
            let page = |offset| {
                db.search(&SearchQuery {
                    text: text.into(),
                    limit: 2,
                    offset,
                    uploader: None,
                })
                .unwrap()
                .into_iter()
                .map(|e| e.infohash)
                .collect::<Vec<_>>()
            };
            let (a, b, c) = (page(0), page(2), page(4));
            assert_eq!((a.len(), b.len(), c.len()), (2, 2, 1), "query {text:?}");
            let mut all: Vec<_> = a.into_iter().chain(b).chain(c).collect();
            all.sort();
            all.dedup();
            assert_eq!(all.len(), 5, "pages overlap for {text:?}");
        }
    }

    #[test]
    fn publish_search_delete() {
        let (mut db, admin) = init_db();
        let user = db.user(&admin.public().to_b64()).unwrap().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("Holiday Photos 2026");
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("beach.jpg"), b"jpeg").unwrap();
        let built = metainfo::build(&root, &Default::default(), |_, _| {
            std::ops::ControlFlow::Continue(())
        })
        .unwrap();
        let stripped = metainfo::strip(&built.bytes).unwrap();
        db.insert_torrent(&built.parsed, &stripped, &["photos".into()], &user)
            .unwrap();
        assert!(matches!(
            db.insert_torrent(&built.parsed, &stripped, &[], &user),
            Err(DbError::Conflict(_))
        ));
        let search = |text: &str, uploader: Option<String>| {
            db.search(&SearchQuery {
                text: text.into(),
                limit: 10,
                offset: 0,
                uploader,
            })
            .unwrap()
        };
        for q in ["holiday", "HOLI", "photos 2026", "beach", ""] {
            assert_eq!(search(q, None).len(), 1, "query {q:?}");
        }
        assert!(search("nothing", None).is_empty());
        assert_eq!(search("holiday", Some(user.pubkey.clone())).len(), 1);
        assert!(search("holiday", Some(pubkey())).is_empty());
        assert!(search("", Some(pubkey())).is_empty());
        db.delete_torrent(&built.parsed.infohash).unwrap();
        let after = db
            .search(&SearchQuery {
                text: "holiday".into(),
                limit: 10,
                ..Default::default()
            })
            .unwrap();
        assert!(after.is_empty());
    }
}
