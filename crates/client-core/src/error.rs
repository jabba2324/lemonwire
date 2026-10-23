use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("no profile named {0:?}")]
    NoSuchProfile(String),
    #[error("no profiles yet: add one with `lemonwire profile add <name> <url>`")]
    NoProfiles,
    #[error("several profiles exist and none is the default; pick one with --profile")]
    AmbiguousProfile,
    #[error("a profile named {0:?} already exists")]
    ProfileExists(String),
    #[error("invalid profile name {0:?}: use letters, digits, '-' or '_'")]
    InvalidProfileName(String),
    #[error("invalid URL {0:?}: must start with http:// or https://")]
    InvalidUrl(String),
    #[error(
        "refusing plain http:// to {0}: tokens and passkeys would travel unencrypted. \
         Use https://, or --insecure if this host is on a network you trust"
    )]
    InsecureUrl(String),
    #[error("this key is protected with a passphrase (set LEMONWIRE_PASSPHRASE or enter it)")]
    PassphraseRequired,
    #[error("wrong passphrase")]
    WrongPassphrase,
    #[error(
        "server key mismatch: expected fingerprint {expected}, server presented {actual}. \
         Not connecting; check the key with the index admin"
    )]
    ServerKeyMismatch { expected: String, actual: String },
    #[error("this index rejected the login: the profile's key isn't a member (yet)")]
    NotAMember,
    #[error("server error ({status}): {message}")]
    Server { status: u16, message: String },
    #[error("can't reach the index: {0}")]
    Http(#[from] reqwest::Error),
    #[error("key error: {0}")]
    Key(#[from] lemonwire_proto::KeyError),
    #[error("key storage: {0}")]
    KeyStore(String),
    #[error("{0}")]
    Torrent(#[from] lemonwire_proto::metainfo::TorrentError),
    #[error("torrent engine: {0}")]
    Engine(String),
    #[error("this needs a torrent engine")]
    NoEngine,
    #[error(
        "another Lemon Wire (the app or another command) is transferring with this config; \
         use that, or wait for it to finish"
    )]
    EngineBusy,
    #[error("cancelled")]
    Cancelled,
    #[error("no transfer for {0}")]
    NoSuchTransfer(String),
    #[error("{} already exists; refusing to overwrite it", .0.display())]
    DestinationExists(PathBuf),
    #[error("{0}")]
    Invalid(String),
    #[error("{path}: {err}", path = .0.display(), err = .1)]
    Io(PathBuf, std::io::Error),
}

pub type Result<T> = std::result::Result<T, ClientError>;

impl ClientError {
    /// A stable, machine-readable kind, for front-ends to branch on.
    pub fn kind(&self) -> &'static str {
        match self {
            ClientError::NoSuchProfile(_) => "no_such_profile",
            ClientError::NoProfiles => "no_profiles",
            ClientError::AmbiguousProfile => "ambiguous_profile",
            ClientError::ProfileExists(_) => "profile_exists",
            ClientError::InvalidProfileName(_) => "invalid_profile_name",
            ClientError::InvalidUrl(_) => "invalid_url",
            ClientError::InsecureUrl(_) => "insecure_url",
            ClientError::PassphraseRequired => "passphrase_required",
            ClientError::WrongPassphrase => "wrong_passphrase",
            ClientError::ServerKeyMismatch { .. } => "server_key_mismatch",
            ClientError::NotAMember => "not_a_member",
            ClientError::Server { .. } => "server",
            ClientError::Http(_) => "network",
            ClientError::Key(_) => "key",
            ClientError::KeyStore(_) => "key_store",
            ClientError::Torrent(_) => "torrent",
            ClientError::Engine(_) => "engine",
            ClientError::NoEngine => "no_engine",
            ClientError::EngineBusy => "engine_busy",
            ClientError::Cancelled => "cancelled",
            ClientError::NoSuchTransfer(_) => "no_such_transfer",
            ClientError::DestinationExists(_) => "destination_exists",
            ClientError::Invalid(_) => "invalid",
            ClientError::Io(..) => "io",
        }
    }
}

/// Serialises as `{"kind": "...", "message": "..."}` so a GUI can show and branch on it.
impl serde::Serialize for ClientError {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut st = s.serialize_struct("ClientError", 2)?;
        st.serialize_field("kind", self.kind())?;
        st.serialize_field("message", &self.to_string())?;
        st.end()
    }
}
