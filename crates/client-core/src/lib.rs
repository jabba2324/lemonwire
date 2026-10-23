//! Lemon Wire client core, shared by every front-end (the `lemonwire` CLI and the GUI).
//!
//! Front-ends build [`Command`]s, run them with [`Client::execute_cancellable`], render
//! the [`Output`] and the [`Event`]s from [`Client::subscribe`], and cancel with a
//! [`CancellationToken`]. Everything else lives here: profiles, keys, the index API,
//! the torrent engine, and the transfer behaviour (how long to seed, resuming,
//! following the saved transfer list).

pub mod api;
pub mod client;
pub mod command;
pub mod config;
pub mod engine;
pub mod error;
pub mod keystore;
#[cfg(feature = "librqbit")]
pub mod rqbit;
mod transfers;

pub use client::{Client, ClientOptions, EngineSettings, OpenOptions};
pub use command::{
    Command, Event, Output, ProfileView, SeedBack, SeedUntil, StopReason, TransferKind,
    TransferView,
};
pub use config::ConfigDir;
pub use engine::{TorrentEngine, TransferId, TransferState, TransferStatus};
pub use error::{ClientError, Result};
pub use lemonwire_proto::api::{FileEntry, Invite, Member, TorrentEntry};
pub use tokio_util::sync::CancellationToken;

/// The most verbose level these log targets may use, so even trace logging never
/// records passkeys: librqbit logs tracker URLs (which carry the passkey) at debug
/// and trace, and the HTTP stack logs request URLs. Front-ends apply these as caps on
/// top of the user's filter (they never make a target more verbose).
pub const LOG_REDACT_CAPS: &[(&str, tracing::Level)] = &[
    ("librqbit_tracker_comms", tracing::Level::INFO),
    ("librqbit::session", tracing::Level::DEBUG),
    ("reqwest", tracing::Level::INFO),
    ("hyper", tracing::Level::INFO),
    ("hyper_util", tracing::Level::INFO),
    ("h2", tracing::Level::INFO),
];
