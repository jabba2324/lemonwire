//! The command architecture (spec §5.1): every action is a serialisable [`Command`],
//! executed by [`crate::Client::execute`], which returns a typed [`Output`] and reports
//! progress as [`Event`]s. Front-ends (the CLI, a GUI) only build commands, render
//! outputs and events, and cancel long-running commands.

use std::path::PathBuf;

use lemonwire_proto::api::{InfoResponse, Invite, Member, TorrentEntry};
use serde::{Deserialize, Serialize};

use crate::engine::TransferStatus;

/// How long `Share` keeps seeding after publishing.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum SeedUntil {
    /// Publish and return; serve it later with `Seed`.
    PublishOnly,
    /// Seed until this many *other* members hold a full copy.
    Copies { count: u64 },
    /// Seed until the command is cancelled (e.g. while a GUI stays open).
    Cancelled,
}

impl Default for SeedUntil {
    fn default() -> Self {
        SeedUntil::Copies { count: 1 }
    }
}

/// After a download completes, keep seeding until any of these is reached.
/// (It also stops early once nobody else is downloading.)
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub struct SeedBack {
    /// Upload this many times the downloaded size.
    pub ratio: f64,
    /// At most this long.
    pub max_secs: u64,
}

impl Default for SeedBack {
    fn default() -> Self {
        Self {
            ratio: 1.0,
            max_secs: 15 * 60,
        }
    }
}

fn default_seed_back() -> Option<SeedBack> {
    Some(SeedBack::default())
}

/// Why a seeding phase ended.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum StopReason {
    /// `SeedUntil::PublishOnly`, or no torrent engine available.
    NotSeeded,
    CopiesReached {
        copies: u64,
    },
    RatioReached,
    TimeLimit,
    NobodyDownloading,
    Cancelled,
}

/// `profile: None` means the default profile (or the only one).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Command {
    /// Create a key pair for a profile you haven't added yet, so you can send the public
    /// key to an admin first. `ProfileAdd` with the same name then uses it.
    KeysGenerate {
        profile: String,
    },
    ProfileList,
    /// Add an index. `profile` is your local label for it; `member_name` is your name
    /// on the index, used when joining with an invite (default: the profile name).
    ProfileAdd {
        profile: String,
        url: String,
        #[serde(default)]
        server_key: Option<String>,
        /// An invite code (`lw1.<token>.<index key>`) from an admin. Its index key is
        /// checked like `server_key`, so no trust on first use is needed.
        #[serde(default)]
        invite: Option<String>,
        #[serde(default)]
        member_name: Option<String>,
        /// Allow plain http:// to a public host.
        #[serde(default)]
        allow_insecure: bool,
    },
    /// Protect a profile's secret key with a passphrase (`None` removes it). The
    /// client's current passphrase opens an already-protected key.
    KeysProtect {
        profile: String,
        #[serde(default)]
        new_passphrase: Option<String>,
    },
    ProfileRemove {
        name: String,
    },
    ProfileSetDefault {
        name: String,
    },
    Info {
        #[serde(default)]
        profile: Option<String>,
    },
    /// Your membership on an index (name, admin flag).
    Whoami {
        #[serde(default)]
        profile: Option<String>,
    },
    Search {
        #[serde(default)]
        profile: Option<String>,
        #[serde(default)]
        query: String,
        #[serde(default)]
        limit: Option<u32>,
        #[serde(default)]
        offset: Option<u32>,
        /// Only your own shares.
        #[serde(default)]
        mine: bool,
    },
    /// One index entry, with its file list (indexes for `Download::files`).
    Details {
        #[serde(default)]
        profile: Option<String>,
        infohash: String,
    },
    /// Publish a file or folder, then seed according to `until`. Long-running.
    Share {
        #[serde(default)]
        profile: Option<String>,
        path: PathBuf,
        #[serde(default)]
        tags: Vec<String>,
        #[serde(default)]
        until: SeedUntil,
    },
    /// Download, then optionally seed back. Long-running; resumes a saved download.
    Download {
        #[serde(default)]
        profile: Option<String>,
        infohash: String,
        #[serde(default)]
        dest: Option<PathBuf>,
        /// Only these files (indexes into the entry's file list).
        #[serde(default)]
        files: Option<Vec<usize>>,
        #[serde(default = "default_seed_back")]
        seed_back: Option<SeedBack>,
    },
    /// Serve every saved transfer until cancelled, following changes to the list.
    Seed,
    Unpublish {
        #[serde(default)]
        profile: Option<String>,
        infohash: String,
    },
    /// Live swarm counts for a torrent, from the tracker.
    Swarm {
        #[serde(default)]
        profile: Option<String>,
        infohash: String,
    },
    /// Saved transfers, with live status for any this client is running.
    Transfers,
    Pause {
        infohash: String,
    },
    Resume {
        infohash: String,
    },
    /// Stop a transfer and forget it. `delete_data` only applies to downloads; a
    /// shared file's original is never deleted.
    Cancel {
        infohash: String,
        #[serde(default)]
        delete_data: bool,
    },
    /// Speed limits for the running engine, in KiB/s (`None` = unlimited).
    SetLimits {
        #[serde(default)]
        upload_kib: Option<u32>,
        #[serde(default)]
        download_kib: Option<u32>,
    },
    MembersList {
        #[serde(default)]
        profile: Option<String>,
    },
    MembersAdd {
        #[serde(default)]
        profile: Option<String>,
        pubkey: String,
        name: String,
        #[serde(default)]
        admin: bool,
    },
    MembersRevoke {
        #[serde(default)]
        profile: Option<String>,
        member: String,
    },
    InviteCreate {
        #[serde(default)]
        profile: Option<String>,
        #[serde(default)]
        admin: bool,
        #[serde(default)]
        ttl_hours: Option<u32>,
    },
    InviteList {
        #[serde(default)]
        profile: Option<String>,
    },
}

impl Command {
    /// Commands that need a torrent engine.
    pub fn needs_engine(&self) -> bool {
        match self {
            Command::Download { .. } | Command::Seed | Command::SetLimits { .. } => true,
            Command::Share { until, .. } => *until != SeedUntil::PublishOnly,
            _ => false,
        }
    }
}

/// A profile as shown to users. Never includes the secret key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProfileView {
    /// Your local label for this index.
    pub name: String,
    pub url: String,
    /// Your name on the index, once known.
    pub member_name: Option<String>,
    /// Your public key on this index (one key pair per profile).
    pub public_key: String,
    pub public_key_fingerprint: String,
    /// The index's public key, pinned when the profile was added.
    pub server_pubkey: String,
    pub server_fingerprint: String,
    pub default: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Output {
    PublicKey {
        profile: String,
        public_key: String,
    },
    Profiles {
        profiles: Vec<ProfileView>,
    },
    ProfileAdded {
        profile: ProfileView,
        /// The server key was pinned from `--server-key` rather than trust on first use.
        pinned_out_of_band: bool,
        joined_with_invite: bool,
        /// Logging in worked, so this key is already a member.
        member: bool,
    },
    Info {
        profile: ProfileView,
        server: InfoResponse,
        member: bool,
    },
    Me {
        profile: ProfileView,
        member: Member,
    },
    Results {
        profile: String,
        /// Offset of the first result (number results from `offset + 1`).
        offset: u32,
        results: Vec<TorrentEntry>,
        next_offset: Option<u32>,
    },
    Details {
        entry: TorrentEntry,
    },
    Shared {
        entry: TorrentEntry,
        already_indexed: bool,
        stopped: StopReason,
    },
    Downloaded {
        entry: TorrentEntry,
        dest: PathBuf,
        seed_back: Option<StopReason>,
    },
    /// `Seed` ended (it only ends when cancelled).
    Served {
        transfers: usize,
    },
    Swarm {
        infohash: String,
        seeders: u64,
        leechers: u64,
        /// Different members holding a complete copy (yourself included).
        complete_members: u64,
    },
    Transfers {
        transfers: Vec<TransferView>,
    },
    Members {
        members: Vec<Member>,
    },
    Member {
        member: Member,
    },
    Invite {
        invite: Invite,
    },
    Invites {
        invites: Vec<Invite>,
    },
    Done {
        message: String,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TransferKind {
    Seed,
    Download,
}

/// A transfer from the local state file, with live status if this client's engine is
/// running it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TransferView {
    pub infohash: String,
    pub name: String,
    pub profile: String,
    pub kind: TransferKind,
    pub path: PathBuf,
    pub paused: bool,
    pub files: Option<Vec<usize>>,
    pub status: Option<TransferStatus>,
}

/// Progress for front-ends (spec §5.1 `subscribe`). Long-running commands emit these
/// while they run.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    /// Building a torrent (after each piece).
    Hashing {
        path: PathBuf,
        done: u64,
        total: u64,
    },
    Published {
        infohash: String,
        name: String,
    },
    TransferAdded {
        infohash: String,
        name: String,
    },
    TransferRemoved {
        infohash: String,
    },
    /// Live status of a transfer a running command is watching, about once a second.
    Progress {
        status: TransferStatus,
    },
    /// `Share` waiting for copies.
    Waiting {
        infohash: String,
        copies: u64,
        wanted: u64,
        leechers: u64,
    },
    DownloadFinished {
        infohash: String,
        name: String,
    },
    /// `Download` seeding back after completion.
    SeedingBack {
        infohash: String,
        uploaded: u64,
        total: u64,
        peers: u32,
    },
    /// `Seed` summary, every few seconds.
    Serving {
        transfers: usize,
        downloading: usize,
        upload_bps: u64,
        download_bps: u64,
        peers: u32,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commands_are_json() {
        let c: Command =
            serde_json::from_str(r#"{"cmd":"search","query":"holiday","limit":5}"#).unwrap();
        assert_eq!(
            c,
            Command::Search {
                profile: None,
                query: "holiday".into(),
                limit: Some(5),
                offset: None,
                mine: false,
            }
        );
        let s = serde_json::to_string(&Command::Transfers).unwrap();
        assert_eq!(s, r#"{"cmd":"transfers"}"#);
        let back: Command = serde_json::from_str(&s).unwrap();
        assert_eq!(back, Command::Transfers);
    }

    #[test]
    fn long_running_defaults() {
        let c: Command = serde_json::from_str(r#"{"cmd":"download","infohash":"ab"}"#).unwrap();
        let Command::Download { seed_back, .. } = c else {
            panic!()
        };
        assert_eq!(seed_back, Some(SeedBack::default()));
        let c: Command = serde_json::from_str(r#"{"cmd":"share","path":"/x"}"#).unwrap();
        assert!(c.needs_engine());
        let c: Command =
            serde_json::from_str(r#"{"cmd":"share","path":"/x","until":{"mode":"publish_only"}}"#)
                .unwrap();
        assert!(!c.needs_engine());
    }
}
