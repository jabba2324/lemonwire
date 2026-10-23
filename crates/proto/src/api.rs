//! JSON types for the `/v1` HTTP API (spec §4.3).

use serde::{Deserialize, Serialize};

pub const API_PREFIX: &str = "/v1";
pub const MAX_SEARCH_LIMIT: u32 = 100;
pub const DEFAULT_SEARCH_LIMIT: u32 = 25;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InfoResponse {
    pub protocol: String,
    pub name: String,
    pub server_pubkey: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JoinRequest {
    pub invite: String,
    pub pubkey: String,
    /// Your member name on this index.
    #[serde(alias = "display_name")]
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeRequest {
    pub pubkey: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeResponse {
    pub nonce: String,
    pub server_sig: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginRequest {
    pub pubkey: String,
    pub nonce: String,
    pub signature: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct LoginResponse {
    pub token: String,
    /// Unix seconds.
    pub expires_at: i64,
    /// This member's personal announce URL (contains their passkey).
    pub announce_url: String,
}

impl std::fmt::Debug for LoginResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoginResponse")
            .field("token", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .field("announce_url", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileEntry {
    pub path: String,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TorrentEntry {
    pub infohash: String,
    pub name: String,
    pub size: u64,
    pub files: Vec<FileEntry>,
    pub tags: Vec<String>,
    /// Uploader's display name.
    pub uploader: String,
    /// Unix seconds.
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResponse {
    pub results: Vec<TorrentEntry>,
    /// Pass as `offset` to get the next page; absent on the last page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_offset: Option<u32>,
}

/// Search offsets beyond this are refused (deep paging is never needed here).
pub const MAX_SEARCH_OFFSET: u32 = 10_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishRequest {
    #[serde(default)]
    pub tags: Vec<String>,
    pub torrent_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FetchResponse {
    pub entry: TorrentEntry,
    /// The stored torrent with the caller's announce URL injected.
    pub torrent_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Member {
    pub pubkey: String,
    pub name: String,
    pub is_admin: bool,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MembersResponse {
    pub members: Vec<Member>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddMemberRequest {
    pub pubkey: String,
    pub name: String,
    #[serde(default)]
    pub is_admin: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateInviteRequest {
    #[serde(default)]
    pub is_admin: bool,
    pub ttl_hours: Option<u32>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Invite {
    /// Short identifier (a prefix of the token's hash), for listing.
    pub id: String,
    /// `lw1.<token>.<server public key>`: what the new member pastes. Only returned
    /// when the invite is created; the server keeps just a hash of the token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    pub is_admin: bool,
    pub created_at: i64,
    pub expires_at: i64,
    /// Public key of the member who redeemed it, if any.
    pub used_by: Option<String>,
}

impl std::fmt::Debug for Invite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Invite")
            .field("id", &self.id)
            .field("code", &self.code.as_ref().map(|_| "<redacted>"))
            .field("is_admin", &self.is_admin)
            .field("expires_at", &self.expires_at)
            .field("used_by", &self.used_by)
            .finish()
    }
}

/// Split an invite code into (token, server public key). Bare tokens have no key.
pub fn parse_invite_code(code: &str) -> (&str, Option<&str>) {
    let code = code.trim();
    match code.split('.').collect::<Vec<_>>().as_slice() {
        ["lw1", token, key] => (token, Some(key)),
        _ => (code, None),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvitesResponse {
    pub invites: Vec<Invite>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorBody {
    pub error: String,
}

/// Limits shared by client and server (spec §6).
pub mod limits {
    pub const MAX_BODY_BYTES: usize = 16 * 1024 * 1024;
    pub const MAX_TORRENT_BYTES: usize = 10 * 1024 * 1024;
    pub const MAX_FILES: usize = 10_000;
    pub const MAX_TAGS: usize = 16;
    pub const MAX_TAG_LEN: usize = 32;
    pub const MAX_NAME_LEN: usize = 64;
    pub const MAX_PATH_COMPONENT_LEN: usize = 255;
}
