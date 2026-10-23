//! The `/v1` HTTP API (spec §4.3).

use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, DefaultBodyLimit, FromRequestParts, Path, Query, Request, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use lemonwire_proto::api::*;
use lemonwire_proto::auth::{self, PROTOCOL};
use lemonwire_proto::keys::{self, KeyPair, PublicKey};
use lemonwire_proto::metainfo::{self, TorrentError};
use serde::Deserialize;

use crate::db::{Db, DbError, SearchQuery, User};
use crate::net::{RateLimiter, client_ip};
use crate::tracker::Swarms;

pub struct AppState {
    db: Mutex<Db>,
    pub server: KeyPair,
    pub server_pub: String,
    pub name: String,
    pub tracker_url: String,
    pub trust_proxy: bool,
    /// Most entries one member may have in the index (0 = no limit).
    pub max_shares_per_member: u64,
    /// Public IP of the index's LAN, for advertising LAN peers (see `net::advertised`).
    pub nat_public: std::sync::RwLock<Option<std::net::IpAddr>>,
    pub auth_limiter: RateLimiter,
    pub swarms: Swarms,
}

pub type Shared = Arc<AppState>;

impl AppState {
    pub fn new(db: Db, trust_proxy: bool, max_shares_per_member: u64) -> Result<Self, DbError> {
        let server = db.server_keypair()?;
        let name = db.meta("name")?.unwrap_or_default();
        let tracker_url = db.meta("tracker_url")?.unwrap_or_default();
        Ok(Self {
            server_pub: server.public().to_b64(),
            server,
            name,
            tracker_url,
            trust_proxy,
            max_shares_per_member,
            nat_public: std::sync::RwLock::new(None),
            auth_limiter: RateLimiter::new(30, Duration::from_secs(60)),
            swarms: Swarms::default(),
            db: Mutex::new(db),
        })
    }

    pub fn db(&self) -> MutexGuard<'_, Db> {
        // A panic while holding the lock leaves SQLite consistent (transactions roll
        // back on drop), so recovering from poisoning is safe.
        self.db.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn announce_url(&self, passkey: &str) -> String {
        format!("{}/announce?passkey={passkey}", self.tracker_url)
    }
}

// ---- errors ------------------------------------------------------------------

#[derive(Debug)]
pub enum ApiError {
    BadRequest(String),
    Unauthorized,
    Forbidden(&'static str),
    NotFound(String),
    Conflict(String),
    TooManyRequests,
    Internal,
}

impl From<DbError> for ApiError {
    fn from(e: DbError) -> Self {
        match e {
            DbError::Conflict(m) => ApiError::Conflict(m),
            DbError::NotFound(m) => ApiError::NotFound(m),
            DbError::Invalid(m) => ApiError::BadRequest(m),
            DbError::Sqlite(e) => {
                tracing::error!(error = %e, "database error");
                ApiError::Internal
            }
            DbError::Io(path, e) => {
                tracing::error!(%path, error = %e, "storage error");
                ApiError::Internal
            }
        }
    }
}

impl From<TorrentError> for ApiError {
    fn from(e: TorrentError) -> Self {
        ApiError::BadRequest(e.to_string())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, msg) = match self {
            ApiError::BadRequest(m) => (StatusCode::BAD_REQUEST, m),
            // One body for every auth failure, so responses don't reveal membership.
            ApiError::Unauthorized => (StatusCode::UNAUTHORIZED, "authentication failed".into()),
            ApiError::Forbidden(m) => (StatusCode::FORBIDDEN, m.into()),
            ApiError::NotFound(m) => (StatusCode::NOT_FOUND, m),
            ApiError::Conflict(m) => (StatusCode::CONFLICT, m),
            ApiError::TooManyRequests => {
                (StatusCode::TOO_MANY_REQUESTS, "too many requests".into())
            }
            ApiError::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "internal error".into()),
        };
        (status, Json(ErrorBody { error: msg })).into_response()
    }
}

type ApiResult<T> = Result<T, ApiError>;

// ---- extractors --------------------------------------------------------------

/// A logged-in member, from `Authorization: Bearer <token>`.
pub struct Authed(pub User);

impl FromRequestParts<Shared> for Authed {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &Shared) -> ApiResult<Self> {
        let token = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or(ApiError::Unauthorized)?;
        let user = state.db().session_user(token.trim())?;
        user.map(Authed).ok_or(ApiError::Unauthorized)
    }
}

/// A logged-in admin.
pub struct Admin(pub User);

impl FromRequestParts<Shared> for Admin {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &Shared) -> ApiResult<Self> {
        let Authed(user) = Authed::from_request_parts(parts, state).await?;
        if !user.is_admin {
            return Err(ApiError::Forbidden("admin only"));
        }
        Ok(Admin(user))
    }
}

fn rate_limit(state: &AppState, peer: SocketAddr, headers: &HeaderMap) -> ApiResult<()> {
    if state
        .auth_limiter
        .check(client_ip(peer, headers, state.trust_proxy))
    {
        Ok(())
    } else {
        Err(ApiError::TooManyRequests)
    }
}

// ---- router ------------------------------------------------------------------

pub fn router(state: Shared) -> Router {
    let v1 = Router::new()
        .route("/info", get(info))
        .route("/join", post(join))
        .route("/auth/challenge", post(challenge))
        .route("/auth/login", post(login))
        .route("/me", get(me))
        .route("/search", get(search))
        .route("/torrents", post(publish))
        .route("/torrents/{infohash}", get(fetch).delete(unpublish))
        .route("/admin/members", get(members_list).post(members_add))
        .route("/admin/members/{selector}", delete(members_revoke))
        .route(
            "/admin/members/{selector}/rotate-passkey",
            post(members_rotate_passkey),
        )
        .route("/admin/invites", get(invites_list).post(invites_create));
    Router::new()
        .nest(API_PREFIX, v1)
        .fallback(|| async { ApiError::NotFound("not found".into()) })
        .layer(DefaultBodyLimit::max(limits::MAX_BODY_BYTES))
        .layer(middleware::from_fn(log_request))
        .with_state(state)
}

/// Logs method, path and status only. Never the query string or headers, which can
/// hold tokens and passkeys.
pub async fn log_request(req: Request, next: Next) -> Response {
    let method = req.method().clone();
    let path = req.uri().path().to_owned();
    let start = Instant::now();
    let res = next.run(req).await;
    tracing::info!(
        %method,
        path,
        status = res.status().as_u16(),
        ms = start.elapsed().as_millis() as u64,
        "request"
    );
    res
}

// ---- public ------------------------------------------------------------------

async fn info(State(s): State<Shared>) -> Json<InfoResponse> {
    Json(InfoResponse {
        protocol: PROTOCOL.into(),
        name: s.name.clone(),
        server_pubkey: s.server_pub.clone(),
    })
}

async fn join(
    State(s): State<Shared>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<JoinRequest>,
) -> ApiResult<(StatusCode, Json<Member>)> {
    rate_limit(&s, peer, &headers)?;
    let user = s
        .db()
        .redeem_invite(&req.invite, &req.pubkey, req.name.trim())?;
    tracing::info!(name = %user.name, "member joined with an invite");
    Ok((StatusCode::CREATED, Json(user.member())))
}

async fn challenge(
    State(s): State<Shared>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<ChallengeRequest>,
) -> ApiResult<Json<ChallengeResponse>> {
    rate_limit(&s, peer, &headers)?;
    // Issue a challenge for any well-formed key, member or not, so this endpoint
    // doesn't reveal who is a member.
    let key = PublicKey::from_b64(&req.pubkey)
        .map_err(|_| ApiError::BadRequest("invalid public key".into()))?;
    let client_pub = key.to_b64();
    let nonce = s.db().create_challenge(&client_pub)?;
    let server_sig = auth::sign_challenge(&s.server, &client_pub, &nonce);
    Ok(Json(ChallengeResponse { nonce, server_sig }))
}

async fn login(
    State(s): State<Shared>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<LoginRequest>,
) -> ApiResult<Json<LoginResponse>> {
    rate_limit(&s, peer, &headers)?;
    let key = PublicKey::from_b64(&req.pubkey).map_err(|_| ApiError::Unauthorized)?;
    let client_pub = key.to_b64();
    let db = s.db();
    // Consume the nonce first, so it's single-use even if the rest fails.
    let issued_to = db.take_challenge(&req.nonce)?;
    let user = db.user(&client_pub)?;
    let sig_ok = auth::verify_login(&s.server_pub, &key, &req.nonce, &req.signature).is_ok();
    match (issued_to, user) {
        (Some(bound), Some(user)) if bound == client_pub && sig_ok => {
            let (token, expires_at) = db.create_session(&user.pubkey)?;
            tracing::info!(name = %user.name, "login");
            Ok(Json(LoginResponse {
                token,
                expires_at,
                announce_url: s.announce_url(&db.passkey(&user)?),
            }))
        }
        _ => Err(ApiError::Unauthorized),
    }
}

// ---- members -----------------------------------------------------------------

async fn me(Authed(user): Authed) -> Json<Member> {
    Json(user.member())
}

#[derive(Deserialize)]
struct SearchParams {
    q: Option<String>,
    limit: Option<u32>,
    offset: Option<u32>,
    /// Only the caller's own uploads.
    #[serde(default)]
    mine: bool,
}

async fn search(
    State(s): State<Shared>,
    Authed(user): Authed,
    Query(p): Query<SearchParams>,
) -> ApiResult<Json<SearchResponse>> {
    let limit = p
        .limit
        .unwrap_or(DEFAULT_SEARCH_LIMIT)
        .clamp(1, MAX_SEARCH_LIMIT);
    let offset = p.offset.unwrap_or(0);
    if offset > MAX_SEARCH_OFFSET {
        return Err(ApiError::BadRequest(format!(
            "offset must be at most {MAX_SEARCH_OFFSET}"
        )));
    }
    // Ask for one extra row to know whether there's another page.
    let mut results = s.db().search(&SearchQuery {
        text: p.q.unwrap_or_default(),
        limit: limit + 1,
        offset,
        uploader: p.mine.then(|| user.pubkey.clone()),
    })?;
    let next_offset = (results.len() > limit as usize).then(|| {
        results.truncate(limit as usize);
        offset + limit
    });
    Ok(Json(SearchResponse {
        results,
        next_offset,
    }))
}

/// Lowercase, trim, dedupe; letters, digits, `-`, `_` and `.` only.
pub fn normalize_tags(tags: &[String]) -> ApiResult<Vec<String>> {
    let mut out: Vec<String> = Vec::new();
    for t in tags {
        let t = t.trim().to_lowercase();
        if t.is_empty() {
            continue;
        }
        let ok = t.chars().count() <= limits::MAX_TAG_LEN
            && t.chars().all(|c| c.is_alphanumeric() || "-_.".contains(c));
        if !ok {
            return Err(ApiError::BadRequest(format!(
                "invalid tag {t:?}: up to {} letters, digits, '-', '_' or '.'",
                limits::MAX_TAG_LEN
            )));
        }
        if !out.contains(&t) {
            out.push(t);
        }
    }
    if out.len() > limits::MAX_TAGS {
        return Err(ApiError::BadRequest(format!(
            "at most {} tags",
            limits::MAX_TAGS
        )));
    }
    Ok(out)
}

async fn publish(
    State(s): State<Shared>,
    Authed(user): Authed,
    Json(req): Json<PublishRequest>,
) -> ApiResult<(StatusCode, Json<TorrentEntry>)> {
    let tags = normalize_tags(&req.tags)?;
    let bytes = keys::b64_decode(&req.torrent_b64)
        .map_err(|_| ApiError::BadRequest("torrent_b64 is not valid base64".into()))?;
    // Derive everything from the torrent itself; never trust client metadata.
    let parsed = metainfo::parse_private(&bytes)?;
    let stripped = metainfo::strip(&bytes)?;
    let mut db = s.db();
    if s.max_shares_per_member > 0 && db.torrents_by(&user.pubkey)? >= s.max_shares_per_member {
        return Err(ApiError::Forbidden(
            "you've reached this index's limit on shares; unpublish something first",
        ));
    }
    let entry = db.insert_torrent(&parsed, &stripped, &tags, &user)?;
    drop(db);
    tracing::info!(infohash = %entry.infohash, uploader = %user.name, "published");
    Ok((StatusCode::CREATED, Json(entry)))
}

fn check_infohash(h: &str) -> ApiResult<String> {
    let h = h.to_ascii_lowercase();
    if h.len() == 40 && h.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(h)
    } else {
        Err(ApiError::BadRequest(
            "infohash must be 40 hex characters".into(),
        ))
    }
}

async fn fetch(
    State(s): State<Shared>,
    Authed(user): Authed,
    Path(infohash): Path<String>,
) -> ApiResult<Json<FetchResponse>> {
    let infohash = check_infohash(&infohash)?;
    let (entry, blob, _) = s
        .db()
        .torrent(&infohash)?
        .ok_or_else(|| ApiError::NotFound("no such torrent".into()))?;
    let passkey = s.db().passkey(&user)?;
    let torrent = metainfo::with_announce(&blob, &s.announce_url(&passkey))?;
    Ok(Json(FetchResponse {
        entry,
        torrent_b64: keys::b64_encode(&torrent),
    }))
}

async fn unpublish(
    State(s): State<Shared>,
    Authed(user): Authed,
    Path(infohash): Path<String>,
) -> ApiResult<StatusCode> {
    let infohash = check_infohash(&infohash)?;
    let mut db = s.db();
    let (_, _, uploader) = db
        .torrent(&infohash)?
        .ok_or_else(|| ApiError::NotFound("no such torrent".into()))?;
    if uploader != user.pubkey && !user.is_admin {
        return Err(ApiError::Forbidden(
            "only the uploader or an admin can remove this",
        ));
    }
    db.delete_torrent(&infohash)?;
    drop(db);
    s.swarms.remove_torrent(&infohash);
    tracing::info!(%infohash, by = %user.name, "unpublished");
    Ok(StatusCode::NO_CONTENT)
}

// ---- admin -------------------------------------------------------------------

async fn members_list(State(s): State<Shared>, _: Admin) -> ApiResult<Json<MembersResponse>> {
    let members = s.db().members()?.iter().map(User::member).collect();
    Ok(Json(MembersResponse { members }))
}

async fn members_add(
    State(s): State<Shared>,
    Admin(admin): Admin,
    Json(req): Json<AddMemberRequest>,
) -> ApiResult<(StatusCode, Json<Member>)> {
    let user = s
        .db()
        .add_member(&req.pubkey, req.name.trim(), req.is_admin)?;
    tracing::info!(name = %user.name, by = %admin.name, "member added");
    Ok((StatusCode::CREATED, Json(user.member())))
}

async fn members_revoke(
    State(s): State<Shared>,
    Admin(admin): Admin,
    Path(selector): Path<String>,
) -> ApiResult<StatusCode> {
    let mut db = s.db();
    let user = db.resolve_member(&selector)?;
    db.revoke(&user.pubkey)?;
    drop(db);
    s.swarms.remove_user(&user.pubkey);
    tracing::info!(name = %user.name, by = %admin.name, "member revoked");
    Ok(StatusCode::NO_CONTENT)
}

async fn members_rotate_passkey(
    State(s): State<Shared>,
    Admin(_): Admin,
    Path(selector): Path<String>,
) -> ApiResult<StatusCode> {
    let db = s.db();
    let user = db.resolve_member(&selector)?;
    db.rotate_passkey(&user.pubkey)?;
    drop(db);
    s.swarms.remove_user(&user.pubkey);
    Ok(StatusCode::NO_CONTENT)
}

async fn invites_list(State(s): State<Shared>, _: Admin) -> ApiResult<Json<InvitesResponse>> {
    Ok(Json(InvitesResponse {
        invites: s.db().invites()?,
    }))
}

async fn invites_create(
    State(s): State<Shared>,
    Admin(admin): Admin,
    Json(req): Json<CreateInviteRequest>,
) -> ApiResult<(StatusCode, Json<Invite>)> {
    let invite = s
        .db()
        .create_invite(req.is_admin, req.ttl_hours.unwrap_or(24))?;
    tracing::info!(by = %admin.name, is_admin = invite.is_admin, "invite created");
    Ok((StatusCode::CREATED, Json(invite)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tags_are_normalised() {
        let t = normalize_tags(&[" Photos ".into(), "photos".into(), "".into(), "2026".into()])
            .unwrap();
        assert_eq!(t, ["photos", "2026"]);
        assert!(normalize_tags(&["no spaces".into()]).is_err());
        assert!(normalize_tags(&["x".repeat(33)]).is_err());
        let many: Vec<String> = (0..17).map(|i| format!("t{i}")).collect();
        assert!(normalize_tags(&many).is_err());
    }

    #[test]
    fn infohash_validation() {
        assert!(check_infohash(&"A".repeat(40)).is_ok());
        assert!(check_infohash("abc").is_err());
        assert!(check_infohash(&"g".repeat(40)).is_err());
    }
}
