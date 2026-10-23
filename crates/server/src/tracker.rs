//! A minimal HTTP tracker that only serves members (spec §4.4).
//!
//! Every announce must carry a current member's `passkey`, and only infohashes in the
//! index are tracked. Peers live in memory and expire if they stop announcing.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum::Router;
use axum::extract::{ConnectInfo, RawQuery, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use lemonwire_proto::bencode::Value;
use percent_encoding::percent_decode;

use crate::api::{Shared, log_request};
use crate::net::{advertised, client_ip};

// Clients are mostly one-shot (they run while a command runs), so keep peer lists
// fresh: short intervals, and forget peers that stop announcing after a few minutes.
pub const ANNOUNCE_INTERVAL: Duration = Duration::from_secs(120);
pub const MIN_INTERVAL: Duration = Duration::from_secs(30);
pub const PEER_EXPIRY: Duration = Duration::from_secs(5 * 60);
const DEFAULT_NUMWANT: usize = 50;
const MAX_NUMWANT: usize = 200;
const MAX_PEERS_PER_TORRENT: usize = 5000;

type Hash20 = [u8; 20];

#[derive(Debug, Clone)]
struct Peer {
    addr: SocketAddr,
    left: u64,
    /// Downloading only some files (`lw_partial=1`): `left == 0` then means "done with
    /// my selection", not a full copy, so it never counts as a seeder.
    partial: bool,
    seen: Instant,
    pubkey: String,
}

impl Peer {
    fn is_seeder(&self) -> bool {
        self.left == 0 && !self.partial
    }
}

/// Infohash (hex) → peer id → peer.
#[derive(Default)]
pub struct Swarms {
    inner: Mutex<HashMap<String, HashMap<Hash20, Peer>>>,
}

impl Swarms {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, HashMap<Hash20, Peer>>> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn remove_torrent(&self, infohash: &str) {
        self.lock().remove(infohash);
    }

    /// Forget every peer announced by this member (after revoke or passkey rotation).
    pub fn remove_user(&self, pubkey: &str) {
        for swarm in self.lock().values_mut() {
            swarm.retain(|_, p| p.pubkey != pubkey);
        }
    }

    /// Drop expired peers, peers of members who no longer exist, and empty swarms.
    pub fn purge(&self, members: &HashSet<String>) {
        let now = Instant::now();
        let mut all = self.lock();
        for swarm in all.values_mut() {
            swarm.retain(|_, p| {
                now.duration_since(p.seen) < PEER_EXPIRY && members.contains(&p.pubkey)
            });
        }
        all.retain(|_, s| !s.is_empty());
    }

    /// (seeders, leechers, distinct members holding a complete copy), live peers only.
    pub fn peer_count(&self, infohash: &str) -> (usize, usize, usize) {
        let now = Instant::now();
        self.lock()
            .get(infohash)
            .map(|s| {
                let live: Vec<_> = s
                    .values()
                    .filter(|p| now.duration_since(p.seen) < PEER_EXPIRY)
                    .collect();
                let seeds: Vec<_> = live.iter().filter(|p| p.is_seeder()).collect();
                let leechers = live.iter().filter(|p| p.left > 0).count();
                let members: HashSet<&str> = seeds.iter().map(|p| p.pubkey.as_str()).collect();
                (seeds.len(), leechers, members.len())
            })
            .unwrap_or((0, 0, 0))
    }
}

pub fn router(state: Shared) -> Router {
    Router::new()
        .route("/announce", get(announce))
        .route("/scrape", get(scrape))
        .layer(axum::middleware::from_fn(log_request))
        .with_state(state)
}

/// Parse a raw query string into decoded (key, value bytes) pairs. `info_hash` and
/// `peer_id` are binary, so values can't be treated as UTF-8.
fn parse_query(q: &str) -> Vec<(String, Vec<u8>)> {
    q.split('&')
        .filter(|p| !p.is_empty())
        .map(|pair| {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            (
                percent_decode(k.as_bytes())
                    .decode_utf8_lossy()
                    .into_owned(),
                percent_decode(v.as_bytes()).collect(),
            )
        })
        .collect()
}

fn first<'a>(params: &'a [(String, Vec<u8>)], key: &str) -> Option<&'a [u8]> {
    params
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_slice())
}

fn num<T: std::str::FromStr>(params: &[(String, Vec<u8>)], key: &str) -> Option<T> {
    first(params, key)
        .and_then(|v| std::str::from_utf8(v).ok())
        .and_then(|s| s.parse().ok())
}

fn bencoded(v: Value) -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain")],
        v.encode(),
    )
        .into_response()
}

/// Trackers report errors as a 200 with a `failure reason`.
fn failure(reason: &str) -> Response {
    let mut d = std::collections::BTreeMap::new();
    d.insert(b"failure reason".to_vec(), Value::from(reason));
    bencoded(Value::Dict(d))
}

/// Check the passkey; returns the member's public key, or a failure reason.
fn authorise(state: &Shared, params: &[(String, Vec<u8>)]) -> Result<String, &'static str> {
    let passkey = first(params, "passkey")
        .and_then(|v| std::str::from_utf8(v).ok())
        .ok_or("missing passkey")?;
    match state.db().user_by_passkey(passkey) {
        Ok(Some(u)) => Ok(u.pubkey),
        Ok(None) => Err("invalid passkey"),
        Err(e) => {
            tracing::error!(error = %e, "tracker database error");
            Err("internal error")
        }
    }
}

fn registered(state: &Shared, infohash: &str) -> bool {
    state.db().torrent_exists(infohash).unwrap_or(false)
}

async fn announce(
    State(s): State<Shared>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    RawQuery(q): RawQuery,
) -> Response {
    let params = parse_query(q.as_deref().unwrap_or(""));
    let pubkey = match authorise(&s, &params) {
        Ok(pk) => pk,
        Err(reason) => return failure(reason),
    };
    let Some(info_hash) = first(&params, "info_hash").and_then(|v| Hash20::try_from(v).ok()) else {
        return failure("bad info_hash");
    };
    let infohash = hex::encode(info_hash);
    let Some(peer_id) = first(&params, "peer_id").and_then(|v| Hash20::try_from(v).ok()) else {
        return failure("bad peer_id");
    };
    let Some(port) = num::<u16>(&params, "port").filter(|&p| p != 0) else {
        return failure("bad port");
    };
    if !registered(&s, &infohash) {
        return failure("unregistered torrent");
    }
    let left = num::<u64>(&params, "left").unwrap_or(0);
    let partial = first(&params, "lw_partial") == Some(b"1");
    let event = first(&params, "event").unwrap_or(b"");
    let numwant = num::<usize>(&params, "numwant")
        .unwrap_or(DEFAULT_NUMWANT)
        .min(MAX_NUMWANT);
    let ip = client_ip(remote, &headers, s.trust_proxy);

    let nat_public = *s.nat_public.read().unwrap_or_else(|e| e.into_inner());
    let mut all = s.swarms.lock();
    let swarm = all.entry(infohash.clone()).or_default();
    if event == b"stopped" {
        swarm.remove(&peer_id);
    } else if swarm.len() < MAX_PEERS_PER_TORRENT || swarm.contains_key(&peer_id) {
        swarm.insert(
            peer_id,
            Peer {
                addr: SocketAddr::new(ip, port),
                left,
                partial,
                seen: Instant::now(),
                pubkey,
            },
        );
    }

    let now = Instant::now();
    let (mut peers4, mut peers6) = (Vec::new(), Vec::new());
    let (mut complete, mut incomplete) = (0i64, 0i64);
    for (id, p) in swarm.iter() {
        if now.duration_since(p.seen) >= PEER_EXPIRY {
            continue;
        }
        if p.is_seeder() {
            complete += 1;
        } else if p.left > 0 {
            incomplete += 1;
        }
        // Don't return the caller, and a peer that needs nothing gets no seeders.
        if *id == peer_id || event == b"stopped" || (left == 0 && p.is_seeder()) {
            continue;
        }
        if peers4.len() / 6 + peers6.len() / 18 >= numwant {
            continue;
        }
        let addr = advertised(p.addr, ip, nat_public);
        match addr.ip() {
            IpAddr::V4(v4) => {
                peers4.extend_from_slice(&v4.octets());
                peers4.extend_from_slice(&addr.port().to_be_bytes());
            }
            IpAddr::V6(v6) => {
                peers6.extend_from_slice(&v6.octets());
                peers6.extend_from_slice(&addr.port().to_be_bytes());
            }
        }
    }
    if swarm.is_empty() {
        all.remove(&infohash);
    }
    drop(all);

    let mut d = std::collections::BTreeMap::new();
    d.insert(
        b"interval".to_vec(),
        Value::Int(ANNOUNCE_INTERVAL.as_secs() as i64),
    );
    d.insert(
        b"min interval".to_vec(),
        Value::Int(MIN_INTERVAL.as_secs() as i64),
    );
    d.insert(b"complete".to_vec(), Value::Int(complete));
    d.insert(b"incomplete".to_vec(), Value::Int(incomplete));
    d.insert(b"peers".to_vec(), Value::Bytes(peers4));
    d.insert(b"peers6".to_vec(), Value::Bytes(peers6));
    bencoded(Value::Dict(d))
}

async fn scrape(State(s): State<Shared>, RawQuery(q): RawQuery) -> Response {
    let params = parse_query(q.as_deref().unwrap_or(""));
    if let Err(reason) = authorise(&s, &params) {
        return failure(reason);
    }
    let mut files = std::collections::BTreeMap::new();
    for (k, v) in params.iter().take(100) {
        let Ok(h) = Hash20::try_from(v.as_slice()) else {
            continue;
        };
        let infohash = hex::encode(h);
        if k != "info_hash" || !registered(&s, &infohash) {
            continue;
        }
        let (seeds, leechers, members) = s.swarms.peer_count(&infohash);
        let mut st = std::collections::BTreeMap::new();
        st.insert(b"complete".to_vec(), Value::Int(seeds as i64));
        // Lemon Wire extension: how many different members have a full copy.
        st.insert(b"complete_members".to_vec(), Value::Int(members as i64));
        st.insert(b"incomplete".to_vec(), Value::Int(leechers as i64));
        st.insert(b"downloaded".to_vec(), Value::Int(0));
        files.insert(h.to_vec(), Value::Dict(st));
    }
    let mut d = std::collections::BTreeMap::new();
    d.insert(b"files".to_vec(), Value::Dict(files));
    bencoded(Value::Dict(d))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_parsing_handles_binary() {
        let p = parse_query("info_hash=%00%FFab&port=6881&passkey=xyz&flag");
        assert_eq!(first(&p, "info_hash"), Some(&[0u8, 0xff, b'a', b'b'][..]));
        assert_eq!(num::<u16>(&p, "port"), Some(6881));
        assert_eq!(first(&p, "flag"), Some(&b""[..]));
        assert_eq!(first(&p, "missing"), None);
    }
}
