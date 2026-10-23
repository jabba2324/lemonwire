//! HTTP client for one index's `/v1` API.

use lemonwire_proto::api::*;
use lemonwire_proto::auth;
use lemonwire_proto::keys::{KeyPair, PublicKey};
use reqwest::{Method, StatusCode};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::error::{ClientError, Result};

#[derive(Clone)]
pub struct ApiClient {
    http: reqwest::Client,
    base: String,
}

/// Normalise an index URL: must be http(s); trailing slashes removed. Plain http is
/// only allowed to local, private-network or Tailscale hosts unless `allow_insecure`.
pub fn normalize_url(url: &str, allow_insecure: bool) -> Result<String> {
    let u = url.trim().trim_end_matches('/');
    let parsed = reqwest::Url::parse(u).map_err(|_| ClientError::InvalidUrl(url.to_owned()))?;
    if parsed.host_str().is_none() {
        return Err(ClientError::InvalidUrl(url.to_owned()));
    }
    match parsed.scheme() {
        "https" => Ok(u.to_owned()),
        "http" => {
            check_plain_http(&parsed, allow_insecure)?;
            Ok(u.to_owned())
        }
        _ => Err(ClientError::InvalidUrl(url.to_owned())),
    }
}

/// Plain http is fine on this machine, a private network or Tailscale (which encrypts
/// everything itself); anywhere else it needs an explicit opt-in.
pub fn check_plain_http(url: &reqwest::Url, allow_insecure: bool) -> Result<()> {
    if url.scheme() != "http" || allow_insecure || is_trusted_network_host(url) {
        return Ok(());
    }
    Err(ClientError::InsecureUrl(
        url.host_str().unwrap_or_default().to_owned(),
    ))
}

fn is_trusted_network_host(url: &reqwest::Url) -> bool {
    use std::net::IpAddr;
    let private_ip = |ip: IpAddr| match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                // 100.64.0.0/10: carrier-grade NAT, used by Tailscale.
                || (o[0] == 100 && (o[1] & 0xc0) == 64)
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    };
    match url.host() {
        Some(url::Host::Ipv4(ip)) => private_ip(ip.into()),
        Some(url::Host::Ipv6(ip)) => private_ip(ip.into()),
        Some(url::Host::Domain(d)) => {
            let d = d.to_ascii_lowercase();
            d == "localhost"
                || d.ends_with(".localhost")
                || d.ends_with(".local")
                || d.ends_with(".ts.net")
        }
        None => false,
    }
}

impl ApiClient {
    /// `base` comes from a saved profile, whose URL was checked when it was added.
    pub fn new(http: reqwest::Client, base: &str) -> Result<Self> {
        Ok(Self {
            http,
            base: normalize_url(base, true)?,
        })
    }

    async fn call<B: Serialize, T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        token: Option<&str>,
        body: Option<&B>,
        query: &[(&str, String)],
    ) -> Result<T> {
        let mut req = self
            .http
            .request(method, format!("{}{API_PREFIX}{path}", self.base));
        if let Some(t) = token {
            req = req.bearer_auth(t);
        }
        if let Some(b) = body {
            req = req.json(b);
        }
        if !query.is_empty() {
            req = req.query(query);
        }
        let res = req.send().await?;
        let status = res.status();
        if status.is_success() {
            if status == StatusCode::NO_CONTENT {
                return serde_json::from_value(serde_json::Value::Null)
                    .map_err(|e| ClientError::Invalid(e.to_string()));
            }
            return Ok(res.json().await?);
        }
        let message = res
            .json::<ErrorBody>()
            .await
            .map(|b| b.error)
            .unwrap_or_else(|_| status.to_string());
        Err(ClientError::Server {
            status: status.as_u16(),
            message,
        })
    }

    async fn get<T: DeserializeOwned>(&self, path: &str, token: Option<&str>) -> Result<T> {
        self.call::<(), T>(Method::GET, path, token, None, &[])
            .await
    }

    async fn post<B: Serialize, T: DeserializeOwned>(
        &self,
        path: &str,
        token: Option<&str>,
        body: &B,
    ) -> Result<T> {
        self.call(Method::POST, path, token, Some(body), &[]).await
    }

    pub async fn info(&self) -> Result<InfoResponse> {
        self.get("/info", None).await
    }

    pub async fn join(&self, invite: &str, key: &KeyPair, name: &str) -> Result<Member> {
        self.post(
            "/join",
            None,
            &JoinRequest {
                invite: invite.to_owned(),
                pubkey: key.public().to_b64(),
                name: name.to_owned(),
            },
        )
        .await
    }

    /// Mutual-auth login (spec §3). The server's challenge signature must verify
    /// against `pinned`, or we stop before signing anything.
    pub async fn login(&self, key: &KeyPair, pinned: &PublicKey) -> Result<LoginResponse> {
        let client_pub = key.public().to_b64();
        let ch: ChallengeResponse = self
            .post(
                "/auth/challenge",
                None,
                &ChallengeRequest {
                    pubkey: client_pub.clone(),
                },
            )
            .await?;
        if auth::verify_challenge(pinned, &client_pub, &ch.nonce, &ch.server_sig).is_err() {
            // Find out what the server claims to be, for a useful message.
            let actual = self
                .info()
                .await
                .map(|i| lemonwire_proto::keys::fingerprint(&i.server_pubkey))
                .unwrap_or_else(|_| "unknown".into());
            return Err(ClientError::ServerKeyMismatch {
                expected: pinned.fingerprint(),
                actual,
            });
        }
        let signature = auth::sign_login(key, &pinned.to_b64(), &ch.nonce);
        let res = self
            .post(
                "/auth/login",
                None,
                &LoginRequest {
                    pubkey: client_pub,
                    nonce: ch.nonce,
                    signature,
                },
            )
            .await;
        match res {
            Err(ClientError::Server { status: 401, .. }) => Err(ClientError::NotAMember),
            other => other,
        }
    }

    /// Swarm counts from the tracker's scrape endpoint, using this member's announce
    /// URL (which carries their passkey).
    pub async fn scrape(&self, announce_url: &str, infohash: &str) -> Result<(u64, u64, u64)> {
        let raw = (0..infohash.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&infohash[i..i + 2], 16))
            .collect::<std::result::Result<Vec<u8>, _>>()
            .map_err(|_| ClientError::Invalid("bad infohash".into()))?;
        let encoded: String = raw.iter().map(|b| format!("%{b:02X}")).collect();
        let Some((base, query)) = announce_url.split_once('?') else {
            return Err(ClientError::Invalid("announce URL has no passkey".into()));
        };
        let Some(base) = base.strip_suffix("/announce") else {
            return Err(ClientError::Invalid(
                "announce URL doesn't end in /announce".into(),
            ));
        };
        let url = format!("{base}/scrape?{query}&info_hash={encoded}");
        // The URL holds our passkey: keep it out of any error message.
        let body = self
            .http
            .get(url)
            .send()
            .await
            .map_err(|e| ClientError::Http(e.without_url()))?
            .bytes()
            .await
            .map_err(|e| ClientError::Http(e.without_url()))?;
        let v = lemonwire_proto::bencode::decode(&body)
            .map_err(|e| ClientError::Invalid(format!("bad scrape reply: {e}")))?;
        use lemonwire_proto::bencode::Value;
        if let Some(reason) = v.get("failure reason").and_then(Value::as_str) {
            return Err(ClientError::Invalid(format!("tracker: {reason}")));
        }
        let stats = v
            .get("files")
            .and_then(Value::as_dict)
            .and_then(|f| f.get(raw.as_slice()));
        let n = |k: &str| {
            stats
                .and_then(|s| s.get(k))
                .and_then(Value::as_int)
                .unwrap_or(0)
                .max(0) as u64
        };
        Ok((n("complete"), n("incomplete"), n("complete_members")))
    }

    pub async fn search(
        &self,
        token: &str,
        q: &str,
        limit: Option<u32>,
        offset: Option<u32>,
        mine: bool,
    ) -> Result<SearchResponse> {
        let mut query = vec![("q", q.to_owned())];
        if let Some(l) = limit {
            query.push(("limit", l.to_string()));
        }
        if let Some(o) = offset {
            query.push(("offset", o.to_string()));
        }
        if mine {
            query.push(("mine", "true".into()));
        }
        self.call::<(), _>(Method::GET, "/search", Some(token), None, &query)
            .await
    }

    pub async fn me(&self, token: &str) -> Result<Member> {
        self.get("/me", Some(token)).await
    }

    pub async fn publish(&self, token: &str, req: &PublishRequest) -> Result<TorrentEntry> {
        self.post("/torrents", Some(token), req).await
    }

    pub async fn fetch(&self, token: &str, infohash: &str) -> Result<FetchResponse> {
        self.get(&format!("/torrents/{infohash}"), Some(token))
            .await
    }

    pub async fn unpublish(&self, token: &str, infohash: &str) -> Result<()> {
        self.call::<(), ()>(
            Method::DELETE,
            &format!("/torrents/{infohash}"),
            Some(token),
            None,
            &[],
        )
        .await
    }

    pub async fn members(&self, token: &str) -> Result<MembersResponse> {
        self.get("/admin/members", Some(token)).await
    }

    pub async fn add_member(&self, token: &str, req: &AddMemberRequest) -> Result<Member> {
        self.post("/admin/members", Some(token), req).await
    }

    pub async fn revoke_member(&self, token: &str, selector: &str) -> Result<()> {
        let sel: String = selector
            .bytes()
            .map(|b| {
                if b.is_ascii_alphanumeric() || b"-_".contains(&b) {
                    (b as char).to_string()
                } else {
                    format!("%{b:02X}")
                }
            })
            .collect();
        self.call::<(), ()>(
            Method::DELETE,
            &format!("/admin/members/{sel}"),
            Some(token),
            None,
            &[],
        )
        .await
    }

    pub async fn create_invite(&self, token: &str, req: &CreateInviteRequest) -> Result<Invite> {
        self.post("/admin/invites", Some(token), req).await
    }

    pub async fn invites(&self, token: &str) -> Result<InvitesResponse> {
        self.get("/admin/invites", Some(token)).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_http_rules() {
        for ok in [
            "https://index.example",
            "http://localhost:8080",
            "http://127.0.0.1",
            "http://192.168.1.10",
            "http://10.0.0.2",
            "http://100.101.102.103",
            "http://[::1]:8080",
            "http://[fd7a:115c:a1e0::1]",
            "http://nas.local",
            "http://index.tail1234.ts.net",
        ] {
            assert!(normalize_url(ok, false).is_ok(), "{ok}");
        }
        for bad in [
            "http://index.example",
            "http://8.8.8.8",
            "http://100.200.0.1",
        ] {
            assert!(
                matches!(normalize_url(bad, false), Err(ClientError::InsecureUrl(_))),
                "{bad}"
            );
            assert!(normalize_url(bad, true).is_ok());
        }
        assert!(matches!(
            normalize_url("ftp://x", false),
            Err(ClientError::InvalidUrl(_))
        ));
        assert_eq!(
            normalize_url("https://index.example/", false).unwrap(),
            "https://index.example"
        );
    }
}
