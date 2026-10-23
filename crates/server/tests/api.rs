//! Integration tests: a real server on ephemeral ports with a temp data dir.

use std::collections::BTreeMap;

use lemonwire_proto::api::*;
use lemonwire_proto::auth;
use lemonwire_proto::bencode::{self, Value};
use lemonwire_proto::keys::{self, KeyPair};
use lemonwire_proto::metainfo::{self, BuildOptions};
use lemonwire_server::db::InitParams;
use lemonwire_server::{Listeners, ServeOptions, open_data_dir, serve};
use reqwest::StatusCode;
use serde_json::json;

struct TestServer {
    api: String,
    tracker: String,
    server_pub: String,
    admin: KeyPair,
    http: reqwest::Client,
    _dir: tempfile::TempDir,
    _stop: tokio::sync::oneshot::Sender<()>,
}

async fn start() -> TestServer {
    start_with(0).await
}

async fn start_with(max_shares_per_member: u64) -> TestServer {
    let dir = tempfile::tempdir().unwrap();
    let listeners = Listeners::bind("127.0.0.1:0", "127.0.0.1:0").await.unwrap();
    let api = format!("http://{}", listeners.api.local_addr().unwrap());
    let tracker = format!("http://{}", listeners.tracker.local_addr().unwrap());
    let admin = KeyPair::generate().unwrap();
    let server = open_data_dir(dir.path())
        .unwrap()
        .init(&InitParams {
            name: "test index",
            admin_pubkey: &admin.public().to_b64(),
            admin_name: "admin",
            public_url: &api,
            tracker_url: &tracker,
        })
        .unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let opts = ServeOptions {
        data_dir: dir.path().to_owned(),
        trust_proxy: false,
        nat_public_addr: None,
        max_shares_per_member,
    };
    tokio::spawn(async move {
        serve(opts, listeners, async {
            let _ = rx.await;
        })
        .await
        .unwrap();
    });
    TestServer {
        api,
        tracker,
        server_pub: server.public().to_b64(),
        admin,
        http: reqwest::Client::new(),
        _dir: dir,
        _stop: tx,
    }
}

impl TestServer {
    fn url(&self, path: &str) -> String {
        format!("{}/v1{path}", self.api)
    }

    async fn challenge(&self, key: &KeyPair) -> ChallengeResponse {
        self.http
            .post(self.url("/auth/challenge"))
            .json(&json!({ "pubkey": key.public().to_b64() }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap()
    }

    async fn try_login(&self, key: &KeyPair) -> reqwest::Response {
        let ch = self.challenge(key).await;
        let pinned = keys::PublicKey::from_b64(&self.server_pub).unwrap();
        auth::verify_challenge(&pinned, &key.public().to_b64(), &ch.nonce, &ch.server_sig)
            .expect("server signature verifies against the pinned key");
        let sig = auth::sign_login(key, &self.server_pub, &ch.nonce);
        self.http
            .post(self.url("/auth/login"))
            .json(&json!({ "pubkey": key.public().to_b64(), "nonce": ch.nonce, "signature": sig }))
            .send()
            .await
            .unwrap()
    }

    async fn login(&self, key: &KeyPair) -> LoginResponse {
        let r = self.try_login(key).await;
        assert_eq!(r.status(), StatusCode::OK);
        r.json().await.unwrap()
    }

    async fn add_member(&self, admin_token: &str, name: &str) -> KeyPair {
        let k = KeyPair::generate().unwrap();
        let r = self
            .http
            .post(self.url("/admin/members"))
            .bearer_auth(admin_token)
            .json(&json!({ "pubkey": k.public().to_b64(), "name": name }))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::CREATED);
        k
    }
}

fn small_torrent(dir: &std::path::Path, name: &str, private: bool) -> Vec<u8> {
    let p = dir.join(name);
    std::fs::write(&p, format!("contents of {name}")).unwrap();
    let opts = BuildOptions {
        private,
        announce: Some("http://elsewhere/announce?passkey=UPLOADERSECRET".into()),
        ..Default::default()
    };
    metainfo::build(&p, &opts, |_, _| std::ops::ControlFlow::Continue(()))
        .unwrap()
        .bytes
}

#[tokio::test]
async fn info_and_mutual_auth() {
    let s = start().await;
    let info: InfoResponse = s
        .http
        .get(s.url("/info"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(info.server_pubkey, s.server_pub);
    assert_eq!(info.protocol, "lemonwire-v1");

    let login = s.login(&s.admin).await;
    assert!(
        login
            .announce_url
            .starts_with(&format!("{}/announce?passkey=", s.tracker))
    );

    // Unknown key and bad signature get identical responses.
    let stranger = KeyPair::generate().unwrap();
    let r1 = s.try_login(&stranger).await;
    assert_eq!(r1.status(), StatusCode::UNAUTHORIZED);
    let body1 = r1.text().await.unwrap();

    let ch = s.challenge(&s.admin).await;
    let bad_sig = auth::sign_login(&stranger, &s.server_pub, &ch.nonce);
    let r2 = s
        .http
        .post(s.url("/auth/login"))
        .json(&json!({ "pubkey": s.admin.public().to_b64(), "nonce": ch.nonce, "signature": bad_sig }))
        .send()
        .await
        .unwrap();
    assert_eq!(r2.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(r2.text().await.unwrap(), body1);

    // That nonce was consumed by the failed attempt, so a correct signature now fails too.
    let good = auth::sign_login(&s.admin, &s.server_pub, &ch.nonce);
    let r3 = s
        .http
        .post(s.url("/auth/login"))
        .json(&json!({ "pubkey": s.admin.public().to_b64(), "nonce": ch.nonce, "signature": good }))
        .send()
        .await
        .unwrap();
    assert_eq!(r3.status(), StatusCode::UNAUTHORIZED);

    // A nonce issued to one key can't be used by another.
    let bob_token = s.login(&s.admin).await.token;
    let bob = s.add_member(&bob_token, "bob").await;
    let ch = s.challenge(&s.admin).await;
    let sig = auth::sign_login(&bob, &s.server_pub, &ch.nonce);
    let r4 = s
        .http
        .post(s.url("/auth/login"))
        .json(&json!({ "pubkey": bob.public().to_b64(), "nonce": ch.nonce, "signature": sig }))
        .send()
        .await
        .unwrap();
    assert_eq!(r4.status(), StatusCode::UNAUTHORIZED);

    // Authenticated endpoints need a token.
    let r = s.http.get(s.url("/search")).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn publish_search_fetch_delete() {
    let s = start().await;
    let dir = tempfile::tempdir().unwrap();
    let admin = s.login(&s.admin).await;
    let bob_key = s.add_member(&admin.token, "bob").await;
    let bob = s.login(&bob_key).await;

    // Non-private torrents are refused.
    let public = small_torrent(dir.path(), "public.txt", false);
    let r = s
        .http
        .post(s.url("/torrents"))
        .bearer_auth(&bob.token)
        .json(&json!({ "torrent_b64": keys::b64_encode(&public) }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);

    let t = small_torrent(dir.path(), "Summer Mixtape.mp3", true);
    let parsed = metainfo::parse(&t).unwrap();
    let r = s
        .http
        .post(s.url("/torrents"))
        .bearer_auth(&bob.token)
        .json(&json!({ "torrent_b64": keys::b64_encode(&t), "tags": ["Music", "2026"] }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CREATED);
    let entry: TorrentEntry = r.json().await.unwrap();
    assert_eq!(entry.infohash, parsed.infohash);
    assert_eq!(entry.uploader, "bob");
    assert_eq!(entry.tags, ["music", "2026"]);

    let search = |q: &'static str| {
        let s = &s;
        let token = admin.token.clone();
        async move {
            let r: SearchResponse = s
                .http
                .get(s.url("/search"))
                .query(&[("q", q)])
                .bearer_auth(token)
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            r.results
        }
    };
    assert_eq!(search("mixtape").await.len(), 1);

    // /me, and filtering to the caller's own uploads.
    let me: Member = s
        .http
        .get(s.url("/me"))
        .bearer_auth(&bob.token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!((me.name.as_str(), me.is_admin), ("bob", false));
    let mine = |token: String| {
        let s = &s;
        async move {
            let r: SearchResponse = s
                .http
                .get(s.url("/search"))
                .query(&[("mine", "true")])
                .bearer_auth(token)
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            r.results.len()
        }
    };
    assert_eq!(mine(bob.token.clone()).await, 1);
    assert_eq!(mine(admin.token.clone()).await, 0);
    assert_eq!(search("music").await.len(), 1);
    assert_eq!(search("\"OR*(").await.len(), 0);
    assert_eq!(search("").await.len(), 1);

    // Fetch: the uploader's announce is gone and the caller's is injected.
    let f: FetchResponse = s
        .http
        .get(s.url(&format!("/torrents/{}", entry.infohash)))
        .bearer_auth(&admin.token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let fetched = keys::b64_decode(&f.torrent_b64).unwrap();
    assert!(!String::from_utf8_lossy(&fetched).contains("UPLOADERSECRET"));
    let fp = metainfo::parse(&fetched).unwrap();
    assert_eq!(fp.infohash, parsed.infohash);
    assert_eq!(fp.announce.as_deref(), Some(admin.announce_url.as_str()));

    // Only the uploader or an admin can unpublish.
    let carol = s.login(&s.add_member(&admin.token, "carol").await).await;
    let path = s.url(&format!("/torrents/{}", entry.infohash));
    let r = s
        .http
        .delete(&path)
        .bearer_auth(&carol.token)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    let r = s
        .http
        .delete(&path)
        .bearer_auth(&bob.token)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NO_CONTENT);
    assert!(search("mixtape").await.is_empty());
}

#[tokio::test]
async fn admin_invites_and_revoke() {
    let s = start().await;
    let admin = s.login(&s.admin).await;
    let bob_key = s.add_member(&admin.token, "bob").await;
    let bob = s.login(&bob_key).await;

    // Members can't use admin endpoints.
    let r = s
        .http
        .get(s.url("/admin/members"))
        .bearer_auth(&bob.token)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);

    let invite: Invite = s
        .http
        .post(s.url("/admin/invites"))
        .bearer_auth(&admin.token)
        .json(&json!({}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let dave = KeyPair::generate().unwrap();
    let join = |key: &KeyPair, name: &str| {
        s.http.post(s.url("/join")).json(&json!({
            "invite": invite.code.as_deref().unwrap(), "pubkey": key.public().to_b64(), "name": name
        }))
    };
    let r = join(&dave, "dave").send().await.unwrap();
    assert_eq!(r.status(), StatusCode::CREATED);
    let r = join(&KeyPair::generate().unwrap(), "eve")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND, "invite is single-use");
    s.login(&dave).await;

    let members: MembersResponse = s
        .http
        .get(s.url("/admin/members"))
        .bearer_auth(&admin.token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(members.members.len(), 3);

    // Revoking ends sessions and blocks login.
    let r = s
        .http
        .delete(s.url("/admin/members/bob"))
        .bearer_auth(&admin.token)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NO_CONTENT);
    let r = s
        .http
        .get(s.url("/search"))
        .bearer_auth(&bob.token)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        s.try_login(&bob_key).await.status(),
        StatusCode::UNAUTHORIZED
    );
}

fn announce_query(info_hash: &[u8], peer_id: u8, port: u16, left: u64, passkey: &str) -> String {
    let enc = |b: &[u8]| {
        percent_encoding::percent_encode(b, percent_encoding::NON_ALPHANUMERIC).to_string()
    };
    format!(
        "passkey={passkey}&info_hash={}&peer_id={}&port={port}&uploaded=0&downloaded=0&left={left}&compact=1",
        enc(info_hash),
        enc(&[peer_id; 20])
    )
}

#[tokio::test]
async fn tracker_enforces_passkey_and_registration() {
    let s = start().await;
    let dir = tempfile::tempdir().unwrap();
    let admin = s.login(&s.admin).await;
    let bob = s.login(&s.add_member(&admin.token, "bob").await).await;
    let passkey = |l: &LoginResponse| l.announce_url.split("passkey=").nth(1).unwrap().to_owned();

    let t = small_torrent(dir.path(), "file.bin", true);
    let parsed = metainfo::parse(&t).unwrap();
    let info_hash = hex::decode(&parsed.infohash).unwrap();

    let announce = |q: String| {
        let s = &s;
        async move {
            let body = s
                .http
                .get(format!("{}/announce?{q}", s.tracker))
                .send()
                .await
                .unwrap()
                .bytes()
                .await
                .unwrap();
            bencode::decode(&body).unwrap()
        }
    };
    let reason = |v: &Value| {
        v.get("failure reason")
            .and_then(Value::as_str)
            .map(str::to_owned)
    };

    // Not yet published.
    let v = announce(announce_query(&info_hash, 1, 6881, 0, &passkey(&bob))).await;
    assert_eq!(reason(&v).as_deref(), Some("unregistered torrent"));

    s.http
        .post(s.url("/torrents"))
        .bearer_auth(&bob.token)
        .json(&json!({ "torrent_b64": keys::b64_encode(&t) }))
        .send()
        .await
        .unwrap();

    let v = announce(announce_query(&info_hash, 1, 6881, 0, "wrong")).await;
    assert_eq!(reason(&v).as_deref(), Some("invalid passkey"));

    // Bob seeds, admin leeches: admin gets bob's address.
    let v = announce(announce_query(&info_hash, 1, 6881, 0, &passkey(&bob))).await;
    assert_eq!(reason(&v), None);
    assert!(v.get("interval").and_then(Value::as_int).unwrap() > 0);
    let v = announce(announce_query(&info_hash, 2, 6882, 100, &passkey(&admin))).await;
    let peers = v.get("peers").and_then(Value::as_bytes).unwrap();
    assert_eq!(peers, [127, 0, 0, 1, 0x1a, 0xe1]); // 127.0.0.1:6881
    assert_eq!(v.get("complete").and_then(Value::as_int), Some(1));
    assert_eq!(v.get("incomplete").and_then(Value::as_int), Some(1));

    // Scrape needs a passkey too.
    let enc = percent_encoding::percent_encode(&info_hash, percent_encoding::NON_ALPHANUMERIC);
    let body = s
        .http
        .get(format!(
            "{}/scrape?passkey={}&info_hash={enc}",
            s.tracker,
            passkey(&bob)
        ))
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    let v = bencode::decode(&body).unwrap();
    let files: &BTreeMap<Vec<u8>, Value> = v.get("files").and_then(Value::as_dict).unwrap();
    assert_eq!(files.len(), 1);

    // A partial download that's done with its selection isn't a full copy.
    let q = announce_query(&info_hash, 3, 6883, 0, &passkey(&admin)) + "&lw_partial=1";
    announce(q).await;
    let scrape = |pk: String| {
        let s = &s;
        let enc = percent_encoding::percent_encode(&info_hash, percent_encoding::NON_ALPHANUMERIC)
            .to_string();
        async move {
            let body = s
                .http
                .get(format!("{}/scrape?passkey={pk}&info_hash={enc}", s.tracker))
                .send()
                .await
                .unwrap()
                .bytes()
                .await
                .unwrap();
            let v = bencode::decode(&body).unwrap();
            let f = v.get("files").and_then(Value::as_dict).unwrap();
            let st = f.values().next().unwrap().clone();
            (
                st.get("complete").and_then(Value::as_int).unwrap(),
                st.get("complete_members").and_then(Value::as_int).unwrap(),
            )
        }
    };
    assert_eq!(
        scrape(passkey(&bob)).await,
        (1, 1),
        "only bob has a full copy"
    );
    let q = announce_query(&info_hash, 3, 6883, 0, &passkey(&admin)) + "&event=stopped";
    announce(q).await;

    // Stopping removes the peer.
    let q = announce_query(&info_hash, 1, 6881, 0, &passkey(&bob)) + "&event=stopped";
    announce(q).await;
    let v = announce(announce_query(&info_hash, 2, 6882, 100, &passkey(&admin))).await;
    assert!(v.get("peers").and_then(Value::as_bytes).unwrap().is_empty());
}

#[tokio::test]
async fn share_quota_per_member() {
    let s = start_with(1).await;
    let dir = tempfile::tempdir().unwrap();
    let admin = s.login(&s.admin).await;
    let publish = |name: &'static str| {
        let s = &s;
        let token = admin.token.clone();
        let t = small_torrent(dir.path(), name, true);
        async move {
            s.http
                .post(s.url("/torrents"))
                .bearer_auth(token)
                .json(&json!({ "torrent_b64": keys::b64_encode(&t) }))
                .send()
                .await
                .unwrap()
                .status()
        }
    };
    assert_eq!(publish("one.txt").await, StatusCode::CREATED);
    assert_eq!(publish("two.txt").await, StatusCode::FORBIDDEN);
}
