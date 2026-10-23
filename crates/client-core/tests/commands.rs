//! Command tests against a real index, with the mock torrent engine.

use std::sync::Arc;
use std::time::Duration;

use lemonwire_client_core::engine::MockEngine;
use lemonwire_client_core::*;
use lemonwire_proto::keys::KeyPair;
use lemonwire_server::testing::TestIndex;

struct TestClient {
    client: Arc<Client>,
    engine: Arc<MockEngine>,
    dir: tempfile::TempDir,
}

fn client() -> TestClient {
    let dir = tempfile::tempdir().unwrap();
    let engine = Arc::new(MockEngine::default());
    let client = Client::new(ClientOptions {
        config: ConfigDir::new(dir.path().join("config")),
        engine: Some(engine.clone()),
        download_dir: Some(dir.path().join("downloads")),
        passphrase: None,
    })
    .unwrap();
    TestClient {
        client: Arc::new(client),
        engine,
        dir,
    }
}

impl TestClient {
    async fn run(&self, cmd: Command) -> Result<Output> {
        self.client.execute(cmd).await
    }

    async fn public_key(&self, profile: &str) -> String {
        match self
            .run(Command::KeysGenerate {
                profile: profile.into(),
            })
            .await
            .unwrap()
        {
            Output::PublicKey { public_key, .. } => public_key,
            o => panic!("unexpected {o:?}"),
        }
    }

    async fn public_key_of(&self, profile: &str) -> String {
        match self.run(Command::ProfileList).await.unwrap() {
            Output::Profiles { profiles } => {
                profiles
                    .into_iter()
                    .find(|p| p.name == profile)
                    .unwrap()
                    .public_key
            }
            o => panic!("unexpected {o:?}"),
        }
    }

    async fn add_profile(
        &self,
        name: &str,
        index: &TestIndex,
        server_key: Option<String>,
        invite: Option<String>,
    ) -> Result<Output> {
        self.run(Command::ProfileAdd {
            profile: name.into(),
            url: index.url.clone(),
            server_key,
            invite,
            member_name: None,
            allow_insecure: false,
        })
        .await
    }

    async fn search(
        &self,
        query: &str,
        limit: Option<u32>,
        offset: Option<u32>,
        mine: bool,
    ) -> (Vec<TorrentEntry>, Option<u32>) {
        match self
            .run(Command::Search {
                profile: None,
                query: query.into(),
                limit,
                offset,
                mine,
            })
            .await
            .unwrap()
        {
            Output::Results {
                results,
                next_offset,
                ..
            } => (results, next_offset),
            o => panic!("unexpected {o:?}"),
        }
    }

    async fn transfers(&self) -> Vec<TransferView> {
        match self.run(Command::Transfers).await.unwrap() {
            Output::Transfers { transfers } => transfers,
            o => panic!("unexpected {o:?}"),
        }
    }

    /// Publish without seeding.
    async fn publish(&self, path: std::path::PathBuf, tags: &[&str]) -> (TorrentEntry, bool) {
        match self
            .run(Command::Share {
                profile: None,
                path,
                tags: tags.iter().map(|t| t.to_string()).collect(),
                until: SeedUntil::PublishOnly,
            })
            .await
            .unwrap()
        {
            Output::Shared {
                entry,
                already_indexed,
                stopped,
            } => {
                assert_eq!(stopped, StopReason::NotSeeded);
                (entry, already_indexed)
            }
            o => panic!("unexpected {o:?}"),
        }
    }

    /// Wait until the mock engine is running this torrent.
    async fn wait_running(&self, infohash: &str) {
        for _ in 0..100 {
            if self.engine.path_of(infohash).is_some() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("{infohash} never started");
    }

    fn download(
        &self,
        infohash: &str,
        dest: Option<std::path::PathBuf>,
        files: Option<Vec<usize>>,
        seed_back: Option<SeedBack>,
    ) -> tokio::task::JoinHandle<Result<Output>> {
        let c = self.client.clone();
        let cmd = Command::Download {
            profile: None,
            infohash: infohash.to_owned(),
            dest,
            files,
            seed_back,
        };
        tokio::spawn(async move { c.execute(cmd).await })
    }
}

/// The admin bootstrap: generate a key, init the index with it, add the profile.
async fn admin_setup() -> (TestIndex, TestClient) {
    let admin = client();
    let pk = admin.public_key("home").await;
    // Generating again returns the same key rather than replacing it.
    assert_eq!(admin.public_key("home").await, pk);
    let index = TestIndex::start(&pk).await;
    let out = admin
        .add_profile("home", &index, Some(index.server_pubkey.clone()), None)
        .await
        .unwrap();
    match out {
        Output::ProfileAdded {
            member,
            pinned_out_of_band,
            profile,
            ..
        } => {
            assert!(member && pinned_out_of_band);
            assert_eq!(profile.public_key, pk);
            assert!(profile.default);
        }
        o => panic!("unexpected {o:?}"),
    }
    (index, admin)
}

/// A second member, added directly by key.
async fn member(index: &TestIndex, name: &str) -> TestClient {
    let c = client();
    c.add_profile("home", index, None, None).await.unwrap();
    let pk = c.public_key_of("home").await;
    index.db().add_member(&pk, name, false).unwrap();
    c
}

#[tokio::test]
async fn server_key_mismatch_is_refused() {
    let (index, _admin) = admin_setup().await;
    let other = client();
    let wrong = KeyPair::generate().unwrap().public().to_b64();
    let err = other
        .add_profile("x", &index, Some(wrong), None)
        .await
        .unwrap_err();
    assert!(matches!(err, ClientError::ServerKeyMismatch { .. }));
    // Errors serialise for front-ends.
    let json = serde_json::to_value(&err).unwrap();
    assert_eq!(json["kind"], "server_key_mismatch");
    assert!(json["message"].as_str().unwrap().contains("mismatch"));
    match other.run(Command::ProfileList).await.unwrap() {
        Output::Profiles { profiles } => assert!(profiles.is_empty()),
        o => panic!("unexpected {o:?}"),
    }
}

#[tokio::test]
async fn tampered_invite_code_is_refused() {
    let (index, admin) = admin_setup().await;
    let code = match admin
        .run(Command::InviteCreate {
            profile: None,
            admin: false,
            ttl_hours: None,
        })
        .await
        .unwrap()
    {
        Output::Invite { invite } => invite.code.unwrap(),
        o => panic!("unexpected {o:?}"),
    };
    // Someone swaps the key in the code (or the URL points at an impostor).
    let impostor = KeyPair::generate().unwrap().public().to_b64();
    let (token, _) = lemonwire_proto::api::parse_invite_code(&code);
    let forged = format!("lw1.{token}.{impostor}");
    let friend = client();
    let err = friend
        .add_profile("x", &index, None, Some(forged))
        .await
        .unwrap_err();
    assert!(matches!(err, ClientError::ServerKeyMismatch { .. }));
    // The genuine code still works (nothing was redeemed).
    friend
        .add_profile("x", &index, None, Some(code))
        .await
        .unwrap();
}

#[tokio::test]
async fn plain_http_only_for_trusted_networks() {
    let c = client();
    for url in ["http://index.example", "http://203.0.113.7:8080"] {
        let err = c
            .run(Command::ProfileAdd {
                profile: "x".into(),
                url: url.into(),
                server_key: None,
                invite: None,
                member_name: None,
                allow_insecure: false,
            })
            .await
            .unwrap_err();
        assert!(matches!(err, ClientError::InsecureUrl(_)), "{url}: {err:?}");
    }
}

#[tokio::test]
async fn changed_server_key_blocks_login() {
    let (index, admin) = admin_setup().await;
    let path = admin.dir.path().join("config/profiles.json");
    let json = std::fs::read_to_string(&path).unwrap();
    let impostor = KeyPair::generate().unwrap().public().to_b64();
    std::fs::write(&path, json.replace(&index.server_pubkey, &impostor)).unwrap();
    let fresh = Client::new(ClientOptions {
        config: ConfigDir::new(admin.dir.path().join("config")),
        engine: None,
        download_dir: None,
        passphrase: None,
    })
    .unwrap();
    let err = fresh
        .execute(Command::Whoami { profile: None })
        .await
        .unwrap_err();
    assert!(
        matches!(err, ClientError::ServerKeyMismatch { .. }),
        "{err:?}"
    );
}

#[tokio::test]
async fn invite_and_direct_add() {
    let (index, admin) = admin_setup().await;

    let invite = match admin
        .run(Command::InviteCreate {
            profile: None,
            admin: false,
            ttl_hours: None,
        })
        .await
        .unwrap()
    {
        Output::Invite { invite } => invite.code.unwrap(),
        o => panic!("unexpected {o:?}"),
    };
    let alice = client();
    match alice
        .run(Command::ProfileAdd {
            profile: "friends".into(),
            url: index.url.clone(),
            server_key: None,
            invite: Some(invite),
            member_name: Some("Alice".into()),
            allow_insecure: false,
        })
        .await
        .unwrap()
    {
        Output::ProfileAdded {
            member,
            joined_with_invite,
            pinned_out_of_band,
            profile,
        } => {
            // The invite code carried the index key, so nothing was trusted on first use.
            assert!(member && joined_with_invite && pinned_out_of_band);
            // The profile label and the member name are separate things.
            assert_eq!(profile.name, "friends");
            assert_eq!(profile.member_name.as_deref(), Some("Alice"));
            assert_eq!(profile.server_fingerprint.len(), 24);
            assert_eq!(profile.public_key_fingerprint.len(), 24);
        }
        o => panic!("unexpected {o:?}"),
    }

    // Direct add: profile first (not a member yet), then the admin adds the key.
    let bob = client();
    let bob_pk = match bob
        .add_profile("friends", &index, None, None)
        .await
        .unwrap()
    {
        Output::ProfileAdded {
            member, profile, ..
        } => {
            assert!(!member);
            profile.public_key
        }
        o => panic!("unexpected {o:?}"),
    };
    let whoami = Command::Whoami { profile: None };
    assert!(matches!(
        bob.run(whoami.clone()).await,
        Err(ClientError::NotAMember)
    ));
    admin
        .run(Command::MembersAdd {
            profile: None,
            pubkey: bob_pk,
            name: "bob".into(),
            admin: false,
        })
        .await
        .unwrap();
    match bob.run(whoami).await.unwrap() {
        Output::Me { member, .. } => {
            assert_eq!((member.name.as_str(), member.is_admin), ("bob", false))
        }
        o => panic!("unexpected {o:?}"),
    }
    // ...and the name the admin chose is now remembered on the profile.
    match bob.run(Command::ProfileList).await.unwrap() {
        Output::Profiles { profiles } => {
            assert_eq!(profiles[0].member_name.as_deref(), Some("bob"))
        }
        o => panic!("unexpected {o:?}"),
    }
    match admin.run(Command::Whoami { profile: None }).await.unwrap() {
        Output::Me { member, .. } => assert!(member.is_admin),
        o => panic!("unexpected {o:?}"),
    }
    match admin
        .run(Command::MembersList { profile: None })
        .await
        .unwrap()
    {
        Output::Members { members } => assert_eq!(members.len(), 3),
        o => panic!("unexpected {o:?}"),
    }
}

#[tokio::test]
async fn publish_search_paging_and_details() {
    let (index, admin) = admin_setup().await;
    let bob = member(&index, "bob").await;

    let folder = bob.dir.path().join("Road Trip");
    std::fs::create_dir(&folder).unwrap();
    std::fs::write(folder.join("map.txt"), b"left at the lemon tree").unwrap();
    std::fs::write(folder.join("route.gpx"), b"<gpx/>").unwrap();
    let (entry, again) = bob.publish(folder.clone(), &["travel"]).await;
    assert!(!again);
    assert_eq!(entry.name, "Road Trip");
    // Publishing without seeding saves the transfer but doesn't start it.
    assert!(bob.engine.path_of(&entry.infohash).is_none());
    assert_eq!(bob.transfers().await.len(), 1);
    // Sharing the same thing again is fine.
    assert!(bob.publish(folder.clone(), &[]).await.1);

    for i in 0..3 {
        let f = admin.dir.path().join(format!("note{i}.txt"));
        std::fs::write(&f, format!("note {i}")).unwrap();
        admin.publish(f, &[]).await;
    }

    // Paging and "mine".
    let (page1, next) = admin.search("", Some(3), None, false).await;
    assert_eq!((page1.len(), next), (3, Some(3)));
    let (page2, next) = admin.search("", Some(3), next, false).await;
    assert_eq!((page2.len(), next), (1, None));
    assert_eq!(admin.search("", None, None, true).await.0.len(), 3);
    let (mine, _) = bob.search("", None, None, true).await;
    assert_eq!(mine.len(), 1);
    assert_eq!(mine[0].uploader, "bob");

    // Details give the file list (indexes for selective downloads).
    match admin
        .run(Command::Details {
            profile: None,
            infohash: entry.infohash.clone(),
        })
        .await
        .unwrap()
    {
        Output::Details { entry: e } => {
            let paths: Vec<_> = e.files.iter().map(|f| f.path.as_str()).collect();
            assert_eq!(paths, ["map.txt", "route.gpx"]);
        }
        o => panic!("unexpected {o:?}"),
    }

    // Unpublish removes it from the index and the local list.
    bob.run(Command::Unpublish {
        profile: None,
        infohash: entry.infohash.clone(),
    })
    .await
    .unwrap();
    assert!(bob.transfers().await.is_empty());
    assert!(admin.search("road", None, None, false).await.0.is_empty());
}

#[tokio::test]
async fn download_selected_files_then_seed_back() {
    let (index, admin) = admin_setup().await;
    let bob = member(&index, "bob").await;
    let folder = bob.dir.path().join("Album");
    std::fs::create_dir(&folder).unwrap();
    for t in ["01.flac", "02.flac", "03.flac"] {
        std::fs::write(folder.join(t), t.repeat(100)).unwrap();
    }
    let (entry, _) = bob.publish(folder, &[]).await;
    let ih = entry.infohash.clone();
    let dest = admin.dir.path().join("dl");

    // Out-of-range file indexes are refused before anything starts.
    let r = admin.download(&ih, Some(dest.clone()), Some(vec![7]), None);
    assert!(r.await.unwrap().is_err());
    assert!(admin.transfers().await.is_empty());

    // Only file 1, no seed-back.
    let task = admin.download(&ih, Some(dest.clone()), Some(vec![1]), None);
    admin.wait_running(&ih).await;
    assert_eq!(admin.engine.only_files_of(&ih), Some(vec![1]));
    admin.engine.complete(&ih, 0);
    match task.await.unwrap().unwrap() {
        Output::Downloaded {
            dest: d, seed_back, ..
        } => {
            assert_eq!(d, dest.join("Album"));
            assert_eq!(seed_back, None);
        }
        o => panic!("unexpected {o:?}"),
    }
    // Stopped in the engine, but saved (with its file selection) for `seed`.
    assert!(admin.engine.path_of(&ih).is_none());
    let t = admin.transfers().await;
    assert_eq!(t.len(), 1);
    assert_eq!(t[0].files, Some(vec![1]));

    // Again: resumes the same transfer, then seeds back until the ratio is reached.
    let policy = SeedBack {
        ratio: 1.0,
        max_secs: 60,
    };
    let task = admin.download(&ih, None, None, Some(policy));
    admin.wait_running(&ih).await;
    assert_eq!(
        admin.engine.only_files_of(&ih),
        Some(vec![1]),
        "selection kept"
    );
    admin.engine.complete(&ih, 10_000);
    match task.await.unwrap().unwrap() {
        Output::Downloaded { seed_back, .. } => {
            assert_eq!(seed_back, Some(StopReason::RatioReached))
        }
        o => panic!("unexpected {o:?}"),
    }

    // A different destination for the same download is refused, and the uploader
    // can't "download" their own share.
    let elsewhere = admin.dir.path().join("elsewhere");
    let r = admin.download(&ih, Some(elsewhere), None, None);
    assert!(r.await.unwrap().is_err());
    let r = bob.download(&ih, None, None, None);
    assert!(r.await.unwrap().is_err());
}

#[tokio::test]
async fn cancelling_keeps_the_transfer() {
    let (index, admin) = admin_setup().await;
    let bob = member(&index, "bob").await;
    let f = bob.dir.path().join("big.iso");
    std::fs::write(&f, vec![1u8; 50_000]).unwrap();
    let (entry, _) = bob.publish(f, &[]).await;

    let cancel = CancellationToken::new();
    let task = {
        let c = admin.client.clone();
        let cancel = cancel.clone();
        let ih = entry.infohash.clone();
        tokio::spawn(async move {
            c.execute_cancellable(
                Command::Download {
                    profile: None,
                    infohash: ih,
                    dest: None,
                    files: None,
                    seed_back: None,
                },
                &cancel,
            )
            .await
        })
    };
    admin.wait_running(&entry.infohash).await;
    cancel.cancel();
    assert!(matches!(task.await.unwrap(), Err(ClientError::Cancelled)));
    assert!(admin.engine.path_of(&entry.infohash).is_none());
    assert_eq!(admin.transfers().await.len(), 1, "saved for later");

    // A share seeding "until cancelled" reports why it stopped.
    let f = bob.dir.path().join("small.txt");
    std::fs::write(&f, b"hi").unwrap();
    let cancel = CancellationToken::new();
    let task = {
        let c = bob.client.clone();
        let cancel = cancel.clone();
        tokio::spawn(async move {
            c.execute_cancellable(
                Command::Share {
                    profile: None,
                    path: f,
                    tags: vec![],
                    until: SeedUntil::Cancelled,
                },
                &cancel,
            )
            .await
        })
    };
    tokio::time::sleep(Duration::from_millis(1500)).await;
    cancel.cancel();
    match task.await.unwrap().unwrap() {
        Output::Shared { stopped, .. } => assert_eq!(stopped, StopReason::Cancelled),
        o => panic!("unexpected {o:?}"),
    }
}

#[tokio::test]
async fn seed_serves_saved_transfers_and_follows_changes() {
    let (_index, admin) = admin_setup().await;
    let a = admin.dir.path().join("a.txt");
    let b = admin.dir.path().join("b.txt");
    std::fs::write(&a, b"aaa").unwrap();
    std::fs::write(&b, b"bbb").unwrap();
    let (ea, _) = admin.publish(a, &[]).await;
    let (eb, _) = admin.publish(b, &[]).await;

    let cancel = CancellationToken::new();
    let task = {
        let c = admin.client.clone();
        let cancel = cancel.clone();
        tokio::spawn(async move { c.execute_cancellable(Command::Seed, &cancel).await })
    };
    admin.wait_running(&ea.infohash).await;
    admin.wait_running(&eb.infohash).await;

    // Pause and cancel while it runs: they apply to the running engine.
    admin
        .run(Command::Pause {
            infohash: ea.infohash.clone(),
        })
        .await
        .unwrap();
    let t = admin.transfers().await;
    let pa = t.iter().find(|t| t.infohash == ea.infohash).unwrap();
    assert_eq!(pa.status.as_ref().unwrap().state, TransferState::Paused);
    admin
        .run(Command::Cancel {
            infohash: eb.infohash.clone(),
            delete_data: false,
        })
        .await
        .unwrap();
    assert!(admin.engine.path_of(&eb.infohash).is_none());

    // Limits apply to the running engine.
    admin
        .run(Command::SetLimits {
            upload_kib: Some(100),
            download_kib: None,
        })
        .await
        .unwrap();
    assert_eq!(admin.engine.limits(), (Some(100 * 1024), None));

    cancel.cancel();
    assert!(matches!(
        task.await.unwrap().unwrap(),
        Output::Served { .. }
    ));
    assert!(admin.engine.path_of(&ea.infohash).is_none());
}

#[tokio::test]
async fn one_engine_per_config_dir() {
    let tc = client();
    let config = tc.client.config().clone();
    let second = Client::new(ClientOptions {
        config: config.clone(),
        engine: Some(Arc::new(MockEngine::default())),
        download_dir: None,
        passphrase: None,
    });
    assert!(matches!(second, Err(ClientError::EngineBusy)));
    // Engine-less clients (quick commands) can still run alongside.
    assert!(
        Client::new(ClientOptions {
            config: config.clone(),
            engine: None,
            download_dir: None,
            passphrase: None,
        })
        .is_ok()
    );
    // Once the first client goes away, the lock is free.
    drop(tc);
    assert!(
        Client::new(ClientOptions {
            config,
            engine: Some(Arc::new(MockEngine::default())),
            download_dir: None,
            passphrase: None,
        })
        .is_ok()
    );
}

#[tokio::test]
async fn download_refuses_existing_destination() {
    let (index, admin) = admin_setup().await;
    let file = admin.dir.path().join("notes.txt");
    std::fs::write(&file, b"hello").unwrap();
    let (entry, _) = admin.publish(file, &[]).await;
    let other = member(&index, "other").await;
    let dest = other.dir.path().join("dl");
    std::fs::create_dir_all(&dest).unwrap();
    std::fs::write(dest.join("notes.txt"), b"mine").unwrap();
    let err = other
        .run(Command::Download {
            profile: None,
            infohash: entry.infohash,
            dest: Some(dest),
            files: None,
            seed_back: None,
        })
        .await
        .unwrap_err();
    assert!(matches!(err, ClientError::DestinationExists(_)), "{err:?}");
}

/// The GUI model: `Seed` runs while the app is open, and transfers that shares and
/// downloads start keep running after those commands return.
#[tokio::test]
async fn transfers_stay_running_while_serving() {
    let (index, admin) = admin_setup().await;
    let file = admin.dir.path().join("photos.txt");
    std::fs::write(&file, b"holiday").unwrap();
    let (entry, _) = admin.publish(file, &[]).await;

    let other = member(&index, "other").await;
    let cancel = CancellationToken::new();
    let serve = {
        let c = other.client.clone();
        let cancel = cancel.clone();
        tokio::spawn(async move { c.execute_cancellable(Command::Seed, &cancel).await })
    };
    let dl = other.download(&entry.infohash, None, None, None);
    other.wait_running(&entry.infohash).await;
    other.engine.complete(&entry.infohash, 0);
    assert!(matches!(
        dl.await.unwrap().unwrap(),
        Output::Downloaded { .. }
    ));
    // Still seeding: `Seed` is serving everything.
    assert!(other.engine.path_of(&entry.infohash).is_some());

    cancel.cancel();
    serve.await.unwrap().unwrap();
    assert!(other.engine.path_of(&entry.infohash).is_none());
}
