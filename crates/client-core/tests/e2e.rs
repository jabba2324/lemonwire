//! End to end (spec §7): init an index with an admin key, add a member, share a folder,
//! search, and download it over localhost via the embedded tracker with two real
//! librqbit engines. The share stops by itself once the downloader has a full copy.

use std::sync::Arc;

use lemonwire_client_core::*;
use lemonwire_server::testing::TestIndex;

async fn client(dir: &std::path::Path) -> Client {
    Client::open(OpenOptions {
        config: ConfigDir::new(dir.join("config")),
        engine: Some(EngineSettings {
            port: 0,
            upnp: false,
            ..Default::default()
        }),
        download_dir: Some(dir.join("downloads")),
        passphrase: None,
    })
    .await
    .unwrap()
}

fn public_key(out: Output) -> String {
    match out {
        Output::PublicKey { public_key, .. } => public_key,
        Output::ProfileAdded { profile, .. } => profile.public_key,
        o => panic!("unexpected {o:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn share_and_download_over_localhost() {
    let admin_dir = tempfile::tempdir().unwrap();
    let bob_dir = tempfile::tempdir().unwrap();
    let admin = Arc::new(client(admin_dir.path()).await);
    let bob = Arc::new(client(bob_dir.path()).await);

    // Admin bootstrap and a member.
    let admin_pk = public_key(
        admin
            .execute(Command::KeysGenerate {
                profile: "home".into(),
            })
            .await
            .unwrap(),
    );
    let index = TestIndex::start(&admin_pk).await;
    let add = |name: &str, key: Option<String>| Command::ProfileAdd {
        profile: name.into(),
        url: index.url.clone(),
        server_key: key,
        invite: None,
        member_name: None,
        allow_insecure: false,
    };
    admin
        .execute(add("home", Some(index.server_pubkey.clone())))
        .await
        .unwrap();
    let bob_pk = public_key(bob.execute(add("home", None)).await.unwrap());
    admin
        .execute(Command::MembersAdd {
            profile: None,
            pubkey: bob_pk,
            name: "bob".into(),
            admin: false,
        })
        .await
        .unwrap();

    // Bob shares a folder with a file spanning several pieces, plus a small one, and
    // keeps seeding until one other member has it all.
    let share = bob_dir.path().join("Lemon Grove");
    std::fs::create_dir_all(share.join("photos")).unwrap();
    let big: Vec<u8> = (0..3_000_000u32)
        .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
        .collect();
    std::fs::write(share.join("photos/grove.raw"), &big).unwrap();
    std::fs::write(share.join("readme.txt"), b"picked fresh").unwrap();
    let sharing = {
        let bob = bob.clone();
        tokio::spawn(async move {
            bob.execute(Command::Share {
                profile: None,
                path: share,
                tags: vec!["photos".into()],
                until: SeedUntil::Copies { count: 1 },
            })
            .await
        })
    };

    // Admin searches (waiting for the publish) and downloads.
    let infohash = loop {
        let Output::Results { results, .. } = admin
            .execute(Command::Search {
                profile: None,
                query: "lemon grove".into(),
                limit: None,
                offset: None,
                mine: false,
            })
            .await
            .unwrap()
        else {
            panic!("expected results")
        };
        if let Some(r) = results.first() {
            break r.infohash.clone();
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    };
    let dest = admin_dir.path().join("dl");
    let Output::Downloaded { dest: root, .. } = admin
        .execute(Command::Download {
            profile: None,
            infohash,
            dest: Some(dest.clone()),
            files: None,
            seed_back: None,
        })
        .await
        .unwrap()
    else {
        panic!("expected download")
    };
    assert_eq!(root, dest.join("Lemon Grove"));
    assert_eq!(std::fs::read(root.join("photos/grove.raw")).unwrap(), big);
    assert_eq!(
        std::fs::read(root.join("readme.txt")).unwrap(),
        b"picked fresh"
    );

    // Bob's share notices the full copy and stops by itself.
    let shared = tokio::time::timeout(std::time::Duration::from_secs(90), sharing)
        .await
        .expect("share didn't stop after the download")
        .unwrap()
        .unwrap();
    let Output::Shared { stopped, .. } = shared else {
        panic!("expected shared")
    };
    assert_eq!(stopped, StopReason::CopiesReached { copies: 1 });

    admin.shutdown().await;
    bob.shutdown().await;
}
