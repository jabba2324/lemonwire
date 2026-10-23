//! UI tests: the real app in egui's test harness (no window or GPU needed).

use egui_kittest::Harness;
use egui_kittest::kittest::Queryable;

use crate::app::{App, UnlockDialog};

fn app(dir: &std::path::Path) -> Harness<'static, App> {
    // No UPnP or fixed port from tests.
    let settings = crate::Settings {
        upnp: false,
        port: 0,
        ..crate::Settings::default()
    };
    settings.save(dir).unwrap();
    let config = lemonwire_client_core::ConfigDir::new(dir);
    Harness::builder()
        .with_size(egui::vec2(1000.0, 640.0))
        .build_eframe(move |cc| App::new(&cc.egui_ctx, config))
}

#[test]
fn first_run_shows_join() {
    let dir = tempfile::tempdir().unwrap();
    let mut h = app(dir.path());
    h.run_steps(5);
    h.get_by_label("Join an index");
    h.get_by_label("I have an invite");
}

#[test]
fn unlock_dialog_takes_input_and_closes() {
    let dir = tempfile::tempdir().unwrap();
    let mut h = app(dir.path());
    h.run_steps(3);
    h.state_mut().unlock = Some(UnlockDialog::default());
    h.run_steps(3);
    h.get_by_role(egui::accesskit::Role::PasswordInput)
        .type_text("lemon tree");
    h.run_steps(3);
    assert_eq!(h.state().unlock.as_ref().unwrap().passphrase, "lemon tree");
    h.get_by_label("Not now").click();
    h.run_steps(3);
    assert!(h.state().unlock.is_none());
}

/// Run frames until `done` holds (background commands need real time).
fn until(h: &mut Harness<'static, App>, what: &str, done: impl Fn(&App) -> bool) {
    for _ in 0..200 {
        h.run_steps(1);
        if done(h.state()) {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    panic!("timed out waiting for {what}");
}

/// A member of a real (in-process) index whose key is protected: the app asks for
/// the passphrase, and once unlocked shows the index.
#[test]
fn locked_key_unlocks_and_browses() {
    use lemonwire_client_core::{Client, ClientOptions, Command, ConfigDir, SeedUntil};

    let rt = tokio::runtime::Runtime::new().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let config = ConfigDir::new(dir.path());
    let setup = Client::new(ClientOptions {
        config: config.clone(),
        engine: None,
        download_dir: None,
        passphrase: None,
    })
    .unwrap();
    let index = rt.block_on(async {
        let pk = match setup
            .execute(Command::KeysGenerate {
                profile: "home".into(),
            })
            .await
            .unwrap()
        {
            lemonwire_client_core::Output::PublicKey { public_key, .. } => public_key,
            o => panic!("{o:?}"),
        };
        let index = lemonwire_server::testing::TestIndex::start(&pk).await;
        setup
            .execute(Command::ProfileAdd {
                profile: "home".into(),
                url: index.url.clone(),
                server_key: Some(index.server_pubkey.clone()),
                invite: None,
                member_name: None,
                allow_insecure: false,
            })
            .await
            .unwrap();
        let file = dir.path().join("lemonade.txt");
        std::fs::write(&file, b"squeeze").unwrap();
        setup
            .execute(Command::Share {
                profile: None,
                path: file,
                tags: vec![],
                until: SeedUntil::PublishOnly,
            })
            .await
            .unwrap();
        setup
            .execute(Command::KeysProtect {
                profile: "home".into(),
                new_passphrase: Some("lemon tree".into()),
            })
            .await
            .unwrap();
        index
    });
    drop(setup);

    let mut h = app(dir.path());
    until(&mut h, "the unlock dialog", |a| a.unlock.is_some());
    h.get_by_role(egui::accesskit::Role::PasswordInput)
        .type_text("wrong");
    h.run_steps(2);
    h.get_by_label("Unlock").click();
    until(&mut h, "the wrong passphrase", |a| {
        a.unlock.as_ref().is_some_and(|u| u.error.is_some())
    });
    h.get_by_role(egui::accesskit::Role::PasswordInput)
        .type_text("lemon tree");
    h.run_steps(2);
    h.get_by_label("Unlock").click();
    until(&mut h, "unlocking", |a| {
        a.unlock.is_none() && a.me.is_some()
    });
    until(&mut h, "search results", |a| a.search.results.len() == 1);
    assert_eq!(h.state().search.results[0].name, "lemonade.txt");

    // Share a folder through the dialog (the file picker itself is the OS's).
    let folder = dir.path().join("zest");
    std::fs::create_dir(&folder).unwrap();
    std::fs::write(folder.join("peel.txt"), b"bright").unwrap();
    h.state_mut().start_share(folder);
    h.run_steps(2);
    h.get_by_label("Tags (optional, separated by commas)")
        .type_text("citrus, peel");
    h.run_steps(2);
    h.get_by_label(&format!("{} Share", egui_phosphor::regular::UPLOAD_SIMPLE))
        .click();
    until(&mut h, "the share", |a| a.share.is_none());
    until(&mut h, "the new entry", |a| a.search.results.len() == 2);
    let zest = h
        .state()
        .search
        .results
        .iter()
        .find(|e| e.name == "zest")
        .cloned()
        .unwrap();
    assert_eq!(zest.tags, ["citrus", "peel"]);
    drop(index);
}
