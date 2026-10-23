//! Helpers for running a throwaway index in tests (used by client crates too).

use std::path::PathBuf;

use crate::db::{Db, InitParams};
use crate::{Listeners, ServeOptions, open_data_dir, serve};

pub struct TestIndex {
    pub url: String,
    pub tracker_url: String,
    pub server_pubkey: String,
    pub data_dir: PathBuf,
    _dir: tempfile::TempDir,
    _stop: tokio::sync::oneshot::Sender<()>,
}

impl TestIndex {
    /// Init a fresh index with `admin_pubkey` and serve it on 127.0.0.1 ephemeral ports.
    pub async fn start(admin_pubkey: &str) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let listeners = Listeners::bind("127.0.0.1:0", "127.0.0.1:0")
            .await
            .expect("bind");
        let url = format!("http://{}", listeners.api.local_addr().expect("addr"));
        let tracker_url = format!("http://{}", listeners.tracker.local_addr().expect("addr"));
        let server = open_data_dir(dir.path())
            .expect("data dir")
            .init(&InitParams {
                name: "test index",
                admin_pubkey,
                admin_name: "admin",
                public_url: &url,
                tracker_url: &tracker_url,
            })
            .expect("init");
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let opts = ServeOptions {
            data_dir: dir.path().to_owned(),
            trust_proxy: false,
            nat_public_addr: None,
            max_shares_per_member: 0,
        };
        tokio::spawn(async move {
            let _ = serve(opts, listeners, async {
                let _ = rx.await;
            })
            .await;
        });
        Self {
            url,
            tracker_url,
            server_pubkey: server.public().to_b64(),
            data_dir: dir.path().to_owned(),
            _dir: dir,
            _stop: tx,
        }
    }

    /// Direct database access, as the `lemonwire-server` CLI has.
    pub fn db(&self) -> Db {
        open_data_dir(&self.data_dir).expect("open db")
    }
}
