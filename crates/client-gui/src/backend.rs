//! The bridge between the UI thread and `client-core`: commands run on a tokio
//! runtime, and their results and progress events come back to the UI, which is
//! repainted whenever something arrives.

use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::StreamExt;
use lemonwire_client_core::{
    CancellationToken, Client, ClientError, Command, ConfigDir, EngineSettings, Event, OpenOptions,
    Output, Result,
};

/// A command running in the background. Poll it each frame with [`poll`].
pub struct Task {
    slot: Arc<Mutex<Option<Result<Output>>>>,
    cancel: CancellationToken,
}

impl Task {
    pub fn cancel(&self) {
        self.cancel.cancel();
    }

    /// The result, once (`None` while it runs).
    pub fn take(&self) -> Option<Result<Output>> {
        self.slot.lock().expect("task slot").take()
    }
}

/// Take a finished task's result, clearing the slot. `None` while it runs (or if
/// there's no task).
pub fn poll(task: &mut Option<Task>) -> Option<Result<Output>> {
    let result = task.as_ref()?.take();
    if result.is_some() {
        *task = None;
    }
    result
}

pub struct Backend {
    rt: tokio::runtime::Runtime,
    pub client: Arc<Client>,
    pub config: ConfigDir,
    ctx: egui::Context,
    events: mpsc::Receiver<Event>,
    events_tx: mpsc::Sender<Event>,
    /// Serving every saved transfer while the app is open (`None` without an engine).
    serving: Option<Task>,
    /// Why there's no engine, if there isn't one.
    pub engine_error: Option<String>,
}

impl Backend {
    pub fn start(ctx: egui::Context, config: ConfigDir, settings: &crate::Settings) -> Self {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .thread_name("lemonwire")
            .build()
            .expect("tokio runtime");
        let (events_tx, events) = mpsc::channel();
        let (client, engine_error) = rt.block_on(open(&config, settings));
        let mut backend = Self {
            rt,
            client,
            config,
            ctx,
            events,
            events_tx,
            serving: None,
            engine_error,
        };
        backend.after_open();
        backend
    }

    /// Try again to start the engine (after another Lemon Wire stopped, say).
    pub fn reopen(&mut self, settings: &crate::Settings) {
        self.stop_serving();
        let (client, engine_error) = self.rt.block_on(open(&self.config, settings));
        self.client = client;
        self.engine_error = engine_error;
        self.after_open();
    }

    fn after_open(&mut self) {
        // Forward progress events to the UI thread.
        let stream = self.client.subscribe();
        let tx = self.events_tx.clone();
        let ctx = self.ctx.clone();
        self.rt.spawn(async move {
            let mut stream = std::pin::pin!(stream);
            while let Some(e) = stream.next().await {
                if tx.send(e).is_err() {
                    break;
                }
                ctx.request_repaint();
            }
        });
        if self.client.has_engine() {
            self.serving = Some(self.run(Command::Seed));
        }
    }

    pub fn has_engine(&self) -> bool {
        self.client.has_engine()
    }

    /// Run a command in the background.
    pub fn run(&self, cmd: Command) -> Task {
        let slot = Arc::new(Mutex::new(None));
        let cancel = CancellationToken::new();
        let (client, ctx, out, stop) = (
            self.client.clone(),
            self.ctx.clone(),
            slot.clone(),
            cancel.clone(),
        );
        self.rt.spawn(async move {
            let result = client.execute_cancellable(cmd, &stop).await;
            *out.lock().expect("task slot") = Some(result);
            ctx.request_repaint();
        });
        Task { slot, cancel }
    }

    pub fn events(&self) -> impl Iterator<Item = Event> + '_ {
        self.events.try_iter()
    }

    pub fn set_passphrase(&self, passphrase: Option<String>) {
        self.client.set_passphrase(passphrase);
    }

    fn stop_serving(&mut self) {
        if let Some(task) = self.serving.take() {
            task.cancel();
            // Seed stops its transfers before returning.
            let slot = task.slot.clone();
            self.rt.block_on(async {
                for _ in 0..50 {
                    if slot.lock().expect("task slot").is_some() {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            });
        }
    }

    /// Stop transfers and the engine before the app exits.
    pub fn shutdown(&mut self) {
        self.stop_serving();
        let client = self.client.clone();
        self.rt.block_on(async move {
            let _ = tokio::time::timeout(Duration::from_secs(5), client.shutdown()).await;
        });
    }
}

async fn open(config: &ConfigDir, settings: &crate::Settings) -> (Arc<Client>, Option<String>) {
    let engine = EngineSettings {
        port: settings.port,
        upnp: settings.upnp,
        upload_kib: settings.upload_kib,
        download_kib: settings.download_kib,
    };
    let options = |engine| OpenOptions {
        config: config.clone(),
        engine,
        download_dir: settings.download_dir.clone(),
        passphrase: None,
    };
    match Client::open(options(Some(engine))).await {
        Ok(c) => (Arc::new(c), None),
        Err(e) => {
            let why = match e {
                ClientError::EngineBusy => "Another Lemon Wire is transferring with this \
                    profile folder (a `lemonwire seed`, say). Searching works, but sharing \
                    and downloading are off until it stops."
                    .to_owned(),
                e => format!("The torrent engine didn't start: {e}"),
            };
            let client = Client::open(options(None))
                .await
                .expect("a client without an engine always opens");
            (Arc::new(client), Some(why))
        }
    }
}
