//! Lemon Wire desktop app: an egui front-end over `client-core`, running the same
//! commands as the CLI. While the window is open it serves every saved transfer, so
//! friends can download what you share.

#![cfg_attr(windows, windows_subsystem = "windows")]

mod app;
mod backend;
mod format;
mod join;
mod members;
mod prefs;
mod search;
mod settings;
mod theme;
mod transfers;
#[cfg(test)]
mod ui_tests;

pub use settings::Settings;

/// `LEMONWIRE_LOG` (default "warn"), capped so logs never carry passkeys unless
/// `LEMONWIRE_LOG_SECRETS=1`.
fn init_logging() {
    use tracing_subscriber::filter::{LevelFilter, Targets};
    use tracing_subscriber::prelude::*;
    let base = std::env::var("LEMONWIRE_LOG").unwrap_or_else(|_| "warn".into());
    let base = tracing_subscriber::EnvFilter::try_new(base)
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn"));
    let caps = (std::env::var("LEMONWIRE_LOG_SECRETS").as_deref() != Ok("1")).then(|| {
        Targets::new()
            .with_default(LevelFilter::TRACE)
            .with_targets(lemonwire_client_core::LOG_REDACT_CAPS.iter().copied())
    });
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(std::io::stderr)
                .with_filter(base)
                .with_filter(caps),
        )
        .init();
}

fn main() -> eframe::Result {
    init_logging();

    // The same folder as the CLI's, so both see the same profiles and transfers.
    let config = match std::env::var_os("LEMONWIRE_CONFIG_DIR") {
        Some(d) => lemonwire_client_core::ConfigDir::new(d),
        None => match lemonwire_client_core::ConfigDir::default_location() {
            Ok(c) => c,
            Err(e) => {
                eprintln!("lemonwire-gui: {e}");
                std::process::exit(1);
            }
        },
    };

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Lemon Wire")
            .with_app_id("lemonwire")
            .with_inner_size([1000.0, 640.0])
            .with_min_inner_size([720.0, 440.0])
            .with_icon(theme::icon()),
        ..Default::default()
    };
    eframe::run_native(
        "Lemon Wire",
        options,
        Box::new(move |cc| Ok(Box::new(app::App::new(&cc.egui_ctx, config)))),
    )
}
