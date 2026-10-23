//! Your shares and downloads, with live progress.

use egui_extras::{Column, TableBuilder};
use egui_phosphor::regular as icon;
use lemonwire_client_core::{Command, TransferKind, TransferState, TransferView};

use crate::app::{After, App, Confirm};
use crate::format;

fn state_text(t: &TransferView) -> String {
    if t.paused {
        return "Paused".into();
    }
    let Some(s) = &t.status else {
        return "Waiting".into();
    };
    match &s.state {
        TransferState::Checking => "Checking".into(),
        TransferState::Downloading => "Downloading".into(),
        TransferState::Seeding => "Sharing".into(),
        TransferState::Paused => "Paused".into(),
        TransferState::Error(e) => format!("Error: {e}"),
    }
}

/// Open a folder in the system file manager.
fn reveal(path: &std::path::Path) {
    let opener = if cfg!(target_os = "macos") {
        "open"
    } else if cfg!(windows) {
        "explorer"
    } else {
        "xdg-open"
    };
    let _ = std::process::Command::new(opener).arg(path).spawn();
}

impl App {
    pub fn transfers_ui(&mut self, ui: &mut egui::Ui) {
        ui.heading("Transfers");
        ui.weak(
            "Everything here is shared with your friends while Lemon Wire is open, \
             including finished downloads.",
        );
        ui.add_space(8.0);
        if self.transfers.is_empty() {
            ui.add_space(30.0);
            ui.vertical_centered(|ui| {
                ui.weak("Nothing yet. Share something, or download from Browse.");
            });
            return;
        }

        let rows = self.transfers.clone();
        let mut action: Option<(Command, Option<Confirm>)> = None;
        TableBuilder::new(ui)
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .striped(true)
            .column(Column::remainder().at_least(160.0).clip(true))
            .column(Column::exact(170.0))
            .column(Column::auto().at_least(80.0))
            .column(Column::auto().at_least(80.0))
            .column(Column::auto().at_least(50.0))
            .column(Column::auto().at_least(110.0))
            .header(22.0, |mut h| {
                for title in ["Name", "Progress", "Down", "Up", "Peers", ""] {
                    h.col(|ui| {
                        ui.strong(title);
                    });
                }
            })
            .body(|body| {
                body.rows(28.0, rows.len(), |mut row| {
                    let t = &rows[row.index()];
                    let s = t.status.as_ref();
                    row.col(|ui| {
                        let i = match t.kind {
                            TransferKind::Seed => icon::UPLOAD_SIMPLE,
                            TransferKind::Download => icon::DOWNLOAD_SIMPLE,
                        };
                        ui.label(format!("{i}  {}", t.name)).on_hover_text(format!(
                            "{}\n{}",
                            t.name,
                            t.path.display()
                        ));
                    });
                    row.col(|ui| {
                        let (done, total) = s.map_or((0, 0), |s| (s.progress_bytes, s.total_bytes));
                        let f = if total == 0 {
                            0.0
                        } else {
                            done as f32 / total as f32
                        };
                        let text = if s.is_some_and(|s| s.finished) {
                            state_text(t)
                        } else {
                            format!("{} · {:.0}%", state_text(t), f * 100.0)
                        };
                        ui.add(egui::ProgressBar::new(f).text(text));
                    });
                    row.col(|ui| {
                        ui.label(format::speed(s.map_or(0, |s| s.download_bps)));
                    });
                    row.col(|ui| {
                        ui.label(format::speed(s.map_or(0, |s| s.upload_bps)));
                    });
                    row.col(|ui| {
                        ui.label(s.map_or(0, |s| s.peers).to_string());
                    });
                    row.col(|ui| {
                        let (i, tip, cmd) = if t.paused {
                            (
                                icon::PLAY,
                                "Resume",
                                Command::Resume {
                                    infohash: t.infohash.clone(),
                                },
                            )
                        } else {
                            (
                                icon::PAUSE,
                                "Pause",
                                Command::Pause {
                                    infohash: t.infohash.clone(),
                                },
                            )
                        };
                        if ui.small_button(i).on_hover_text(tip).clicked() {
                            action = Some((cmd, None));
                        }
                        let folder = match t.kind {
                            TransferKind::Seed => t.path.parent().map(|p| p.to_owned()),
                            TransferKind::Download => Some(t.path.clone()),
                        };
                        if let Some(folder) = folder
                            && ui
                                .small_button(icon::FOLDER_OPEN)
                                .on_hover_text("Show in folder")
                                .clicked()
                        {
                            reveal(&folder);
                        }
                        if ui.small_button(icon::X).on_hover_text("Remove").clicked() {
                            action = Some(remove(t));
                        }
                    });
                });
            });
        if let Some((cmd, confirm)) = action {
            match confirm {
                Some(c) => self.confirm = Some(c),
                None => self.act(cmd, After::Nothing),
            }
        }
    }
}

/// Removing asks first; for a download it also offers to delete what arrived.
fn remove(t: &TransferView) -> (Command, Option<Confirm>) {
    let cmd = Command::Cancel {
        infohash: t.infohash.clone(),
        delete_data: false,
    };
    let text = match t.kind {
        TransferKind::Seed => format!(
            "Stop sharing {} from this computer? It stays in the index (remove it there \
             from Browse), and your file is untouched.",
            t.name
        ),
        TransferKind::Download => format!(
            "Stop downloading {}? What has arrived so far stays in {}.",
            t.name,
            t.path.display()
        ),
    };
    let confirm = Confirm {
        title: format!("Remove {}?", t.name),
        text,
        button: "Remove".into(),
        cmd: cmd.clone(),
        after: After::Nothing,
    };
    (cmd, Some(confirm))
}
