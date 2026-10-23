//! Browsing and searching the index, with a details pane for the selected entry.

use egui::RichText;
use egui_extras::{Column, TableBuilder};
use egui_phosphor::regular as icon;
use lemonwire_client_core::{Command, Output, TorrentEntry, TransferKind};

use crate::app::{After, App, Confirm};
use crate::backend::{Task, poll};
use crate::format;

#[derive(Default)]
pub struct SearchPage {
    pub query: String,
    pub mine: bool,
    pub results: Vec<TorrentEntry>,
    pub next_offset: Option<u32>,
    task: Option<Task>,
    appending: bool,
    pub selected: Option<String>,
    /// Which files to download, for the selected entry.
    pub files: Vec<bool>,
    /// (infohash, seeders, leechers, members with a full copy).
    swarm: Option<(String, u64, u64, u64)>,
    swarm_task: Option<Task>,
    pub error: Option<String>,
}

const PAGE: u32 = 50;

impl App {
    /// Run the search again from the start (or fetch the next page).
    pub fn search_now(&mut self, more: bool) {
        let offset = if more { self.search.next_offset } else { None };
        if more && offset.is_none() {
            return;
        }
        self.search.appending = more;
        self.search.error = None;
        self.search.task = Some(self.backend.run(Command::Search {
            profile: self.profile_arg(),
            query: self.search.query.trim().to_owned(),
            limit: Some(PAGE),
            offset,
            mine: self.search.mine,
        }));
    }

    fn select_entry(&mut self, e: &TorrentEntry) {
        self.search.selected = Some(e.infohash.clone());
        self.search.files = vec![true; e.files.len()];
        self.search.swarm = None;
        self.search.swarm_task = Some(self.backend.run(Command::Swarm {
            profile: self.profile_arg(),
            infohash: e.infohash.clone(),
        }));
    }

    fn poll_search(&mut self) {
        if let Some(r) = poll(&mut self.search.task) {
            match r {
                Ok(Output::Results {
                    results,
                    next_offset,
                    ..
                }) => {
                    if self.search.appending {
                        self.search.results.extend(results);
                    } else {
                        self.search.results = results;
                    }
                    self.search.next_offset = next_offset;
                }
                Ok(_) => {}
                // The unlock dialog explains a locked key.
                Err(lemonwire_client_core::ClientError::PassphraseRequired) => {
                    self.error(lemonwire_client_core::ClientError::PassphraseRequired);
                }
                Err(e) => {
                    self.search.error = Some(e.to_string());
                    self.error(e);
                }
            }
        }
        if let Some(Ok(Output::Swarm {
            infohash,
            seeders,
            leechers,
            complete_members,
        })) = poll(&mut self.search.swarm_task)
        {
            self.search.swarm = Some((infohash, seeders, leechers, complete_members));
        }
    }

    pub fn search_ui(&mut self, ui: &mut egui::Ui) {
        self.poll_search();

        ui.horizontal(|ui| {
            let edit = ui.add(
                egui::TextEdit::singleline(&mut self.search.query)
                    .hint_text(format!("{} Search the index", icon::MAGNIFYING_GLASS))
                    .desired_width((ui.available_width() - 200.0).max(120.0)),
            );
            let enter = edit.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            if ui.button("Search").clicked() || enter {
                self.search_now(false);
            }
            if ui.checkbox(&mut self.search.mine, "Only mine").changed() {
                self.search_now(false);
            }
            if self.search.task.is_some() {
                ui.spinner();
            }
        });
        ui.add_space(8.0);

        let selected = self
            .search
            .selected
            .as_ref()
            .and_then(|h| self.search.results.iter().find(|e| &e.infohash == h))
            .cloned();
        if let Some(entry) = &selected {
            egui::Panel::right("details")
                .resizable(true)
                .default_size(320.0)
                .min_size(240.0)
                .show(ui, |ui| self.details_ui(ui, entry));
        }

        if self.search.results.is_empty() {
            ui.add_space(30.0);
            ui.vertical_centered(|ui| {
                if self.search.task.is_some() {
                    ui.weak("Searching…");
                } else if self.unlock.is_some() {
                    ui.weak("Unlock your key to browse this index.");
                } else if let Some(e) = &self.search.error {
                    ui.colored_label(ui.visuals().error_fg_color, e);
                } else if self.search.query.trim().is_empty() && !self.search.mine {
                    ui.weak("Nothing has been shared on this index yet. Share something!");
                } else {
                    ui.weak("No matches.");
                }
            });
            return;
        }

        let now = format::now();
        let mut clicked = None;
        let results = self.search.results.clone();
        let sel = self.search.selected.clone();
        TableBuilder::new(ui)
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .striped(true)
            .sense(egui::Sense::click())
            .column(Column::remainder().at_least(160.0).clip(true))
            .column(Column::auto().at_least(70.0))
            .column(Column::auto().at_least(90.0))
            .column(Column::auto().at_least(90.0))
            .header(22.0, |mut h| {
                h.col(|ui| {
                    ui.strong("Name");
                });
                h.col(|ui| {
                    ui.strong("Size");
                });
                h.col(|ui| {
                    ui.strong("Shared by");
                });
                h.col(|ui| {
                    ui.strong("Added");
                });
            })
            .body(|body| {
                body.rows(24.0, results.len(), |mut row| {
                    let e = &results[row.index()];
                    row.set_selected(sel.as_deref() == Some(e.infohash.as_str()));
                    row.col(|ui| {
                        let i = if e.files.len() > 1 {
                            icon::FOLDER
                        } else {
                            icon::FILE
                        };
                        ui.label(format!("{i}  {}", e.name)).on_hover_text(&e.name);
                    });
                    row.col(|ui| {
                        ui.label(format::bytes(e.size));
                    });
                    row.col(|ui| {
                        ui.label(&e.uploader);
                    });
                    row.col(|ui| {
                        ui.label(format::ago(e.created_at, now));
                    });
                    if row.response().clicked() {
                        clicked = Some(e.clone());
                    }
                });
            });
        if let Some(e) = clicked {
            self.select_entry(&e);
        }
        if self.search.next_offset.is_some() {
            ui.add_space(6.0);
            if ui.button("Load more").clicked() {
                self.search_now(true);
            }
        }
    }

    fn details_ui(&mut self, ui: &mut egui::Ui, e: &TorrentEntry) {
        egui::ScrollArea::vertical().show(ui, |ui| {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.heading(&e.name);
            });
            ui.weak(format!(
                "{} · {} file{} · shared by {}",
                format::bytes(e.size),
                e.files.len(),
                if e.files.len() == 1 { "" } else { "s" },
                e.uploader
            ));
            if !e.tags.is_empty() {
                ui.horizontal_wrapped(|ui| {
                    for t in &e.tags {
                        ui.label(RichText::new(format!("#{t}")).color(crate::theme::LEMON_DEEP));
                    }
                });
            }
            ui.add_space(6.0);
            match &self.search.swarm {
                Some((h, seeds, leechers, members)) if h == &e.infohash => {
                    let others = if *seeds == 0 {
                        "Nobody is sharing this right now".to_owned()
                    } else {
                        format!(
                            "{seeds} sharing · {leechers} downloading · {members} with a full copy"
                        )
                    };
                    ui.label(format!("{} {others}", icon::USERS));
                }
                _ => {
                    ui.weak("Checking who has it…");
                }
            }
            ui.add_space(10.0);

            let local = self
                .transfers
                .iter()
                .find(|t| t.infohash == e.infohash)
                .map(|t| t.kind);
            match local {
                Some(TransferKind::Seed) => {
                    ui.label(format!("{} You're sharing this", icon::CHECK));
                }
                Some(TransferKind::Download) => {
                    ui.label(format!("{} In your transfers", icon::CHECK));
                    if ui.button("Show transfers").clicked() {
                        self.page = crate::app::Page::Transfers;
                    }
                }
                None => {
                    let picked = self.search.files.iter().filter(|f| **f).count();
                    let can = self.backend.has_engine() && picked > 0;
                    ui.horizontal(|ui| {
                        let files = (picked < e.files.len()).then(|| {
                            self.search
                                .files
                                .iter()
                                .enumerate()
                                .filter(|(_, f)| **f)
                                .map(|(i, _)| i)
                                .collect::<Vec<_>>()
                        });
                        if ui
                            .add_enabled(
                                can,
                                egui::Button::new(format!("{} Download", icon::DOWNLOAD_SIMPLE)),
                            )
                            .clicked()
                        {
                            self.start_download(e.infohash.clone(), None, files.clone());
                        }
                        if ui
                            .add_enabled(can, egui::Button::new("To…"))
                            .on_hover_text("Choose where to save it")
                            .clicked()
                            && let Some(dir) = rfd::FileDialog::new()
                                .set_title("Download to")
                                .pick_folder()
                        {
                            self.start_download(e.infohash.clone(), Some(dir), files);
                        }
                    });
                    if !self.backend.has_engine() {
                        ui.weak("Transfers are off right now.");
                    }
                }
            }

            let mine = self.me.as_ref().is_some_and(|m| m.name == e.uploader);
            if mine || self.is_admin() {
                ui.add_space(4.0);
                if ui
                    .button(format!("{} Remove from the index", icon::TRASH))
                    .clicked()
                {
                    self.confirm = Some(Confirm {
                        title: format!("Remove {}?", e.name),
                        text: "Members won't find it any more, and nobody can download it. \
                               Files already downloaded stay where they are."
                            .into(),
                        button: "Remove".into(),
                        cmd: Command::Unpublish {
                            profile: self.profile_arg(),
                            infohash: e.infohash.clone(),
                        },
                        after: After::Search,
                    });
                }
            }

            if e.files.len() > 1 {
                ui.add_space(10.0);
                ui.separator();
                let picking = local.is_none();
                ui.horizontal(|ui| {
                    ui.strong("Files");
                    if picking {
                        if ui.small_button("All").clicked() {
                            self.search.files.iter_mut().for_each(|f| *f = true);
                        }
                        if ui.small_button("None").clicked() {
                            self.search.files.iter_mut().for_each(|f| *f = false);
                        }
                    }
                });
                for (i, f) in e.files.iter().enumerate() {
                    let text = format!("{}  ({})", f.path, format::bytes(f.size));
                    if picking && let Some(on) = self.search.files.get_mut(i) {
                        ui.checkbox(on, text);
                    } else {
                        ui.label(text);
                    }
                }
            }
        });
    }
}
