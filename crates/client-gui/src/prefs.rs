//! Settings: this index, downloads, speed limits, network, the key passphrase and
//! appearance.

use egui::RichText;
use egui_phosphor::regular as icon;
use lemonwire_client_core::Command;

use crate::app::{After, App, Confirm};
use crate::settings::Theme;

#[derive(Default)]
pub struct PrefsPage {
    pub new_passphrase: String,
    pub repeat: String,
}

/// A KiB/s limit field: 0 means unlimited.
fn limit_field(ui: &mut egui::Ui, label: &str, value: &mut Option<u32>) -> bool {
    let mut v = value.unwrap_or(0);
    let changed = ui
        .horizontal(|ui| {
            ui.label(label);
            let r = ui.add(
                egui::DragValue::new(&mut v)
                    .range(0..=1_000_000)
                    .speed(10)
                    .suffix(" KB/s"),
            );
            if v == 0 {
                ui.weak("unlimited");
            }
            r.changed()
        })
        .inner;
    *value = (v > 0).then_some(v);
    changed
}

impl App {
    pub fn prefs_ui(&mut self, ui: &mut egui::Ui) {
        egui::ScrollArea::vertical().show(ui, |ui| {
            ui.heading("Settings");
            ui.add_space(8.0);
            self.profile_section(ui);
            ui.add_space(14.0);

            ui.strong("Downloads");
            ui.horizontal(|ui| {
                let shown = self
                    .settings
                    .download_dir
                    .as_ref()
                    .map_or("Downloads/lemonwire (the default)".to_owned(), |d| {
                        d.display().to_string()
                    });
                ui.label(RichText::new(shown).monospace());
                if ui.button("Change…").clicked()
                    && let Some(dir) = rfd::FileDialog::new()
                        .set_title("Save downloads in")
                        .pick_folder()
                {
                    self.settings.download_dir = Some(dir);
                    self.save_settings();
                }
                if self.settings.download_dir.is_some() && ui.button("Reset").clicked() {
                    self.settings.download_dir = None;
                    self.save_settings();
                }
            });
            ui.add_space(14.0);

            ui.strong("Speed limits");
            let up = limit_field(ui, "Upload", &mut self.settings.upload_kib);
            let down = limit_field(ui, "Download", &mut self.settings.download_kib);
            if up || down {
                self.save_settings();
                if self.backend.has_engine() {
                    self.act(
                        Command::SetLimits {
                            upload_kib: self.settings.upload_kib,
                            download_kib: self.settings.download_kib,
                        },
                        After::Nothing,
                    );
                }
            }
            ui.add_space(14.0);

            ui.strong("Network");
            let mut changed = false;
            ui.horizontal(|ui| {
                ui.label("Port for friends to connect to");
                changed |= ui
                    .add(egui::DragValue::new(&mut self.settings.port).range(1024..=65535))
                    .changed();
            });
            changed |= ui
                .checkbox(
                    &mut self.settings.upnp,
                    "Open the port on my router automatically (UPnP)",
                )
                .changed();
            if changed {
                self.save_settings();
            }
            ui.weak("Network changes apply the next time Lemon Wire starts.");
            ui.add_space(14.0);

            self.passphrase_section(ui);
            ui.add_space(14.0);

            ui.strong("Appearance");
            ui.horizontal(|ui| {
                let before = self.settings.theme;
                for t in [Theme::System, Theme::Light, Theme::Dark] {
                    ui.selectable_value(&mut self.settings.theme, t, t.label());
                }
                if self.settings.theme != before {
                    crate::theme::install(ui.ctx(), self.settings.theme);
                    self.save_settings();
                }
            });
        });
    }

    fn profile_section(&mut self, ui: &mut egui::Ui) {
        let Some(p) = self.current_profile().cloned() else {
            return;
        };
        ui.strong(format!("This index: {}", p.name));
        egui::Grid::new("profile")
            .num_columns(2)
            .spacing([12.0, 4.0])
            .show(ui, |ui| {
                ui.label("Address");
                ui.label(&p.url);
                ui.end_row();
                ui.label("Your name");
                ui.label(p.member_name.as_deref().unwrap_or("–"));
                ui.end_row();
                ui.label("Your key");
                ui.horizontal(|ui| {
                    ui.monospace(&p.public_key_fingerprint);
                    if ui
                        .small_button(icon::COPY)
                        .on_hover_text("Copy your public key")
                        .clicked()
                    {
                        ui.ctx().copy_text(p.public_key.clone());
                        self.toasts.info("Copied your public key");
                    }
                });
                ui.end_row();
                ui.label("Index key");
                ui.monospace(&p.server_fingerprint)
                    .on_hover_text("Check this matches what the admin sees, if in doubt");
                ui.end_row();
            });
        ui.horizontal(|ui| {
            if !p.default && ui.button("Open this index at start").clicked() {
                self.act(
                    Command::ProfileSetDefault {
                        name: p.name.clone(),
                    },
                    After::Profiles,
                );
            }
            if ui
                .button(format!("{} Leave this index…", icon::SIGN_OUT))
                .clicked()
            {
                self.confirm = Some(Confirm {
                    title: format!("Remove {} from this computer?", p.name),
                    text: "This deletes your key for it, so you'd need a new invite to come \
                           back. Your files and downloads stay where they are."
                        .into(),
                    button: "Remove".into(),
                    cmd: Command::ProfileRemove {
                        name: p.name.clone(),
                    },
                    after: After::Profiles,
                });
            }
        });
    }

    fn passphrase_section(&mut self, ui: &mut egui::Ui) {
        let Some(profile) = self.profile.clone() else {
            return;
        };
        ui.strong("Key passphrase");
        ui.label(
            "Protect your key for this index with a passphrase, so someone who copies \
             your files can't use it. You'll be asked for it when Lemon Wire starts.",
        );
        let f = &mut self.prefs;
        ui.horizontal(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut f.new_passphrase)
                    .password(true)
                    .hint_text("New passphrase")
                    .desired_width(180.0),
            );
            ui.add(
                egui::TextEdit::singleline(&mut f.repeat)
                    .password(true)
                    .hint_text("Again")
                    .desired_width(180.0),
            );
        });
        let matches = !f.new_passphrase.is_empty() && f.new_passphrase == f.repeat;
        if !f.repeat.is_empty() && !matches {
            ui.colored_label(ui.visuals().warn_fg_color, "The two don't match.");
        }
        let mut cmd = None;
        ui.horizontal(|ui| {
            if ui
                .add_enabled(
                    matches,
                    egui::Button::new(format!("{} Set passphrase", icon::LOCK)),
                )
                .clicked()
            {
                cmd = Some(Some(std::mem::take(&mut f.new_passphrase)));
                f.repeat.clear();
            }
            if ui.button("Remove passphrase").clicked() {
                cmd = Some(None);
            }
        });
        if let Some(new_passphrase) = cmd {
            self.act(
                Command::KeysProtect {
                    profile,
                    new_passphrase,
                },
                After::Nothing,
            );
        }
    }
}
