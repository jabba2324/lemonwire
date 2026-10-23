//! Joining an index: with an invite code (the usual way), or by sending your key to
//! the admin first.

use egui::RichText;
use egui_phosphor::regular as icon;
use lemonwire_client_core::{ClientError, Command, Output, ProfileView};

use crate::app::App;
use crate::backend::{Task, poll};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Invite,
    Key,
}

pub struct JoinForm {
    pub mode: Mode,
    pub url: String,
    pub invite: String,
    pub name: String,
    pub profile: String,
    profile_edited: bool,
    pub server_key: String,
    pub insecure: bool,
    taken: Vec<String>,
    /// Your public key (key mode, once generated).
    pub public_key: Option<String>,
    task: Option<Task>,
    key_task: Option<Task>,
    pub error: Option<String>,
    /// Added, but the index doesn't know this key yet (key mode).
    pub waiting: bool,
}

impl JoinForm {
    pub fn new(profiles: &[ProfileView]) -> Self {
        Self {
            mode: Mode::Invite,
            url: String::new(),
            invite: String::new(),
            name: String::new(),
            profile: String::new(),
            profile_edited: false,
            server_key: String::new(),
            insecure: false,
            taken: profiles.iter().map(|p| p.name.clone()).collect(),
            public_key: None,
            task: None,
            key_task: None,
            error: None,
            waiting: false,
        }
    }

    fn suggest_profile(&mut self) {
        if !self.profile_edited {
            self.profile = profile_name(&self.url, &self.taken);
        }
    }
}

/// A local label for an index from its address: `https://files.example.org` → `files`.
pub fn profile_name(url: &str, taken: &[String]) -> String {
    let host = url
        .trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    let first = host
        .split(['.', ':', '/'])
        .find(|s| !s.is_empty() && *s != "www")
        // An IP address or localhost says nothing about the group.
        .filter(|s| *s != "localhost" && !s.starts_with(|c: char| c.is_ascii_digit() || c == '['))
        .unwrap_or("index");
    let mut base: String = first
        .chars()
        .map(|c| c.to_ascii_lowercase())
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .take(32)
        .collect();
    if base.is_empty() {
        base = "index".into();
    }
    let mut name = base.clone();
    let mut n = 2;
    while taken.contains(&name) {
        name = format!("{base}-{n}");
        n += 1;
    }
    name
}

fn wide<'a>(s: &'a mut String, hint: &str) -> egui::TextEdit<'a> {
    egui::TextEdit::singleline(s)
        .hint_text(hint.to_owned())
        .desired_width(f32::INFINITY)
}

impl App {
    pub fn join_ui(&mut self, ui: &mut egui::Ui) {
        let Some(mut f) = self.join.take() else {
            return;
        };
        let mut close = false;
        self.poll_join(&mut f, &mut close);

        egui::ScrollArea::vertical().show(ui, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(24.0);
                ui.label(
                    RichText::new(icon::LIGHTNING)
                        .size(40.0)
                        .color(crate::theme::LEMON),
                );
                ui.heading("Join an index");
                ui.label("An index is a private group where friends share files with each other.");
                ui.add_space(16.0);
            });
            // A centred, left-aligned column.
            let width = ui.available_width().min(460.0);
            let pad = (ui.available_width() - width) / 2.0;
            ui.horizontal_top(|ui| {
                ui.add_space(pad);
                ui.vertical(|ui| {
                    ui.set_width(width);
                    ui.horizontal(|ui| {
                        ui.selectable_value(&mut f.mode, Mode::Invite, "I have an invite");
                        ui.selectable_value(&mut f.mode, Mode::Key, "The admin will add me");
                    });
                    ui.add_space(10.0);
                    let busy = f.task.is_some();
                    ui.add_enabled_ui(!busy, |ui| self.join_fields(ui, &mut f));
                    ui.add_space(12.0);
                    if let Some(e) = &f.error {
                        ui.colored_label(ui.visuals().error_fg_color, e);
                        ui.add_space(8.0);
                    }
                    ui.horizontal(|ui| {
                        let ready = match f.mode {
                            Mode::Invite => {
                                !f.url.trim().is_empty()
                                    && !f.invite.trim().is_empty()
                                    && !f.name.trim().is_empty()
                            }
                            Mode::Key => f.public_key.is_some() && !f.url.trim().is_empty(),
                        };
                        let label = match f.mode {
                            Mode::Invite => "Join",
                            Mode::Key if f.waiting => "Check again",
                            Mode::Key => "Connect",
                        };
                        if ui
                            .add_enabled(ready && !busy, egui::Button::new(label))
                            .clicked()
                        {
                            self.submit_join(&mut f);
                        }
                        if busy {
                            ui.spinner();
                        }
                        if !self.profiles.is_empty() && ui.button("Cancel").clicked() {
                            close = true;
                        }
                    });
                });
            });
        });
        if !close {
            self.join = Some(f);
        }
    }

    fn join_fields(&mut self, ui: &mut egui::Ui, f: &mut JoinForm) {
        if f.mode == Mode::Key {
            ui.label(
                "Send your public key to the index's admin. Once they've added you, \
                 connect below.",
            );
            ui.add_space(6.0);
            if f.profile.is_empty() {
                f.profile = profile_name("", &f.taken);
            }
            match &f.public_key {
                Some(k) => {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(k).monospace());
                        if ui.button(icon::COPY).on_hover_text("Copy").clicked() {
                            ui.ctx().copy_text(k.clone());
                            self.toasts.info("Copied your public key");
                        }
                    });
                }
                None => {
                    if ui.button(format!("{} Create my key", icon::KEY)).clicked()
                        && f.key_task.is_none()
                    {
                        f.key_task = Some(self.backend.run(Command::KeysGenerate {
                            profile: f.profile.clone(),
                        }));
                    }
                }
            }
            ui.add_space(10.0);
        }

        let label = ui.label("Index address");
        if ui
            .add(wide(&mut f.url, "https://files.example.org"))
            .labelled_by(label.id)
            .changed()
            && f.mode == Mode::Invite
        {
            f.suggest_profile();
        }
        ui.add_space(6.0);
        match f.mode {
            Mode::Invite => {
                let label = ui.label("Invite code");
                ui.add(wide(&mut f.invite, "lw1.…")).labelled_by(label.id);
                ui.add_space(6.0);
                let label = ui.label("Your name in the group");
                ui.add(wide(&mut f.name, "Sam")).labelled_by(label.id);
            }
            Mode::Key => {
                let label = ui.label("Index key (optional: the admin can give you this)");
                ui.add(wide(&mut f.server_key, "")).labelled_by(label.id);
            }
        }
        ui.add_space(6.0);
        egui::CollapsingHeader::new("More options").show(ui, |ui| {
            ui.label("Label for this index on this computer");
            let locked = f.mode == Mode::Key && f.public_key.is_some();
            if ui
                .add_enabled(!locked, wide(&mut f.profile, "files"))
                .changed()
            {
                f.profile_edited = true;
            }
            ui.checkbox(
                &mut f.insecure,
                "Allow an unencrypted (http://) address on the internet",
            );
        });
    }

    fn submit_join(&mut self, f: &mut JoinForm) {
        f.error = None;
        let cmd = match f.mode {
            Mode::Invite => Command::ProfileAdd {
                profile: f.profile.clone(),
                url: f.url.trim().to_owned(),
                server_key: None,
                invite: Some(f.invite.trim().to_owned()),
                member_name: Some(f.name.trim().to_owned()),
                allow_insecure: f.insecure,
            },
            Mode::Key if f.waiting => Command::Whoami {
                profile: Some(f.profile.clone()),
            },
            Mode::Key => Command::ProfileAdd {
                profile: f.profile.clone(),
                url: f.url.trim().to_owned(),
                server_key: Some(f.server_key.trim().to_owned()).filter(|k| !k.is_empty()),
                invite: None,
                member_name: None,
                allow_insecure: f.insecure,
            },
        };
        f.task = Some(self.backend.run(cmd));
    }

    fn poll_join(&mut self, f: &mut JoinForm, close: &mut bool) {
        if let Some(r) = poll(&mut f.key_task) {
            match r {
                Ok(Output::PublicKey { public_key, .. }) => f.public_key = Some(public_key),
                Ok(_) => {}
                Err(e) => f.error = Some(e.to_string()),
            }
        }
        let Some(r) = poll(&mut f.task) else {
            return;
        };
        match r {
            Ok(Output::ProfileAdded {
                member: true,
                profile,
                ..
            })
            | Ok(Output::Me { profile, .. }) => {
                self.toasts.success(format!("Joined {}", profile.name));
                self.profile = Some(profile.name);
                self.load_profiles();
                *close = true;
            }
            Ok(Output::ProfileAdded { member: false, .. }) => {
                f.waiting = true;
                self.load_profiles();
                f.error = Some(
                    "Connected, but the admin hasn't added your key yet. Ask them to, \
                     then check again."
                        .into(),
                );
            }
            Ok(_) => {}
            Err(ClientError::NotAMember) => {
                f.error = Some("The admin hasn't added your key yet.".into());
            }
            Err(e) => f.error = Some(e.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::profile_name;

    #[test]
    fn profile_names_from_addresses() {
        let none: Vec<String> = vec![];
        assert_eq!(profile_name("https://files.example.org", &none), "files");
        assert_eq!(profile_name("https://www.Lemons.example/", &none), "lemons");
        assert_eq!(profile_name("http://192.168.1.5:8080", &none), "index");
        assert_eq!(profile_name("http://localhost:8080", &none), "index");
        assert_eq!(profile_name("", &none), "index");
        let taken = vec!["files".to_owned(), "files-2".to_owned()];
        assert_eq!(profile_name("https://files.example.org", &taken), "files-3");
    }
}
