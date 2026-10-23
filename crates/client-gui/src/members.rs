//! Admins: members, invites, and adding a member by key.

use egui::RichText;
use egui_extras::{Column, TableBuilder};
use egui_phosphor::regular as icon;
use lemonwire_client_core::{Command, Invite, Member, Output};
use lemonwire_proto::keys;

use crate::app::{After, App, Confirm};
use crate::backend::{Task, poll};
use crate::format;

pub struct MembersPage {
    loaded: bool,
    pub members: Vec<Member>,
    pub invites: Vec<Invite>,
    members_task: Option<Task>,
    invites_task: Option<Task>,
    pub invite_admin: bool,
    pub invite_days: u32,
    invite_task: Option<Task>,
    /// The code just created: shown once, the index keeps only its hash.
    pub new_code: Option<String>,
    pub add_key: String,
    pub add_name: String,
    pub add_admin: bool,
    add_task: Option<Task>,
}

impl Default for MembersPage {
    fn default() -> Self {
        Self {
            loaded: false,
            members: vec![],
            invites: vec![],
            members_task: None,
            invites_task: None,
            invite_admin: false,
            invite_days: 7,
            invite_task: None,
            new_code: None,
            add_key: String::new(),
            add_name: String::new(),
            add_admin: false,
            add_task: None,
        }
    }
}

impl App {
    fn poll_members(&mut self) {
        if !self.members.loaded {
            self.members.loaded = true;
            self.members.members_task = Some(self.backend.run(Command::MembersList {
                profile: self.profile_arg(),
            }));
            self.members.invites_task = Some(self.backend.run(Command::InviteList {
                profile: self.profile_arg(),
            }));
        }
        match poll(&mut self.members.members_task) {
            Some(Ok(Output::Members { members })) => self.members.members = members,
            Some(Err(e)) => self.error(e),
            _ => {}
        }
        match poll(&mut self.members.invites_task) {
            Some(Ok(Output::Invites { invites })) => self.members.invites = invites,
            Some(Err(e)) => self.error(e),
            _ => {}
        }
        match poll(&mut self.members.invite_task) {
            Some(Ok(Output::Invite { invite })) => {
                self.members.new_code = invite.code;
                self.members.invites_task = Some(self.backend.run(Command::InviteList {
                    profile: self.profile_arg(),
                }));
            }
            Some(Err(e)) => self.error(e),
            _ => {}
        }
        match poll(&mut self.members.add_task) {
            Some(Ok(Output::Member { member })) => {
                self.toasts.success(format!("Added {}", member.name));
                self.members.add_key.clear();
                self.members.add_name.clear();
                self.members.add_admin = false;
                self.members.loaded = false;
            }
            Some(Err(e)) => self.error(e),
            _ => {}
        }
    }

    pub fn members_ui(&mut self, ui: &mut egui::Ui) {
        self.poll_members();
        let now = format::now();
        egui::ScrollArea::vertical().show(ui, |ui| {
            ui.heading("Invite a friend");
            ui.label(
                "Send them the code together with this index's address. Each code \
                 works once.",
            );
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.label("Expires after");
                ui.add(
                    egui::DragValue::new(&mut self.members.invite_days)
                        .range(1..=90)
                        .suffix(" days"),
                );
                ui.checkbox(&mut self.members.invite_admin, "Make them an admin");
                let busy = self.members.invite_task.is_some();
                if ui
                    .add_enabled(
                        !busy,
                        egui::Button::new(format!("{} Create invite", icon::TICKET)),
                    )
                    .clicked()
                {
                    self.members.new_code = None;
                    self.members.invite_task = Some(self.backend.run(Command::InviteCreate {
                        profile: self.profile_arg(),
                        admin: self.members.invite_admin,
                        ttl_hours: Some(self.members.invite_days * 24),
                    }));
                }
            });
            if let Some(code) = self.members.new_code.clone() {
                let url = self
                    .current_profile()
                    .map(|p| p.url.clone())
                    .unwrap_or_default();
                egui::Frame::group(ui.style()).show(ui, |ui| {
                    ui.label("Send this to your friend (you won't see the code again):");
                    let message =
                        format!("Join my Lemon Wire index!\nAddress: {url}\nInvite code: {code}");
                    ui.label(RichText::new(&message).monospace());
                    if ui.button(format!("{} Copy", icon::COPY)).clicked() {
                        ui.ctx().copy_text(message);
                        self.toasts.info("Copied the invite");
                    }
                });
            }

            ui.add_space(16.0);
            ui.heading("Members");
            ui.add_space(4.0);
            let members = self.members.members.clone();
            let my_key = self.current_profile().map(|p| p.public_key.clone());
            let mut revoke = None;
            TableBuilder::new(ui)
                .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                .id_salt("members")
                .striped(true)
                .vscroll(false)
                .column(Column::remainder().at_least(120.0))
                .column(Column::auto().at_least(60.0))
                .column(Column::auto().at_least(110.0))
                .column(Column::auto().at_least(90.0))
                .column(Column::auto().at_least(70.0))
                .header(22.0, |mut h| {
                    for title in ["Name", "", "Key", "Joined", ""] {
                        h.col(|ui| {
                            ui.strong(title);
                        });
                    }
                })
                .body(|mut body| {
                    for m in &members {
                        body.row(24.0, |mut row| {
                            row.col(|ui| {
                                ui.label(&m.name);
                            });
                            row.col(|ui| {
                                if m.is_admin {
                                    ui.weak("admin");
                                }
                            });
                            row.col(|ui| {
                                ui.monospace(keys::fingerprint(&m.pubkey))
                                    .on_hover_text(&m.pubkey);
                            });
                            row.col(|ui| {
                                ui.label(format::ago(m.created_at, now));
                            });
                            row.col(|ui| {
                                let me = my_key.as_deref() == Some(m.pubkey.as_str());
                                if !me && ui.small_button("Revoke").clicked() {
                                    revoke = Some(m.clone());
                                }
                            });
                        });
                    }
                });
            if let Some(m) = revoke {
                self.confirm = Some(Confirm {
                    title: format!("Revoke {}?", m.name),
                    text: "Their key stops working straight away: they can no longer \
                           search, download or share here. What they shared stays listed."
                        .into(),
                    button: "Revoke".into(),
                    cmd: Command::MembersRevoke {
                        profile: self.profile_arg(),
                        member: m.pubkey,
                    },
                    after: After::Members,
                });
            }

            let open: Vec<_> = self
                .members
                .invites
                .iter()
                .filter(|i| i.used_by.is_none() && i.expires_at > now)
                .cloned()
                .collect();
            if !open.is_empty() {
                ui.add_space(16.0);
                ui.heading("Unused invites");
                for i in open {
                    ui.label(format!(
                        "{}{} · expires in {} days",
                        i.id,
                        if i.is_admin { " (admin)" } else { "" },
                        ((i.expires_at - now + 86_399) / 86_400).max(1)
                    ));
                }
            }

            ui.add_space(16.0);
            egui::CollapsingHeader::new("Add someone by their key").show(ui, |ui| {
                ui.label("For friends who sent you their public key instead of using an invite.");
                ui.add(
                    egui::TextEdit::singleline(&mut self.members.add_key)
                        .hint_text("Their public key")
                        .desired_width(f32::INFINITY),
                );
                ui.add(
                    egui::TextEdit::singleline(&mut self.members.add_name)
                        .hint_text("Their name")
                        .desired_width(f32::INFINITY),
                );
                ui.checkbox(&mut self.members.add_admin, "Admin");
                let ready = !self.members.add_key.trim().is_empty()
                    && !self.members.add_name.trim().is_empty()
                    && self.members.add_task.is_none();
                if ui
                    .add_enabled(ready, egui::Button::new(format!("{} Add", icon::USER_PLUS)))
                    .clicked()
                {
                    self.members.add_task = Some(self.backend.run(Command::MembersAdd {
                        profile: self.profile_arg(),
                        pubkey: self.members.add_key.trim().to_owned(),
                        name: self.members.add_name.trim().to_owned(),
                        admin: self.members.add_admin,
                    }));
                }
            });
        });
    }
}
