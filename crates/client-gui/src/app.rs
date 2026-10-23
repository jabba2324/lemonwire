//! The app: state, the frame loop, the sidebar and the dialogs. Each page lives in
//! its own module as more `impl App` blocks.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use egui::{Align, Layout, RichText};
use egui_phosphor::regular as icon;
use lemonwire_client_core::{
    ClientError, Command, Event, Member, Output, ProfileView, SeedUntil, TransferView,
};

use crate::backend::{Backend, Task, poll};
use crate::members::MembersPage;
use crate::search::SearchPage;
use crate::settings::{Settings, Theme};
use crate::{format, theme};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Page {
    Search,
    Transfers,
    Members,
    Settings,
}

/// What to reload after a background action succeeds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum After {
    Nothing,
    Profiles,
    Members,
    Search,
}

/// Something to confirm before running it.
pub struct Confirm {
    pub title: String,
    pub text: String,
    pub button: String,
    pub cmd: Command,
    pub after: After,
}

pub struct ShareDialog {
    pub path: PathBuf,
    pub tags: String,
    pub task: Option<Task>,
    /// Hashing progress (done, total bytes).
    pub hashed: Option<(u64, u64)>,
    pub error: Option<String>,
    focused: bool,
}

#[derive(Default)]
pub struct UnlockDialog {
    pub passphrase: String,
    pub error: Option<String>,
    pub task: Option<Task>,
    /// Focus the field once, when the dialog opens (not every frame: on X11 that
    /// restarts input-method handling each frame and drops typing).
    focused: bool,
}

pub struct App {
    pub backend: Backend,
    pub settings: Settings,
    pub toasts: egui_notify::Toasts,

    pub profiles: Vec<ProfileView>,
    pub profiles_loaded: bool,
    profiles_task: Option<Task>,
    /// The selected profile's name.
    pub profile: Option<String>,
    /// Your membership on the selected index.
    pub me: Option<Member>,
    me_task: Option<Task>,

    pub page: Page,
    pub join: Option<crate::join::JoinForm>,
    pub search: SearchPage,
    pub members: MembersPage,
    pub prefs: crate::prefs::PrefsPage,

    pub transfers: Vec<TransferView>,
    transfers_task: Option<Task>,
    transfers_polled: Option<Instant>,
    /// Downloads started from this app, by infohash.
    pub downloads: Vec<(String, Task)>,

    /// Background actions: (what to reload after, the task).
    actions: Vec<(After, Task)>,
    pub confirm: Option<Confirm>,
    pub share: Option<ShareDialog>,
    pub unlock: Option<UnlockDialog>,
    quit_dialog: bool,
    quitting: bool,
}

impl App {
    pub fn new(ctx: &egui::Context, config: lemonwire_client_core::ConfigDir) -> Self {
        let settings = Settings::load(config.root());
        theme::install(ctx, settings.theme);
        let backend = Backend::start(ctx.clone(), config, &settings);
        let mut app = Self {
            backend,
            profile: settings.profile.clone(),
            settings,
            toasts: egui_notify::Toasts::default(),
            profiles: vec![],
            profiles_loaded: false,
            profiles_task: None,
            me: None,
            me_task: None,
            page: Page::Search,
            join: None,
            search: SearchPage::default(),
            members: MembersPage::default(),
            prefs: Default::default(),
            transfers: vec![],
            transfers_task: None,
            transfers_polled: None,
            downloads: vec![],
            actions: vec![],
            confirm: None,
            share: None,
            unlock: None,
            quit_dialog: false,
            quitting: false,
        };
        app.load_profiles();
        app
    }

    // ---- helpers for pages ---------------------------------------------------

    pub fn profile_arg(&self) -> Option<String> {
        self.profile.clone()
    }

    pub fn current_profile(&self) -> Option<&ProfileView> {
        let name = self.profile.as_deref()?;
        self.profiles.iter().find(|p| p.name == name)
    }

    pub fn is_admin(&self) -> bool {
        self.me.as_ref().is_some_and(|m| m.is_admin)
    }

    /// Run a command whose result is just shown as a toast.
    pub fn act(&mut self, cmd: Command, after: After) {
        self.actions.push((after, self.backend.run(cmd)));
    }

    /// Show an error; a locked key opens the unlock dialog instead.
    pub fn error(&mut self, e: ClientError) {
        match e {
            ClientError::PassphraseRequired => {
                if self.unlock.is_none() {
                    self.unlock = Some(UnlockDialog::default());
                }
            }
            ClientError::Cancelled => {}
            e => {
                self.toasts
                    .error(e.to_string())
                    .duration(Some(Duration::from_secs(8)));
            }
        }
    }

    pub fn save_settings(&mut self) {
        if let Err(e) = self.settings.save(self.backend.config.root()) {
            self.toasts.error(format!("Couldn't save settings: {e}"));
        }
    }

    pub fn load_profiles(&mut self) {
        self.profiles_task = Some(self.backend.run(Command::ProfileList));
    }

    pub fn select_profile(&mut self, name: Option<String>) {
        self.profile = name;
        self.me = None;
        self.search = SearchPage::default();
        self.members = MembersPage::default();
        if self.page == Page::Members {
            self.page = Page::Search;
        }
        if self.profile.is_some() {
            self.me_task = Some(self.backend.run(Command::Whoami {
                profile: self.profile_arg(),
            }));
            self.search_now(false);
        }
        if self.settings.profile != self.profile {
            self.settings.profile = self.profile.clone();
            self.save_settings();
        }
    }

    pub fn start_share(&mut self, path: PathBuf) {
        self.share = Some(ShareDialog {
            path,
            tags: String::new(),
            task: None,
            hashed: None,
            error: None,
            focused: false,
        });
    }

    pub fn start_download(
        &mut self,
        infohash: String,
        dest: Option<PathBuf>,
        files: Option<Vec<usize>>,
    ) {
        let cmd = Command::Download {
            profile: self.profile_arg(),
            infohash: infohash.clone(),
            dest: dest.or_else(|| self.settings.download_dir.clone()),
            files,
            // The app keeps serving while open, so no separate seed-back phase.
            seed_back: None,
        };
        self.downloads.push((infohash, self.backend.run(cmd)));
        self.poll_transfers_soon();
    }

    pub fn poll_transfers_soon(&mut self) {
        self.transfers_polled = None;
    }

    // ---- the frame -------------------------------------------------------------

    fn handle_events(&mut self) {
        let events: Vec<Event> = self.backend.events().collect();
        for e in events {
            match e {
                Event::Hashing { done, total, .. } => {
                    if let Some(s) = &mut self.share {
                        s.hashed = Some((done, total));
                    }
                }
                Event::DownloadFinished { name, .. } => {
                    self.toasts
                        .success(format!("Downloaded {name}"))
                        .duration(Some(Duration::from_secs(6)));
                    self.poll_transfers_soon();
                }
                Event::TransferAdded { .. } | Event::TransferRemoved { .. } => {
                    self.poll_transfers_soon();
                }
                _ => {}
            }
        }
    }

    fn poll_tasks(&mut self) {
        if let Some(r) = poll(&mut self.profiles_task) {
            match r {
                Ok(Output::Profiles { profiles }) => {
                    self.profiles = profiles;
                    self.profiles_loaded = true;
                    let keep = self
                        .profile
                        .as_ref()
                        .filter(|n| self.profiles.iter().any(|p| &p.name == *n))
                        .cloned();
                    let pick = keep
                        .or_else(|| {
                            self.profiles
                                .iter()
                                .find(|p| p.default)
                                .map(|p| p.name.clone())
                        })
                        .or_else(|| self.profiles.first().map(|p| p.name.clone()));
                    if pick != self.profile || self.me.is_none() {
                        self.select_profile(pick);
                    }
                }
                Ok(_) => {}
                Err(e) => {
                    self.profiles_loaded = true;
                    self.error(e);
                }
            }
        }
        if let Some(r) = poll(&mut self.me_task) {
            match r {
                Ok(Output::Me { member, profile }) => {
                    self.me = Some(member);
                    if let Some(p) = self.profiles.iter_mut().find(|p| p.name == profile.name) {
                        *p = profile;
                    }
                }
                Ok(_) => {}
                Err(ClientError::NotAMember) => {
                    self.toasts
                        .warning(
                            "You're not a member of this index yet: send your key to its admin",
                        )
                        .duration(Some(Duration::from_secs(10)));
                }
                Err(e) => self.error(e),
            }
        }
        if let Some(r) = poll(&mut self.transfers_task)
            && let Ok(Output::Transfers { transfers }) = r
        {
            self.transfers = transfers;
        }
        let mut finished = vec![];
        self.downloads.retain(|(_, t)| match t.take() {
            Some(r) => {
                finished.push(r);
                false
            }
            None => true,
        });
        for r in finished {
            if let Err(e) = r {
                self.error(e);
            }
        }
        let mut done = vec![];
        self.actions.retain(|(after, t)| match t.take() {
            Some(r) => {
                done.push((*after, r));
                false
            }
            None => true,
        });
        for (after, r) in done {
            match r {
                Ok(Output::Done { message }) => {
                    self.toasts.success(message);
                }
                Ok(_) => {}
                Err(e) => {
                    self.error(e);
                    continue;
                }
            }
            self.poll_transfers_soon();
            match after {
                After::Nothing => {}
                After::Profiles => self.load_profiles(),
                After::Members => self.members = MembersPage::default(),
                After::Search => self.search_now(false),
            }
        }
        // Keep the transfer list (and the status bar) fresh.
        let due = self
            .transfers_polled
            .is_none_or(|t| t.elapsed() >= Duration::from_secs(1));
        if due && self.transfers_task.is_none() {
            self.transfers_polled = Some(Instant::now());
            self.transfers_task = Some(self.backend.run(Command::Transfers));
        }
    }

    fn handle_close(&mut self, ctx: &egui::Context) {
        if !ctx.input(|i| i.viewport().close_requested()) || self.quitting {
            return;
        }
        let sharing = self.transfers.iter().any(|t| t.status.is_some());
        if sharing {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            self.quit_dialog = true;
        } else {
            self.quitting = true;
        }
    }

    fn sidebar(&mut self, ui: &mut egui::Ui) {
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.label(
                RichText::new(icon::LIGHTNING)
                    .size(22.0)
                    .color(theme::LEMON),
            );
            ui.heading("Lemon Wire");
        });
        ui.add_space(8.0);

        let current = self.profile.clone().unwrap_or_default();
        let label = self
            .current_profile()
            .map_or(current.clone(), |p| p.name.clone());
        let mut pick = None;
        egui::ComboBox::from_id_salt("profile")
            .width(ui.available_width())
            .selected_text(label)
            .show_ui(ui, |ui| {
                for p in &self.profiles {
                    if ui.selectable_label(p.name == current, &p.name).clicked() {
                        pick = Some(p.name.clone());
                    }
                }
                ui.separator();
                if ui
                    .button(format!("{} Join another index…", icon::PLUS))
                    .clicked()
                {
                    pick = Some(String::new());
                }
            });
        match pick {
            Some(n) if n.is_empty() => self.join = Some(crate::join::JoinForm::new(&self.profiles)),
            Some(n) if n != current => self.select_profile(Some(n)),
            _ => {}
        }
        if let Some(me) = &self.me {
            ui.weak(format!("Signed in as {}", me.name));
        }
        ui.add_space(12.0);

        let share = ui.add_enabled(
            self.profile.is_some(),
            egui::Button::new(format!("{} Share…", icon::UPLOAD_SIMPLE))
                .min_size(egui::vec2(ui.available_width(), 32.0)),
        );
        egui::Popup::menu(&share).show(|ui| {
            if ui.button(format!("{} A file…", icon::FILE)).clicked()
                && let Some(p) = rfd::FileDialog::new().set_title("Share a file").pick_file()
            {
                self.start_share(p);
            }
            if ui.button(format!("{} A folder…", icon::FOLDER)).clicked()
                && let Some(p) = rfd::FileDialog::new()
                    .set_title("Share a folder")
                    .pick_folder()
            {
                self.start_share(p);
            }
        });
        ui.add_space(12.0);

        let admin = self.is_admin();
        let mut nav = |ui: &mut egui::Ui, page: Page, text: String| {
            let r = ui
                .with_layout(Layout::top_down_justified(Align::Min), |ui| {
                    ui.add(
                        egui::Button::selectable(self.page == page, text)
                            .min_size(egui::vec2(0.0, 28.0)),
                    )
                })
                .inner;
            if r.clicked() {
                self.page = page;
            }
        };
        nav(
            ui,
            Page::Search,
            format!("{}  Browse", icon::MAGNIFYING_GLASS),
        );
        let active = self.transfers.len();
        nav(
            ui,
            Page::Transfers,
            if active > 0 {
                format!("{}  Transfers ({active})", icon::ARROWS_DOWN_UP)
            } else {
                format!("{}  Transfers", icon::ARROWS_DOWN_UP)
            },
        );
        if admin {
            nav(ui, Page::Members, format!("{}  Members", icon::USERS));
        }
        nav(ui, Page::Settings, format!("{}  Settings", icon::GEAR));

        ui.with_layout(Layout::bottom_up(Align::Min), |ui| {
            ui.add_space(8.0);
            let live: Vec<_> = self
                .transfers
                .iter()
                .filter_map(|t| t.status.as_ref())
                .collect();
            let up: u64 = live.iter().map(|s| s.upload_bps).sum();
            let down: u64 = live.iter().map(|s| s.download_bps).sum();
            let peers: u32 = live.iter().map(|s| s.peers).sum();
            ui.weak(format!(
                "{} {}   {} {}   {} {peers}",
                icon::ARROW_UP,
                format::speed(up),
                icon::ARROW_DOWN,
                format::speed(down),
                icon::USERS
            ));
            if self.backend.has_engine() {
                let shared = self.transfers.iter().filter(|t| t.status.is_some()).count();
                ui.weak(format!("Serving {shared} while open"));
            } else {
                ui.colored_label(ui.visuals().warn_fg_color, "Transfers are off");
            }
        });
    }

    fn engine_banner(&mut self, ui: &mut egui::Ui) {
        let Some(why) = self.backend.engine_error.clone() else {
            return;
        };
        egui::Frame::group(ui.style())
            .fill(ui.visuals().extreme_bg_color)
            .show(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.colored_label(ui.visuals().warn_fg_color, icon::WARNING);
                    ui.label(why);
                    if ui.button("Try again").clicked() {
                        self.backend.reopen(&self.settings);
                        self.poll_transfers_soon();
                    }
                });
            });
        ui.add_space(8.0);
    }

    fn dialogs(&mut self, ctx: &egui::Context) {
        self.share_dialog(ctx);
        self.unlock_dialog(ctx);
        self.confirm_dialog(ctx);
        self.quit_dialog(ctx);
    }

    fn share_dialog(&mut self, ctx: &egui::Context) {
        let Some(mut s) = self.share.take() else {
            return;
        };
        if let Some(r) = poll(&mut s.task) {
            match r {
                Ok(Output::Shared {
                    entry,
                    already_indexed,
                    ..
                }) => {
                    let msg = if already_indexed {
                        format!(
                            "{} was already in the index; serving it while Lemon Wire is open",
                            entry.name
                        )
                    } else {
                        format!(
                            "Shared {}: friends can download it while Lemon Wire is open",
                            entry.name
                        )
                    };
                    self.toasts
                        .success(msg)
                        .duration(Some(Duration::from_secs(8)));
                    self.search_now(false);
                    self.poll_transfers_soon();
                    return;
                }
                Ok(_) => return,
                Err(ClientError::Cancelled) => return,
                Err(ClientError::PassphraseRequired) => {
                    self.error(ClientError::PassphraseRequired);
                    s.hashed = None;
                }
                Err(e) => {
                    s.error = Some(e.to_string());
                    s.hashed = None;
                }
            }
        }
        let mut keep = true;
        egui::Modal::new(egui::Id::new("share")).show(ctx, |ui| {
            ui.set_width(420.0);
            ui.heading("Share with this index");
            ui.add_space(6.0);
            ui.label(RichText::new(s.path.display().to_string()).monospace());
            ui.add_space(8.0);
            let running = s.task.is_some();
            ui.add_enabled_ui(!running, |ui| {
                let label = ui.label("Tags (optional, separated by commas)");
                let edit = ui
                    .add(
                        egui::TextEdit::singleline(&mut s.tags)
                            .hint_text("photos, holiday")
                            .desired_width(f32::INFINITY),
                    )
                    .labelled_by(label.id);
                if !s.focused {
                    edit.request_focus();
                    s.focused = true;
                }
            });
            if let Some((done, total)) = s.hashed {
                ui.add_space(8.0);
                let f = if total == 0 {
                    0.0
                } else {
                    done as f32 / total as f32
                };
                ui.add(egui::ProgressBar::new(f).text(format!(
                    "Preparing: {} of {}",
                    format::bytes(done),
                    format::bytes(total)
                )));
            } else if running {
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label("Preparing…");
                });
            }
            if let Some(e) = &s.error {
                ui.add_space(6.0);
                ui.colored_label(ui.visuals().error_fg_color, e);
            }
            if !self.backend.has_engine() {
                ui.add_space(6.0);
                ui.weak("Transfers are off, so this only adds it to the index for now.");
            }
            ui.add_space(10.0);
            ui.horizontal(|ui| {
                if running {
                    if ui.button("Stop").clicked()
                        && let Some(t) = &s.task
                    {
                        t.cancel();
                    }
                } else {
                    if ui
                        .button(format!("{} Share", icon::UPLOAD_SIMPLE))
                        .clicked()
                    {
                        s.error = None;
                        let tags = s
                            .tags
                            .split(',')
                            .map(|t| t.trim().to_owned())
                            .filter(|t| !t.is_empty())
                            .collect();
                        s.task = Some(self.backend.run(Command::Share {
                            profile: self.profile_arg(),
                            path: s.path.clone(),
                            tags,
                            // Published here; the app's Seed serves it while open.
                            until: SeedUntil::PublishOnly,
                        }));
                    }
                    if ui.button("Cancel").clicked() {
                        keep = false;
                    }
                }
            });
        });
        if keep {
            self.share = Some(s);
        }
    }

    fn unlock_dialog(&mut self, ctx: &egui::Context) {
        let Some(mut d) = self.unlock.take() else {
            return;
        };
        if let Some(r) = poll(&mut d.task) {
            match r {
                Ok(_) => {
                    self.toasts.success("Unlocked");
                    // Retry what needed the key.
                    let profile = self.profile.clone();
                    self.select_profile(profile);
                    return;
                }
                Err(ClientError::WrongPassphrase) => {
                    d.error = Some("That passphrase didn't open your key.".into());
                    d.focused = false;
                    self.backend.set_passphrase(None);
                }
                Err(e) => {
                    d.error = Some(e.to_string());
                }
            }
        }
        let mut keep = true;
        egui::Modal::new(egui::Id::new("unlock")).show(ctx, |ui| {
            ui.set_width(360.0);
            ui.heading(format!("{} Unlock your key", icon::LOCK));
            ui.label("Your key for this index is protected with a passphrase.");
            ui.add_space(8.0);
            let edit = ui.add(
                egui::TextEdit::singleline(&mut d.passphrase)
                    .password(true)
                    .hint_text("Passphrase")
                    .desired_width(f32::INFINITY),
            );
            if !d.focused {
                edit.request_focus();
                d.focused = true;
            }
            if let Some(e) = &d.error {
                ui.colored_label(ui.visuals().error_fg_color, e);
            }
            ui.add_space(8.0);
            let enter = edit.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            ui.horizontal(|ui| {
                let busy = d.task.is_some();
                if (ui.add_enabled(!busy, egui::Button::new("Unlock")).clicked() || enter) && !busy
                {
                    d.error = None;
                    self.backend
                        .set_passphrase(Some(std::mem::take(&mut d.passphrase)));
                    d.task = Some(self.backend.run(Command::Whoami {
                        profile: self.profile_arg(),
                    }));
                }
                if busy {
                    ui.spinner();
                }
                if ui.button("Not now").clicked() {
                    keep = false;
                }
            });
        });
        if keep {
            self.unlock = Some(d);
        }
    }

    fn confirm_dialog(&mut self, ctx: &egui::Context) {
        let Some(c) = self.confirm.take() else {
            return;
        };
        let mut answer = None;
        egui::Modal::new(egui::Id::new("confirm")).show(ctx, |ui| {
            ui.set_width(380.0);
            ui.heading(&c.title);
            ui.add_space(4.0);
            ui.label(&c.text);
            ui.add_space(10.0);
            ui.horizontal(|ui| {
                if ui.button(&c.button).clicked() {
                    answer = Some(true);
                }
                if ui.button("Cancel").clicked() {
                    answer = Some(false);
                }
            });
        });
        match answer {
            Some(true) => self.act(c.cmd, c.after),
            Some(false) => {}
            None => self.confirm = Some(c),
        }
    }

    fn quit_dialog(&mut self, ctx: &egui::Context) {
        if !self.quit_dialog {
            return;
        }
        egui::Modal::new(egui::Id::new("quit")).show(ctx, |ui| {
            ui.set_width(380.0);
            ui.heading("Quit Lemon Wire?");
            ui.label(
                "Friends can only download what you share while Lemon Wire is open, and \
                 downloads pause until you open it again.",
            );
            ui.add_space(10.0);
            ui.horizontal(|ui| {
                if ui.button("Quit").clicked() {
                    self.quit_dialog = false;
                    self.quitting = true;
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
                if ui.button("Keep running").clicked() {
                    self.quit_dialog = false;
                    ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(true));
                }
            });
        });
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        self.handle_events();
        self.poll_tasks();
        self.handle_close(&ctx);

        if !self.profiles_loaded {
            egui::CentralPanel::default_margins().show(ui, |ui| {
                ui.centered_and_justified(|ui| ui.spinner());
            });
        } else if self.profiles.is_empty() || self.join.is_some() {
            if self.join.is_none() {
                self.join = Some(crate::join::JoinForm::new(&self.profiles));
            }
            egui::CentralPanel::default_margins().show(ui, |ui| self.join_ui(ui));
        } else {
            egui::Panel::left("sidebar")
                .resizable(false)
                .exact_size(210.0)
                .show(ui, |ui| self.sidebar(ui));
            egui::CentralPanel::default_margins().show(ui, |ui| {
                self.engine_banner(ui);
                match self.page {
                    Page::Search => self.search_ui(ui),
                    Page::Transfers => self.transfers_ui(ui),
                    Page::Members => self.members_ui(ui),
                    Page::Settings => self.prefs_ui(ui),
                }
            });
        }
        self.dialogs(&ctx);
        self.toasts.show(&ctx);

        // Live transfer numbers.
        ctx.request_repaint_after(Duration::from_secs(1));
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        self.backend.shutdown();
    }
}

impl Theme {
    pub fn label(self) -> &'static str {
        match self {
            Theme::System => "Same as the system",
            Theme::Light => "Light",
            Theme::Dark => "Dark",
        }
    }
}
