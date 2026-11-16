use egui::{self, Color32, RichText, Vec2};
use passwords_keeper::{
    credentials::CredentialsInput,
    error::VaultError,
    i18n,
    native::SystemEvent,
    security::{Generator, Secret},
    service::{Command, Response},
    settings::{Language, Settings},
    updates::{self, StagedUpdate, Update},
    vault::{Catalog, EntryDraft, search},
};
use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

pub enum Event {
    Repaint(Instant),
    Worker(Response),
    System(SystemEvent),
    Chosen(Option<PathBuf>, bool),
    ExportChosen(Option<PathBuf>),
    KeyFileChosen {
        result: passwords_keeper::error::Result<Option<PathBuf>>,
        target: KeyTarget,
        epoch: u64,
    },
    AttachmentChosen {
        path: Option<PathBuf>,
        entry: Uuid,
        name: Option<String>,
        epoch: u64,
    },
    UpdateChecked(Result<Option<Update>, updates::UpdateError>, bool),
    Progress(u8),
    Downloaded(Result<StagedUpdate, updates::UpdateError>),
    ClipboardError,
    PreferencesSaved(bool),
    InstallFinished(bool),
    Paste(u64, Secret),
}
#[derive(Clone, Copy)]
enum Next {
    Entry(Uuid),
    New,
    Home,
    Quit,
    Install,
}
#[derive(Clone)]
enum Prompt {
    Draft(Next),
    Delete(Uuid),
    RemoveAttachment(Uuid, String),
    Quit,
    LockedQuit,
}
#[derive(Clone, Copy, PartialEq)]
enum Screen {
    Home,
    Unlock,
    Workspace,
}
#[derive(Clone, Copy)]
pub enum KeyTarget {
    Unlock,
    Rekey,
}
struct KeyEditor {
    use_password: bool,
    password: Secret,
    confirmation: Secret,
    key_file: Option<PathBuf>,
}
impl Default for KeyEditor {
    fn default() -> Self {
        Self {
            use_password: true,
            password: Secret::default(),
            confirmation: Secret::default(),
            key_file: None,
        }
    }
}
pub enum Effect {
    Choose(bool),
    Export,
    KeyFile {
        create: bool,
        target: KeyTarget,
        epoch: u64,
    },
    Attachment {
        entry: Uuid,
        name: Option<String>,
        epoch: u64,
    },
    CheckUpdates(bool),
    Download(Update),
    SavePreferences(Settings),
    Hide,
    Install(StagedUpdate),
}
pub struct App {
    pub prefs: Settings,
    pub worker: mpsc::Sender<Command>,
    pub effects: Vec<Effect>,
    pub visible: bool,
    pub privacy_epoch: u64,
    screen: Screen,
    path: Option<PathBuf>,
    catalog: Catalog,
    selected_group: Option<Uuid>,
    draft: Option<EntryDraft>,
    draft_dirty: bool,
    master: Secret,
    confirmation: Secret,
    use_password: bool,
    key_file: Option<PathBuf>,
    key_editor: Option<KeyEditor>,
    pending_rekey: Option<(bool, Option<PathBuf>)>,
    new_vault: bool,
    query: String,
    settings_open: bool,
    licenses_open: bool,
    group_dialog: Option<Option<Uuid>>,
    group_name: String,
    prompt: Option<Prompt>,
    next: Option<Next>,
    busy: bool,
    locked_snapshot: bool,
    locked_unsaved: bool,
    locking: bool,
    lock_failed: bool,
    lock_after_open: bool,
    can_cancel: bool,
    notice: Option<(&'static str, Instant)>,
    error: Option<&'static str>,
    error_detail: Option<PathBuf>,
    reveal: bool,
    pub reveal_until: Option<Instant>,
    generator_open: bool,
    generator: Generator,
    generated: Secret,
    cancel: Arc<AtomicBool>,
    update: Option<Update>,
    update_status: Option<&'static str>,
    checking: bool,
    downloading: bool,
    progress: u8,
    staged: Option<StagedUpdate>,
    pub last_activity: Instant,
    pub close_requested: bool,
    pub clipboard: Option<mpsc::Sender<passwords_keeper::service::ClipboardCommand>>,
}
impl App {
    pub fn new(worker: mpsc::Sender<Command>, prefs: Settings) -> Self {
        let mut result = Self {
            prefs,
            worker,
            effects: Vec::new(),
            visible: true,
            privacy_epoch: 0,
            screen: Screen::Home,
            path: None,
            catalog: Catalog::default(),
            selected_group: None,
            draft: None,
            draft_dirty: false,
            master: Secret::default(),
            confirmation: Secret::default(),
            use_password: true,
            key_file: None,
            key_editor: None,
            pending_rekey: None,
            new_vault: false,
            query: String::new(),
            settings_open: false,
            licenses_open: false,
            group_dialog: None,
            group_name: String::new(),
            prompt: None,
            next: None,
            busy: false,
            locked_snapshot: false,
            locked_unsaved: false,
            locking: false,
            lock_failed: false,
            lock_after_open: false,
            can_cancel: false,
            notice: None,
            error: None,
            error_detail: None,
            reveal: false,
            reveal_until: None,
            generator_open: false,
            generator: Generator::default(),
            generated: Secret::default(),
            cancel: Arc::new(AtomicBool::new(false)),
            update: None,
            update_status: None,
            checking: false,
            downloading: false,
            progress: 0,
            staged: None,
            last_activity: Instant::now(),
            close_requested: false,
            clipboard: None,
        };
        if result.prefs.startup_updates {
            result.checking = true;
            result.effects.push(Effect::CheckUpdates(true));
        }
        result
    }
    fn t(&self, key: &str) -> String {
        i18n::text(self.prefs.language, key).into()
    }
    fn command(&mut self, command: Command) {
        self.can_cancel = matches!(
            command,
            Command::Save { export: None, .. } | Command::Rekey { .. }
        );
        self.busy = true;
        self.error = None;
        self.error_detail = None;
        if self.worker.send(command).is_err() {
            self.busy = false;
            self.error = Some("err_file");
        }
    }
    fn flash(&mut self, key: &'static str) {
        self.notice = Some((key, Instant::now() + Duration::from_secs(3)));
    }
    fn clear_secrets(&mut self, ctx: &egui::Context) {
        self.draft = None;
        self.generated.0.zeroize();
        self.master.0.zeroize();
        self.confirmation.0.zeroize();
        self.key_editor = None;
        self.query.zeroize();
        self.reveal = false;
        self.reveal_until = None;
        for e in &mut self.catalog.entries {
            e.title.zeroize();
            e.username.zeroize();
            e.url.zeroize();
        }
        for g in &mut self.catalog.groups {
            g.name.zeroize();
        }
        self.catalog = Catalog::default();
        ctx.memory_mut(|m| m.data = Default::default());
    }
    pub fn lock(&mut self, ctx: &egui::Context) {
        if self.screen != Screen::Workspace || self.locking {
            return;
        }
        self.privacy_epoch = self.privacy_epoch.wrapping_add(1);
        let draft = if self.draft_dirty {
            self.draft.take()
        } else {
            None
        };
        self.locked_unsaved = self.catalog.dirty || draft.is_some();
        self.locking = true;
        self.screen = Screen::Unlock;
        self.locked_snapshot = true;
        self.settings_open = false;
        self.prompt = None;
        self.group_dialog = None;
        self.generator_open = false;
        self.command(Command::Lock(draft));
        self.clear_secrets(ctx);
        if let Some(clipboard) = &self.clipboard {
            let _ = clipboard.send(passwords_keeper::service::ClipboardCommand::Clear);
        }
    }
    pub fn activity(&mut self) {
        if self.screen == Screen::Workspace {
            self.last_activity = Instant::now();
        }
    }
    pub fn deadline(&self) -> Option<Instant> {
        let idle = if self.screen == Screen::Workspace {
            Some(self.last_activity + Duration::from_secs(self.prefs.idle_minutes as u64 * 60))
        } else {
            None
        };
        [idle, self.reveal_until, self.notice.map(|(_, until)| until)]
            .into_iter()
            .flatten()
            .min()
    }
    pub fn timers(&mut self, ctx: &egui::Context) -> bool {
        let now = Instant::now();
        let mut changed = false;
        if self.screen == Screen::Workspace
            && now.duration_since(self.last_activity)
                >= Duration::from_secs(self.prefs.idle_minutes as u64 * 60)
        {
            self.lock(ctx);
            changed = true;
        }
        if self.reveal_until.is_some_and(|t| now >= t) {
            self.reveal = false;
            self.reveal_until = None;
            changed = true;
        }
        if self.notice.is_some_and(|(_, t)| now >= t) {
            self.notice = None;
            changed = true;
        }
        changed
    }
    pub fn event(&mut self, event: Event, ctx: &egui::Context) {
        match event {
            Event::Worker(response) => {
                match response {
                    Response::Opened {
                        catalog,
                        path,
                        draft,
                    } => {
                        if self.locking {
                            return;
                        }
                        self.catalog = catalog;
                        self.path = Some(path.clone());
                        self.screen = Screen::Workspace;
                        self.busy = false;
                        self.locked_snapshot = false;
                        self.locked_unsaved = false;
                        self.last_activity = Instant::now();
                        self.selected_group = None;
                        self.draft_dirty = draft.is_some();
                        self.draft = draft;
                        self.prefs.remember(path);
                        self.effects
                            .push(Effect::SavePreferences(self.prefs.clone()));
                        self.lock_failed = false;
                        if self.lock_after_open {
                            self.lock_after_open = false;
                            self.lock(ctx);
                        }
                    }
                    Response::Entry(draft) => {
                        if !self.locking && self.screen == Screen::Workspace {
                            self.draft = Some(draft);
                            self.draft_dirty = false;
                            self.reveal = false;
                        }
                        self.busy = self.locking;
                    }
                    Response::Attachments {
                        entry,
                        catalog,
                        items,
                        exported,
                    } => {
                        self.busy = self.locking;
                        if !self.locking && self.screen == Screen::Workspace {
                            self.catalog = catalog;
                            if let Some(draft) = self.draft.as_mut()
                                && draft.id == Some(entry)
                            {
                                draft.attachments = items;
                            }
                            if exported {
                                self.flash("attachment_exported");
                            }
                        }
                    }
                    Response::Rekeyed { catalog, warning } => {
                        if let Some((use_password, key_file)) = self.pending_rekey.take() {
                            self.use_password = use_password;
                            self.key_file = key_file;
                        }
                        self.key_editor = None;
                        self.busy = self.locking;
                        if !self.locking && self.screen == Screen::Workspace {
                            self.catalog = catalog;
                            if let Some(path) = warning {
                                self.error = Some("err_recovered_conflict");
                                self.error_detail = Some(path);
                            } else {
                                self.flash("key_changed");
                            }
                        }
                    }
                    Response::Catalog {
                        catalog,
                        selected,
                        saved,
                    } => {
                        self.busy = self.locking;
                        if !self.locking && self.screen == Screen::Workspace {
                            self.catalog = catalog;
                            self.draft_dirty = false;
                            if let Some(id) = selected
                                && let Some(d) = self.draft.as_mut()
                            {
                                d.id = Some(id);
                            }
                            if saved {
                                self.flash("saved");
                            }
                            if let Some(next) = self.next.take() {
                                self.navigate(next, ctx);
                            }
                        }
                    }
                    Response::Locked { unsaved } => {
                        self.lock_failed = false;
                        self.locking = false;
                        self.busy = false;
                        self.locked_unsaved = unsaved;
                        self.draft_dirty = false;
                    }
                    Response::Closed => {
                        self.busy = false;
                        self.locked_snapshot = false;
                        self.locked_unsaved = false;
                        self.path = None;
                        self.key_file = None;
                        self.use_password = true;
                        self.pending_rekey = None;
                        self.screen = Screen::Home;
                        self.clear_secrets(ctx);
                    }
                    Response::Failed { error, lock_failed } => {
                        self.pending_rekey = None;
                        self.error_detail = if let VaultError::ConflictRecovered(path) = &error {
                            Some(path.clone())
                        } else {
                            None
                        };
                        self.busy = self.locking;
                        self.next = None;
                        if lock_failed {
                            // Privacy screen stays closed; explicit retry can re-authenticate.
                            self.locking = false;
                            self.busy = false;
                            self.locked_snapshot = true;
                            self.lock_failed = true;
                            self.error = Some("lock_failed");
                        } else {
                            self.error = Some(error_key(&error));
                        }
                    }
                }
            }
            Event::Chosen(path, create) => {
                self.busy = false;
                if let Some(path) = path {
                    self.path = Some(path);
                    self.new_vault = create;
                    self.screen = Screen::Unlock;
                    self.error = None;
                }
            }
            Event::ExportChosen(path) => self.export_selected(path),
            Event::KeyFileChosen {
                result,
                target,
                epoch,
            } => {
                if epoch != self.privacy_epoch {
                    return;
                }
                self.busy = self.locking;
                match result {
                    Ok(Some(path)) => match target {
                        KeyTarget::Unlock => self.key_file = Some(path),
                        KeyTarget::Rekey => {
                            if let Some(editor) = &mut self.key_editor {
                                editor.key_file = Some(path);
                            }
                        }
                    },
                    Ok(None) => {}
                    Err(error) => self.error = Some(error_key(&error)),
                }
            }
            Event::AttachmentChosen {
                path,
                entry,
                name,
                epoch,
            } => {
                if epoch != self.privacy_epoch || self.screen != Screen::Workspace {
                    return;
                }
                self.busy = self.locking;
                if let Some(path) = path {
                    self.command(if let Some(name) = name {
                        Command::ExportAttachment { entry, name, path }
                    } else {
                        Command::AddAttachment { entry, path }
                    });
                }
            }
            Event::UpdateChecked(result, startup) => {
                self.checking = false;
                match result {
                    Ok(Some(update)) => {
                        self.update = Some(update);
                        self.update_status = Some("update_available");
                    }
                    Ok(None) => {
                        if !startup {
                            self.update_status = Some("up_to_date");
                        }
                    }
                    Err(_) => {
                        self.update_status = Some("update_failed");
                    }
                }
            }
            Event::Progress(value) => self.progress = value,
            Event::Downloaded(result) => {
                self.downloading = false;
                match result {
                    Ok(stage) => {
                        self.staged = Some(stage);
                        self.update_status = Some("ready_restart");
                    }
                    Err(_) => self.update_status = Some("integrity_failed"),
                }
            }
            Event::ClipboardError => self.error = Some("err_clipboard"),
            Event::PreferencesSaved(false) => self.error = Some("err_file"),
            Event::InstallFinished(true) => self.close_requested = true,
            Event::InstallFinished(false) => {
                self.busy = false;
                self.update_status = Some("integrity_failed");
            }
            Event::System(action) => match action {
                SystemEvent::SessionLocked | SystemEvent::Lock => {
                    if self.screen == Screen::Unlock && self.busy && !self.locking {
                        self.lock_after_open = true;
                    }
                    self.lock(ctx);
                }
                SystemEvent::Open => self.visible = true,
                SystemEvent::Quit => self.ask_quit(),
            },
            Event::Repaint(_) | Event::PreferencesSaved(true) | Event::Paste(_, _) => {}
        }
    }
    pub fn ask_quit(&mut self) {
        if self.locking || self.busy {
            return;
        }
        if self.locked_snapshot && self.locked_unsaved {
            self.prompt = Some(Prompt::LockedQuit);
        } else if self.catalog.dirty || self.draft_dirty {
            self.prompt = Some(Prompt::Quit);
        } else {
            self.close_requested = true;
        }
    }
    fn try_navigate(&mut self, next: Next, ctx: &egui::Context) {
        if self.draft_dirty {
            self.prompt = Some(Prompt::Draft(next));
        } else {
            self.navigate(next, ctx);
        }
    }
    fn navigate(&mut self, next: Next, ctx: &egui::Context) {
        self.prompt = None;
        self.reveal = false;
        self.reveal_until = None;
        match next {
            Next::Entry(id) => self.command(Command::Entry(id)),
            Next::New => {
                let mut draft = EntryDraft::default();
                draft.group = self.selected_group.unwrap_or(self.catalog.groups[0].id);
                self.draft = Some(draft);
                self.draft_dirty = false;
            }
            Next::Home => {
                if self.catalog.dirty {
                    self.prompt = Some(Prompt::Draft(Next::Home));
                } else {
                    self.clear_secrets(ctx);
                    self.command(Command::Close);
                }
            }
            Next::Quit => self.close_requested = true,
            Next::Install => {
                if let Some(stage) = self.staged.take() {
                    self.effects.push(Effect::Install(stage));
                    self.busy = true;
                }
            }
        }
    }
    fn save(&mut self, export: Option<PathBuf>) {
        self.cancel = Arc::new(AtomicBool::new(false));
        self.command(Command::Save {
            draft: if self.draft_dirty {
                self.draft.clone()
            } else {
                None
            },
            export,
            cancel: self.cancel.clone(),
        });
    }
    pub fn export_selected(&mut self, path: Option<PathBuf>) {
        self.busy = false;
        if let Some(path) = path {
            self.save(Some(path));
        }
    }
    pub fn show(&mut self, ctx: &egui::Context) {
        self.apply_style(ctx);
        let language = self.prefs.language;
        let t = |key: &str| i18n::text(language, key).to_string();
        egui::TopBottomPanel::top("toolbar")
            .frame(
                egui::Frame::new()
                    .fill(surface(self.prefs.dark))
                    .inner_margin(egui::Margin::symmetric(24, 15)),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    let (rect, _) = ui.allocate_exact_size(Vec2::splat(28.), egui::Sense::hover());
                    draw_mark(ui, rect, self.prefs.dark);
                    ui.label(RichText::new("Passwords Keeper").size(20.).strong());
                    if self.screen == Screen::Workspace {
                        ui.add_space(18.);
                        ui.label(
                            RichText::new(if self.catalog.dirty || self.draft_dirty {
                                t("dirty")
                            } else {
                                t("saved")
                            })
                            .small()
                            .color(muted(self.prefs.dark)),
                        );
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button(t("settings")).clicked() {
                            self.settings_open = !self.settings_open;
                        }
                        if self.screen == Screen::Workspace {
                            if ui
                                .add_enabled(!self.locking, egui::Button::new(t("lock")))
                                .clicked()
                            {
                                self.lock(ctx);
                            }
                            if ui
                                .add_enabled(
                                    !self.busy,
                                    egui::Button::new(t("save")).fill(accent(self.prefs.dark)),
                                )
                                .clicked()
                            {
                                self.save(None);
                            }
                        }
                    });
                });
            });
        egui::TopBottomPanel::bottom("status")
            .frame(egui::Frame::new().inner_margin(egui::Margin::symmetric(24, 10)))
            .show(ctx, |ui| {
                if let Some(error) = self.error {
                    ui.horizontal_wrapped(|ui| {
                        ui.colored_label(
                            if self.prefs.dark {
                                Color32::from_rgb(255, 168, 162)
                            } else {
                                Color32::from_rgb(153, 37, 40)
                            },
                            t(error),
                        );
                        if ui.small_button("×").on_hover_text(t("hide")).clicked() {
                            self.error = None;
                        }
                    });
                    if let Some(path) = &self.error_detail {
                        ui.label(path.display().to_string());
                    }
                } else if self.busy {
                    ui.horizontal(|ui| {
                        ui.label(t("busy"));
                        if self.can_cancel && ui.button(t("cancel")).clicked() {
                            self.cancel.store(true, Ordering::SeqCst);
                        }
                    });
                } else if let Some((key, _)) = self.notice {
                    ui.colored_label(accent(self.prefs.dark), t(key));
                } else if self.update.is_some() && self.staged.is_none() {
                    if ui.link(t("update_available")).clicked() {
                        self.settings_open = true;
                    }
                } else {
                    ui.label(
                        RichText::new(t("local"))
                            .small()
                            .color(muted(self.prefs.dark)),
                    );
                }
            });
        match self.screen {
            Screen::Home => self.home(ctx),
            Screen::Unlock => self.unlock(ctx),
            Screen::Workspace => self.workspace(ctx),
        }
        if self.settings_open {
            self.settings(ctx);
        }
        if self.licenses_open {
            static LINES: std::sync::LazyLock<Vec<&'static str>> = std::sync::LazyLock::new(|| {
                include_str!("../LICENSE")
                    .lines()
                    .chain(include_str!("../assets/third-party-licenses.txt").lines())
                    .collect()
            });
            let mut open = true;
            egui::Window::new(self.t("licenses"))
                .id(egui::Id::new("licenses_window"))
                .open(&mut open)
                .default_width(700.)
                .default_height(500.)
                .show(ctx, |ui| {
                    ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Extend);
                    let row_height = ui.text_style_height(&egui::TextStyle::Monospace);
                    egui::ScrollArea::both().show_rows(ui, row_height, LINES.len(), |ui, range| {
                        for line in &LINES[range] {
                            ui.label(RichText::new(*line).monospace());
                        }
                    });
                });
            self.licenses_open = open;
        }
        if self.group_dialog.is_some() {
            self.group_editor(ctx);
        }
        if self.generator_open {
            self.password_generator(ctx);
        }
        if self.key_editor.is_some() {
            self.key_editor(ctx);
        }
        if self.prompt.is_some() {
            self.prompt(ctx);
        }
        if self.reveal {
            ctx.request_repaint_after(Duration::from_secs(15));
        }
    }
    fn home(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(70.);
                ui.heading(RichText::new(self.t("tagline")).size(34.));
                ui.add_space(12.);
                ui.label(self.t("no_recent"));
                ui.add_space(28.);
                ui.horizontal_centered(|ui| {
                    let width = 340.;
                    ui.add_space(((ui.available_width() - width) / 2.).max(0.));
                    if ui
                        .add_enabled(
                            !self.busy,
                            egui::Button::new(self.t("create"))
                                .fill(accent(self.prefs.dark))
                                .min_size(Vec2::new(164., 42.)),
                        )
                        .clicked()
                    {
                        self.busy = true;
                        self.effects.push(Effect::Choose(true));
                    }
                    if ui
                        .add_enabled(
                            !self.busy,
                            egui::Button::new(self.t("open")).min_size(Vec2::new(164., 42.)),
                        )
                        .clicked()
                    {
                        self.busy = true;
                        self.effects.push(Effect::Choose(false));
                    }
                });
                ui.add_space(42.);
                ui.allocate_ui_with_layout(
                    Vec2::new(570., 300.),
                    egui::Layout::top_down(egui::Align::Min),
                    |ui| {
                        ui.label(RichText::new(self.t("recent")).strong());
                        ui.add_space(10.);
                        for path in self.prefs.recent.clone() {
                            let filename = path.file_name().unwrap_or_default().to_string_lossy();
                            let response = ui.add_sized(
                                [ui.available_width(), 52.],
                                egui::Button::new(format!("{}\n{}", filename, path.display()))
                                    .frame(false),
                            );
                            if response.clicked() && !self.busy {
                                self.path = Some(path);
                                self.new_vault = false;
                                self.screen = Screen::Unlock;
                                self.error = None;
                            }
                        }
                    },
                );
            });
        });
    }
    fn unlock(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    ui.vertical_centered(|ui| {
                        ui.add_space(24.);
                        let create = self.new_vault && !self.locked_snapshot;
                        ui.heading(
                            RichText::new(self.t(if create { "create" } else { "locked" }))
                                .size(30.),
                        );
                        ui.add_space(12.);
                        if let Some(path) = &self.path {
                            ui.label(
                                RichText::new(
                                    path.file_name().unwrap_or_default().to_string_lossy(),
                                )
                                .strong(),
                            );
                        }
                        ui.add_space(20.);
                        ui.allocate_ui_with_layout(
                            Vec2::new(440., 320.),
                            egui::Layout::top_down(egui::Align::Min),
                            |ui| {
                                ui.label(self.t(if self.lock_failed {
                                    "lock_failed"
                                } else if self.locked_unsaved {
                                    "encrypted_draft"
                                } else if create {
                                    "master_hint"
                                } else {
                                    "unlock_hint"
                                }));
                                ui.add_space(20.);
                                if ui
                                    .add_enabled(
                                        !self.busy,
                                        egui::Checkbox::new(
                                            &mut self.use_password,
                                            i18n::text(self.prefs.language, "use_master"),
                                        ),
                                    )
                                    .changed()
                                    && !self.use_password
                                {
                                    self.master.0.zeroize();
                                    self.confirmation.0.zeroize();
                                }
                                let edit = ui.add_enabled(
                                    !self.busy && self.use_password,
                                    egui::TextEdit::singleline(&mut self.master.0)
                                        .password(true)
                                        .desired_width(f32::INFINITY)
                                        .margin(Vec2::splat(10.)),
                                );
                                if create && self.use_password {
                                    ui.add_space(12.);
                                    ui.label(self.t("confirm_master"));
                                    ui.add(
                                        egui::TextEdit::singleline(&mut self.confirmation.0)
                                            .password(true)
                                            .desired_width(f32::INFINITY)
                                            .margin(Vec2::splat(10.)),
                                    );
                                }
                                ui.add_space(12.);
                                if let Some(create) = key_file_controls(
                                    ui,
                                    self.prefs.language,
                                    &mut self.key_file,
                                    !self.busy,
                                ) {
                                    self.busy = true;
                                    self.effects.push(Effect::KeyFile {
                                        create,
                                        target: KeyTarget::Unlock,
                                        epoch: self.privacy_epoch,
                                    });
                                }
                                ui.add_space(18.);
                                let submit = ui
                                    .add_enabled(
                                        !self.busy,
                                        egui::Button::new(self.t(if create {
                                            "create"
                                        } else {
                                            "unlock"
                                        }))
                                        .fill(accent(self.prefs.dark))
                                        .min_size(Vec2::new(440., 40.)),
                                    )
                                    .clicked()
                                    || (edit.lost_focus()
                                        && ui.input(|i| i.key_pressed(egui::Key::Enter))
                                        && !self.busy);
                                if submit {
                                    if let Some(error) = credential_error(
                                        self.use_password,
                                        &self.master.0,
                                        &self.confirmation.0,
                                        self.key_file.is_some(),
                                        create,
                                    ) {
                                        self.error = Some(error);
                                    } else {
                                        let password = self.use_password.then(|| {
                                            Zeroizing::new(std::mem::take(&mut self.master.0))
                                        });
                                        let credentials = CredentialsInput {
                                            password,
                                            key_file: self.key_file.clone(),
                                        };
                                        self.confirmation.0.zeroize();
                                        if self.locked_snapshot {
                                            self.command(Command::Unlock(credentials));
                                        } else if let Some(path) = self.path.clone() {
                                            self.command(Command::Open {
                                                path,
                                                credentials,
                                                create,
                                            });
                                        }
                                    }
                                }
                                ui.add_space(10.);
                                if !self.busy
                                    && !self.locked_snapshot
                                    && ui.button(self.t("back")).clicked()
                                {
                                    self.screen = Screen::Home;
                                    self.master.0.zeroize();
                                    self.confirmation.0.zeroize();
                                }
                                if !self.busy
                                    && self.locked_snapshot
                                    && !self.locked_unsaved
                                    && ui.button(self.t("vaults")).clicked()
                                {
                                    self.command(Command::Close);
                                }
                            },
                        );
                    });
                });
        });
    }
    fn workspace(&mut self, ctx: &egui::Context) {
        let language = self.prefs.language;
        let t = |key: &str| i18n::text(language, key).to_string();
        egui::SidePanel::left("groups")
            .exact_width(210.)
            .resizable(false)
            .frame(
                egui::Frame::new()
                    .fill(surface(self.prefs.dark))
                    .inner_margin(18),
            )
            .show(ctx, |ui| {
                ui.add_space(12.);
                ui.label(
                    RichText::new(t("groups"))
                        .strong()
                        .color(muted(self.prefs.dark)),
                );
                ui.add_space(12.);
                if ui
                    .selectable_label(self.selected_group.is_none(), t("all"))
                    .clicked()
                {
                    self.selected_group = None;
                }
                for group in self.catalog.groups.clone() {
                    ui.horizontal(|ui| {
                        ui.add_space((group.depth as f32 * 12.).min(72.));
                        if ui
                            .selectable_label(self.selected_group == Some(group.id), &group.name)
                            .clicked()
                        {
                            self.selected_group = Some(group.id);
                        }
                    });
                }
                ui.add_space(20.);
                ui.add_enabled_ui(!self.busy, |ui| {
                    if ui.button(format!("+ {}", t("add_group"))).clicked() {
                        self.group_name.clear();
                        self.group_dialog = Some(None);
                    }
                    if let Some(id) = self.selected_group {
                        if ui.small_button(t("rename")).clicked() {
                            self.group_name = self
                                .catalog
                                .groups
                                .iter()
                                .find(|g| g.id == id)
                                .map(|g| g.name.clone())
                                .unwrap_or_default();
                            self.group_dialog = Some(Some(id));
                        }
                        if ui.small_button(t("delete_group")).clicked() {
                            self.command(Command::DeleteGroup(id));
                            self.selected_group = None;
                        }
                    }
                });
                ui.with_layout(egui::Layout::bottom_up(egui::Align::Min), |ui| {
                    if ui.button(t("minimize")).clicked() {
                        self.lock(ctx);
                        self.effects.push(Effect::Hide);
                    }
                    if ui.button(t("save_copy")).clicked() && !self.busy {
                        self.effects.push(Effect::Export);
                        self.busy = true;
                    }
                    if ui.button(t("vaults")).clicked() && !self.busy {
                        self.try_navigate(Next::Home, ctx);
                    }
                });
            });
        egui::SidePanel::left("entries")
            .default_width(310.)
            .width_range(250. ..=430.)
            .resizable(true)
            .frame(egui::Frame::new().inner_margin(20))
            .show(ctx, |ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut self.query)
                        .hint_text(t("search"))
                        .desired_width(f32::INFINITY)
                        .margin(Vec2::splat(9.)),
                );
                ui.add_space(18.);
                ui.horizontal(|ui| {
                    ui.label(RichText::new(t("entries")).strong());
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui
                            .add_enabled(
                                !self.busy,
                                egui::Button::new(format!("+ {}", t("add_entry"))),
                            )
                            .clicked()
                        {
                            self.try_navigate(Next::New, ctx);
                        }
                    });
                });
                ui.add_space(12.);
                let entries = search(&self.catalog, self.selected_group, &self.query)
                    .into_iter()
                    .cloned()
                    .collect::<Vec<_>>();
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        if entries.is_empty() {
                            ui.add_space(32.);
                            ui.label(
                                RichText::new(t(if self.catalog.entries.is_empty() {
                                    "empty_hint"
                                } else {
                                    "no_results"
                                }))
                                .color(muted(self.prefs.dark)),
                            );
                        }
                        for entry in entries {
                            let selected = self.draft.as_ref().and_then(|e| e.id) == Some(entry.id);
                            let response = ui.add_sized(
                                [ui.available_width(), 62.],
                                egui::Button::new(
                                    RichText::new(format!("{}\n{}", entry.title, entry.username))
                                        .size(15.),
                                )
                                .selected(selected),
                            );
                            if response.clicked() && !self.busy {
                                self.try_navigate(Next::Entry(entry.id), ctx);
                            }
                            ui.add_space(6.);
                        }
                    });
            });
        egui::CentralPanel::default()
            .frame(egui::Frame::new().inner_margin(28))
            .show(ctx, |ui| {
                if self.draft.is_none() {
                    ui.vertical_centered(|ui| {
                        ui.add_space(130.);
                        ui.heading(self.t(if self.catalog.entries.is_empty() {
                            "empty"
                        } else {
                            "select"
                        }));
                        ui.add_space(16.);
                        if ui.button(self.t("add_entry")).clicked() && !self.busy {
                            self.navigate(Next::New, ctx);
                        }
                    });
                    return;
                }
                let language = self.prefs.language;
                let t = |key: &str| i18n::text(language, key).to_string();
                let mut draft = self.draft.take().unwrap_or_default();
                let mut changed = false;
                ui.heading(if draft.title.is_empty() {
                    t("add_entry")
                } else {
                    draft.title.clone()
                });
                ui.add_space(20.);
                ui.add_enabled_ui(!self.busy, |ui| {
                    egui::ScrollArea::vertical()
                        .auto_shrink([false, false])
                        .show(ui, |ui| {
                            changed |= field(ui, &t("title"), &mut draft.title, false);
                            ui.add_space(14.);
                            ui.label(t("group"));
                            egui::ComboBox::from_id_salt("entry_group")
                                .selected_text(
                                    self.catalog
                                        .groups
                                        .iter()
                                        .find(|g| g.id == draft.group)
                                        .map(|g| g.name.as_str())
                                        .unwrap_or(""),
                                )
                                .width(ui.available_width())
                                .show_ui(ui, |ui| {
                                    for g in &self.catalog.groups {
                                        changed |= ui
                                            .selectable_value(
                                                &mut draft.group,
                                                g.id,
                                                format!("{}{}", "  ".repeat(g.depth), g.name),
                                            )
                                            .changed();
                                    }
                                });
                            ui.add_space(14.);
                            changed |= field(ui, &t("username"), &mut draft.username, false);
                            ui.add_space(14.);
                            ui.horizontal(|ui| {
                                ui.label(t("password"));
                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| {
                                        if ui
                                            .small_button(t(if self.reveal {
                                                "hide"
                                            } else {
                                                "reveal"
                                            }))
                                            .clicked()
                                        {
                                            self.reveal = !self.reveal;
                                            self.reveal_until = if self.reveal {
                                                Some(Instant::now() + Duration::from_secs(15))
                                            } else {
                                                None
                                            };
                                        }
                                        if ui.small_button(t("copy")).clicked()
                                            && let Some(clipboard) = &self.clipboard
                                        {
                                            let _ = clipboard.send(
                                                passwords_keeper::service::ClipboardCommand::Copy(
                                                    Zeroizing::new(draft.password.clone()),
                                                    Duration::from_secs(
                                                        self.prefs.clipboard_seconds as u64,
                                                    ),
                                                ),
                                            );
                                            self.flash("copied");
                                        }
                                    },
                                );
                            });
                            changed |= ui
                                .add(
                                    egui::TextEdit::singleline(&mut draft.password)
                                        .password(!self.reveal)
                                        .desired_width(f32::INFINITY)
                                        .margin(Vec2::splat(9.)),
                                )
                                .changed();
                            if ui.small_button(t("generate")).clicked() {
                                self.generator_open = true;
                                match self.generator.generate() {
                                    Ok(value) => self.generated.0 = (*value).clone(),
                                    Err(e) => self.error = Some(error_key(&e)),
                                }
                            }
                            ui.add_space(14.);
                            changed |= field(ui, &t("url"), &mut draft.url, false);
                            ui.add_space(14.);
                            ui.label(t("notes"));
                            changed |= ui
                                .add(
                                    egui::TextEdit::multiline(&mut draft.notes)
                                        .desired_width(f32::INFINITY)
                                        .desired_rows(5)
                                        .margin(Vec2::splat(9.)),
                                )
                                .changed();
                            ui.add_space(18.);
                            ui.horizontal(|ui| {
                                ui.label(RichText::new(t("attachments")).strong());
                                if let Some(entry) = draft.id
                                    && ui.small_button(t("add_attachment")).clicked()
                                {
                                    self.busy = true;
                                    self.effects.push(Effect::Attachment {
                                        entry,
                                        name: None,
                                        epoch: self.privacy_epoch,
                                    });
                                }
                            });
                            ui.label(
                                RichText::new(t(if draft.id.is_none() {
                                    "apply_before_attachment"
                                } else {
                                    "attachment_hint"
                                }))
                                .small()
                                .color(muted(self.prefs.dark)),
                            );
                            if let Some(entry) = draft.id {
                                for item in &draft.attachments {
                                    ui.push_id(&item.name, |ui| {
                                        ui.horizontal_wrapped(|ui| {
                                            ui.label(format!(
                                                "{} · {} KiB",
                                                item.name,
                                                item.size.div_ceil(1024)
                                            ));
                                            if ui.small_button(t("save_attachment")).clicked() {
                                                self.busy = true;
                                                self.effects.push(Effect::Attachment {
                                                    entry,
                                                    name: Some(item.name.clone()),
                                                    epoch: self.privacy_epoch,
                                                });
                                            }
                                            if ui
                                                .small_button(t("remove_key_file"))
                                                .on_hover_text(t("remove_attachment"))
                                                .clicked()
                                            {
                                                self.prompt = Some(Prompt::RemoveAttachment(
                                                    entry,
                                                    item.name.clone(),
                                                ));
                                            }
                                        })
                                    });
                                }
                            }
                            ui.add_space(20.);
                            ui.horizontal(|ui| {
                                if ui
                                    .add_enabled(
                                        self.draft_dirty || changed,
                                        egui::Button::new(t("apply")).fill(accent(self.prefs.dark)),
                                    )
                                    .clicked()
                                {
                                    self.command(Command::Apply(draft.clone()));
                                }
                                if ui.button(t("cancel")).clicked() {
                                    if let Some(id) = draft.id {
                                        self.command(Command::Entry(id));
                                    } else {
                                        draft = EntryDraft::default();
                                        self.draft_dirty = false;
                                    }
                                }
                                if let Some(id) = draft.id {
                                    ui.with_layout(
                                        egui::Layout::right_to_left(egui::Align::Center),
                                        |ui| {
                                            if ui
                                                .button(RichText::new(t("delete")).color(
                                                    if self.prefs.dark {
                                                        Color32::from_rgb(255, 168, 162)
                                                    } else {
                                                        Color32::from_rgb(153, 37, 40)
                                                    },
                                                ))
                                                .clicked()
                                            {
                                                self.prompt = Some(Prompt::Delete(id));
                                            }
                                        },
                                    );
                                }
                            });
                        });
                });
                self.draft_dirty |= changed;
                self.draft = Some(draft);
            });
    }
    fn settings(&mut self, ctx: &egui::Context) {
        let before = serde_json::to_string(&self.prefs).unwrap_or_default();
        let mut open = self.settings_open;
        let mut dismiss = !self.licenses_open
            && self.key_editor.is_none()
            && self.prompt.is_none()
            && ctx.input_mut(|input| input.consume_key(egui::Modifiers::NONE, egui::Key::Escape));
        let language = self.prefs.language;
        let t = |key: &str| i18n::text(language, key).to_string();
        let height = (ctx.content_rect().height() - 140.).clamp(180., 560.);
        let response = egui::Window::new(t("settings"))
            .id(egui::Id::new("settings_window"))
            .open(&mut open)
            .resizable(false)
            .collapsible(false)
            .fixed_size(egui::vec2(560., height + 40.))
            .show(ctx, |ui| {
                egui::ScrollArea::vertical()
                    .max_height(height)
                    .min_scrolled_height(height)
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        ui.heading(t("appearance"));
                        ui.add_space(10.);
                        ui.horizontal(|ui| {
                            ui.selectable_value(&mut self.prefs.dark, false, t("light"));
                            ui.selectable_value(&mut self.prefs.dark, true, t("dark"));
                        });
                        egui::ComboBox::from_label(t("language"))
                            .selected_text(self.prefs.language.name())
                            .show_ui(ui, |ui| {
                                for value in Language::ALL {
                                    ui.selectable_value(
                                        &mut self.prefs.language,
                                        value,
                                        value.name(),
                                    );
                                }
                            });
                        ui.checkbox(&mut self.prefs.reduced_motion, t("reduced_motion"));
                        ui.add_space(22.);
                        ui.heading(t("security"));
                        ui.add_space(10.);
                        ui.add(
                            egui::Slider::new(&mut self.prefs.idle_minutes, 1..=60).text(t("idle")),
                        );
                        ui.add(
                            egui::Slider::new(&mut self.prefs.clipboard_seconds, 5..=120)
                                .text(t("clipboard")),
                        );
                        ui.label(t("session_lock"));
                        if self.screen == Screen::Workspace {
                            ui.add_space(10.);
                            if ui
                                .add_enabled(
                                    !self.busy && !self.draft_dirty,
                                    egui::Button::new(t("change_key")),
                                )
                                .clicked()
                            {
                                self.key_editor = Some(KeyEditor::default());
                            }
                            if self.draft_dirty {
                                ui.label(RichText::new(t("apply_before_key")).small());
                            }
                        }
                        ui.add_space(22.);
                        ui.heading(t("updates"));
                        ui.add_space(10.);
                        ui.label(format!("{} {}", t("installed"), passwords_keeper::VERSION));
                        ui.checkbox(&mut self.prefs.startup_updates, t("startup"));
                        if ui
                            .add_enabled(
                                !self.checking,
                                egui::Button::new(t(if self.checking {
                                    "checking"
                                } else {
                                    "check_updates"
                                })),
                            )
                            .clicked()
                        {
                            self.checking = true;
                            self.effects.push(Effect::CheckUpdates(false));
                        }
                        if let Some(status) = self.update_status {
                            ui.label(t(status));
                        }
                        if let Some(update) = &self.update {
                            ui.label(format!("v{}", update.version));
                            if self.staged.is_none()
                                && ui
                                    .add_enabled(
                                        !self.downloading,
                                        egui::Button::new(t("install"))
                                            .fill(accent(self.prefs.dark)),
                                    )
                                    .clicked()
                            {
                                self.downloading = true;
                                self.effects.push(Effect::Download(update.clone()));
                            }
                        }
                        if self.downloading {
                            ui.add(
                                egui::ProgressBar::new(self.progress as f32 / 100.)
                                    .text(t("downloading")),
                            );
                        }
                        if self.staged.is_some() && ui.button(t("restart")).clicked() {
                            if self.draft_dirty || self.catalog.dirty {
                                self.prompt = Some(Prompt::Draft(Next::Install));
                            } else if self.locked_unsaved {
                                self.prompt = Some(Prompt::LockedQuit);
                            } else {
                                self.navigate(Next::Install, ctx);
                            }
                        }
                        ui.label(
                            RichText::new(t("update_privacy"))
                                .small()
                                .color(muted(self.prefs.dark)),
                        );
                        ui.add_space(22.);
                        ui.collapsing(t("compatibility"), |ui| {
                            ui.label(t("format_limits"));
                            ui.add_space(8.);
                            ui.label(RichText::new(t("kdf_limits")).small());
                        });
                        ui.add_space(14.);
                        ui.label(
                            RichText::new(t("memory_note"))
                                .small()
                                .color(muted(self.prefs.dark)),
                        );
                        ui.add_space(14.);
                        ui.label("MIT · RustCrypto · keepass-rs · egui");
                        if ui.button(t("licenses")).clicked() {
                            self.licenses_open = true;
                        }
                    });
                ui.separator();
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let close = ui.button(t("close_settings"));
                    #[cfg(test)]
                    ctx.data_mut(|data| {
                        data.insert_temp(egui::Id::new("test_settings_close"), close.rect)
                    });
                    dismiss |= close.clicked();
                });
            });
        #[cfg(test)]
        if let Some(response) = &response {
            ctx.data_mut(|data| {
                data.insert_temp(
                    egui::Id::new("test_settings_window"),
                    response.response.rect,
                )
            });
        }
        #[cfg(not(test))]
        let _ = response;
        if !open || dismiss {
            self.settings_open = false;
            ctx.request_repaint();
        }
        if before != serde_json::to_string(&self.prefs).unwrap_or_default() {
            self.effects
                .push(Effect::SavePreferences(self.prefs.clone()));
        }
    }
    fn key_editor(&mut self, ctx: &egui::Context) {
        let Some(mut editor) = self.key_editor.take() else {
            return;
        };
        let language = self.prefs.language;
        let t = |key: &str| i18n::text(language, key).to_string();
        let mut open = true;
        let mut dismiss = false;
        egui::Window::new(t("change_key"))
            .id(egui::Id::new("change_master_key"))
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .default_width(460.)
            .show(ctx, |ui| {
                ui.label(t("change_key_hint"));
                ui.add_space(14.);
                ui.add_enabled_ui(!self.busy, |ui| {
                    if ui
                        .checkbox(&mut editor.use_password, t("use_master"))
                        .changed()
                        && !editor.use_password
                    {
                        editor.password.0.zeroize();
                        editor.confirmation.0.zeroize();
                    }
                    if editor.use_password {
                        field(ui, &t("new_master"), &mut editor.password.0, true);
                        field(ui, &t("confirm_master"), &mut editor.confirmation.0, true);
                    }
                    ui.add_space(12.);
                    if let Some(create) =
                        key_file_controls(ui, language, &mut editor.key_file, true)
                    {
                        self.busy = true;
                        self.effects.push(Effect::KeyFile {
                            create,
                            target: KeyTarget::Rekey,
                            epoch: self.privacy_epoch,
                        });
                    }
                    ui.add_space(18.);
                    if self.draft_dirty {
                        ui.label(t("apply_before_key"));
                    }
                    ui.horizontal(|ui| {
                        if ui
                            .add_enabled(!self.draft_dirty, egui::Button::new(t("change_key")))
                            .clicked()
                        {
                            if let Some(error) = credential_error(
                                editor.use_password,
                                &editor.password.0,
                                &editor.confirmation.0,
                                editor.key_file.is_some(),
                                true,
                            ) {
                                self.error = Some(error);
                            } else {
                                self.pending_rekey =
                                    Some((editor.use_password, editor.key_file.clone()));
                                let credentials = CredentialsInput {
                                    password: editor.use_password.then(|| {
                                        Zeroizing::new(std::mem::take(&mut editor.password.0))
                                    }),
                                    key_file: editor.key_file.clone(),
                                };
                                editor.confirmation.0.zeroize();
                                self.cancel = Arc::new(AtomicBool::new(false));
                                self.command(Command::Rekey {
                                    credentials,
                                    cancel: self.cancel.clone(),
                                });
                            }
                        }
                        dismiss = ui.button(t("cancel")).clicked();
                    });
                });
            });
        if self.busy || (open && !dismiss) {
            self.key_editor = Some(editor);
        }
    }
    fn group_editor(&mut self, ctx: &egui::Context) {
        let rename = self.group_dialog.flatten();
        let mut open = true;
        egui::Window::new(self.t(if rename.is_some() {
            "rename"
        } else {
            "add_group"
        }))
        .id(egui::Id::new("group_editor"))
        .open(&mut open)
        .collapsible(false)
        .resizable(false)
        .show(ctx, |ui| {
            ui.label(self.t("group_name"));
            ui.add(egui::TextEdit::singleline(&mut self.group_name).char_limit(256));
            ui.add_space(12.);
            if ui.button(self.t("apply")).clicked() {
                let name = std::mem::take(&mut self.group_name);
                if let Some(id) = rename {
                    self.command(Command::RenameGroup(id, name));
                } else {
                    self.command(Command::AddGroup(
                        self.selected_group.unwrap_or(self.catalog.groups[0].id),
                        name,
                    ));
                }
                self.group_dialog = None;
            }
        });
        if !open {
            self.group_dialog = None;
        }
    }
    fn password_generator(&mut self, ctx: &egui::Context) {
        let mut open = true;
        let language = self.prefs.language;
        let t = |key: &str| i18n::text(language, key).to_string();
        egui::Window::new(t("generator"))
            .id(egui::Id::new("generator"))
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .default_width(390.)
            .show(ctx, |ui| {
                ui.add(egui::Slider::new(&mut self.generator.length, 8..=128).text(t("length")));
                ui.checkbox(&mut self.generator.lower, t("lower"));
                ui.checkbox(&mut self.generator.upper, t("upper"));
                ui.checkbox(&mut self.generator.digits, t("digits"));
                ui.checkbox(&mut self.generator.symbols, t("symbols"));
                ui.checkbox(&mut self.generator.ambiguous, t("ambiguous"));
                ui.add_space(14.);
                ui.add(
                    egui::TextEdit::singleline(&mut self.generated.0)
                        .password(true)
                        .desired_width(f32::INFINITY),
                );
                ui.add_space(14.);
                ui.horizontal(|ui| {
                    if ui.button(t("generate")).clicked() {
                        match self.generator.generate() {
                            Ok(value) => self.generated.0 = (*value).clone(),
                            Err(e) => self.error = Some(error_key(&e)),
                        }
                    }
                    if ui.button(t("use_password")).clicked() {
                        if let Some(draft) = self.draft.as_mut() {
                            draft.password.zeroize();
                            draft.password = std::mem::take(&mut self.generated.0);
                            self.draft_dirty = true;
                        }
                        self.generator_open = false;
                    }
                });
            });
        if !open {
            self.generator_open = false;
            self.generated.0.zeroize();
        }
    }
    fn prompt(&mut self, ctx: &egui::Context) {
        let Some(prompt) = self.prompt.clone() else {
            return;
        };
        let message = match &prompt {
            Prompt::Draft(Next::Home | Next::Install | Next::Quit) => "leave_prompt",
            Prompt::Draft(_) => "draft_prompt",
            Prompt::Delete(_) => "delete_confirm",
            Prompt::RemoveAttachment(..) => "remove_attachment_confirm",
            Prompt::Quit => "quit_prompt",
            Prompt::LockedQuit => "quit_locked",
        };
        egui::Modal::new(egui::Id::new("confirm")).show(ctx, |ui| {
            ui.set_width(440.);
            ui.heading(self.t(message));
            ui.add_space(22.);
            ui.horizontal(|ui| {
                match prompt {
                    Prompt::Draft(next) => {
                        let needs_save = matches!(next, Next::Quit | Next::Home | Next::Install);
                        if ui
                            .button(self.t(if needs_save { "save" } else { "apply" }))
                            .clicked()
                        {
                            self.prompt = None;
                            self.next = Some(next);
                            if needs_save {
                                self.save(None);
                            } else if let Some(draft) = self.draft.clone() {
                                self.command(Command::Apply(draft));
                            }
                        }
                        if ui.button(self.t("discard")).clicked() {
                            self.draft = None;
                            self.draft_dirty = false;
                            self.prompt = None;
                            if matches!(next, Next::Home) {
                                self.catalog.dirty = false;
                            }
                            self.navigate(next, ctx);
                        }
                    }
                    Prompt::Quit => {
                        if ui.button(self.t("save")).clicked() {
                            self.prompt = None;
                            self.next = Some(Next::Quit);
                            self.save(None);
                        }
                        if ui.button(self.t("discard")).clicked() {
                            self.close_requested = true;
                        }
                    }
                    Prompt::LockedQuit => {
                        if ui.button(self.t("unlock")).clicked() {
                            self.prompt = None;
                            self.settings_open = false;
                        }
                        if ui.button(self.t("discard")).clicked() {
                            self.close_requested = true;
                        }
                    }
                    Prompt::Delete(id) => {
                        if ui.button(self.t("delete")).clicked() {
                            self.draft = None;
                            self.draft_dirty = false;
                            self.prompt = None;
                            self.command(Command::DeleteEntry(id));
                        }
                    }
                    Prompt::RemoveAttachment(entry, name) => {
                        if ui.button(self.t("remove_attachment")).clicked() {
                            self.prompt = None;
                            self.command(Command::RemoveAttachment { entry, name });
                        }
                    }
                }
                if ui.button(self.t("cancel")).clicked() {
                    self.prompt = None;
                }
            });
        });
    }
    fn apply_style(&self, ctx: &egui::Context) {
        let mut style = (*ctx.style()).clone();
        let dark = self.prefs.dark;
        style.visuals = if dark {
            egui::Visuals::dark()
        } else {
            egui::Visuals::light()
        };
        style.visuals.panel_fill = background(dark);
        style.visuals.window_fill = surface(dark);
        style.visuals.extreme_bg_color = background(dark);
        style.visuals.faint_bg_color = surface(dark);
        style.visuals.override_text_color = Some(if dark {
            Color32::from_rgb(231, 239, 235)
        } else {
            Color32::from_rgb(30, 49, 44)
        });
        style.visuals.selection.bg_fill = if dark {
            Color32::from_rgb(40, 82, 70)
        } else {
            Color32::from_rgb(195, 228, 213)
        };
        style.visuals.widgets.active.bg_fill = if dark {
            Color32::from_rgb(55, 96, 83)
        } else {
            Color32::from_rgb(185, 223, 207)
        };
        for widget in [
            &mut style.visuals.widgets.inactive,
            &mut style.visuals.widgets.hovered,
            &mut style.visuals.widgets.active,
        ] {
            widget.corner_radius = egui::CornerRadius::same(7);
        }
        style.visuals.window_corner_radius = egui::CornerRadius::same(12);
        style.spacing.item_spacing = Vec2::new(8., 8.);
        style.spacing.button_padding = Vec2::new(12., 8.);
        style.spacing.interact_size = Vec2::new(36., 34.);
        style.spacing.window_margin = egui::Margin::same(22);
        style
            .text_styles
            .insert(egui::TextStyle::Body, egui::FontId::proportional(15.));
        style
            .text_styles
            .insert(egui::TextStyle::Button, egui::FontId::proportional(14.));
        style
            .text_styles
            .insert(egui::TextStyle::Heading, egui::FontId::proportional(26.));
        style.visuals.text_cursor.blink = false;
        style.animation_time = if self.prefs.reduced_motion { 0. } else { 0.14 };
        ctx.set_style(style);
    }
}
fn field(ui: &mut egui::Ui, label: &str, value: &mut String, password: bool) -> bool {
    ui.label(label);
    ui.add(
        egui::TextEdit::singleline(value)
            .password(password)
            .desired_width(f32::INFINITY)
            .margin(Vec2::splat(9.)),
    )
    .changed()
}
fn background(dark: bool) -> Color32 {
    if dark {
        Color32::from_rgb(16, 26, 30)
    } else {
        Color32::from_rgb(248, 249, 246)
    }
}
fn surface(dark: bool) -> Color32 {
    if dark {
        Color32::from_rgb(24, 38, 42)
    } else {
        Color32::from_rgb(235, 242, 236)
    }
}
fn accent(dark: bool) -> Color32 {
    if dark {
        Color32::from_rgb(49, 116, 94)
    } else {
        Color32::from_rgb(173, 218, 194)
    }
}
fn muted(dark: bool) -> Color32 {
    if dark {
        Color32::from_rgb(158, 183, 174)
    } else {
        Color32::from_rgb(80, 109, 96)
    }
}
pub fn draw_mark(ui: &egui::Ui, rect: egui::Rect, dark: bool) {
    let p = ui.painter();
    let color = if dark {
        Color32::from_rgb(131, 218, 180)
    } else {
        Color32::from_rgb(31, 105, 75)
    };
    let c = rect.center();
    p.rect_filled(
        egui::Rect::from_center_size(c, Vec2::new(rect.width() * 0.72, rect.height() * 0.65)),
        6,
        color,
    );
    p.circle_stroke(
        c - Vec2::new(0., rect.height() * 0.22),
        rect.width() * 0.22,
        egui::Stroke::new(2.5, color),
    );
    p.circle_filled(c, 2.3, background(dark));
    p.line_segment(
        [c, c + Vec2::new(0., 6.)],
        egui::Stroke::new(2.3, background(dark)),
    );
}
fn credential_error(
    use_password: bool,
    password: &str,
    confirmation: &str,
    key_file: bool,
    creating: bool,
) -> Option<&'static str> {
    if !use_password && !key_file {
        return Some("err_key_required");
    }
    if use_password && password.len() > 4096 {
        return Some("err_limit");
    }
    if use_password && creating && (password != confirmation || password.chars().count() < 12) {
        return Some("err_password");
    }
    None
}
fn key_file_controls(
    ui: &mut egui::Ui,
    language: Language,
    path: &mut Option<PathBuf>,
    enabled: bool,
) -> Option<bool> {
    let t = |key: &str| i18n::text(language, key).to_string();
    let mut action = None;
    ui.add_enabled_ui(enabled, |ui| {
        ui.label(t("key_file"));
        if let Some(file) = path.as_ref() {
            ui.label(file.file_name().unwrap_or_default().to_string_lossy())
                .on_hover_text(file.display().to_string());
        } else {
            ui.label(RichText::new(t("no_key_file")).small());
        }
        ui.horizontal_wrapped(|ui| {
            if ui.button(t("choose_key_file")).clicked() {
                action = Some(false);
            }
            if ui.button(t("create_key_file")).clicked() {
                action = Some(true);
            }
            if path.is_some() && ui.small_button(t("remove_key_file")).clicked() {
                *path = None;
            }
        });
        ui.label(RichText::new(t("key_file_hint")).small());
    });
    action
}
fn error_key(error: &VaultError) -> &'static str {
    match error {
        VaultError::Credentials => "err_credentials",
        VaultError::CredentialsRequired => "err_key_required",
        VaultError::KeyFile => "err_key_file",
        VaultError::AttachmentExists => "err_attachment_exists",
        VaultError::Corrupt => "err_corrupt",
        VaultError::Unsupported => "err_unsupported",
        VaultError::Limit => "err_limit",
        VaultError::Conflict => "err_conflict",
        VaultError::ConflictRecovered(_) => "err_recovered_conflict",
        VaultError::Cancelled => "cancelled",
        VaultError::InvalidEntry | VaultError::NotFound => "err_entry",
        VaultError::Clipboard => "err_clipboard",
        VaultError::Random => "err_random",
        _ => "err_file",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn harness() -> (App, mpsc::Receiver<Command>, egui::Context) {
        let (tx, rx) = mpsc::channel();
        let prefs = Settings {
            startup_updates: false,
            ..Default::default()
        };
        (App::new(tx, prefs), rx, egui::Context::default())
    }
    fn open(app: &mut App, ctx: &egui::Context) {
        let mut catalog = Catalog::default();
        catalog.groups.push(passwords_keeper::vault::GroupSummary {
            id: Uuid::new_v4(),
            name: "Synthetic".into(),
            depth: 0,
        });
        app.event(
            Event::Worker(Response::Opened {
                catalog,
                path: PathBuf::from("synthetic.kdbx"),
                draft: None,
            }),
            ctx,
        );
        app.effects.clear();
    }
    #[test]
    fn disabled_startup_checks_emit_no_network_effect() {
        let (app, _, _) = harness();
        assert!(
            !app.effects
                .iter()
                .any(|e| matches!(e, Effect::CheckUpdates(_)))
        );
    }
    fn settings_frame(app: &mut App, ctx: &egui::Context, events: Vec<egui::Event>) {
        let _ = ctx.run(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(980., 640.),
                )),
                events,
                ..Default::default()
            },
            |ctx| {
                if app.settings_open {
                    app.settings(ctx);
                }
            },
        );
    }
    #[test]
    fn settings_close_button_and_escape_remain_closed() {
        let (mut app, _, ctx) = harness();
        app.settings_open = true;
        for _ in 0..3 {
            settings_frame(&mut app, &ctx, vec![]);
        }
        let rect = ctx
            .data(|data| data.get_temp::<egui::Rect>(egui::Id::new("test_settings_close")))
            .unwrap();
        assert!(
            rect.bottom() <= 640.,
            "close button outside the smallest viewport"
        );
        let pos = rect.center();
        settings_frame(
            &mut app,
            &ctx,
            vec![
                egui::Event::PointerMoved(pos),
                egui::Event::PointerButton {
                    pos,
                    button: egui::PointerButton::Primary,
                    pressed: true,
                    modifiers: Default::default(),
                },
            ],
        );
        settings_frame(
            &mut app,
            &ctx,
            vec![egui::Event::PointerButton {
                pos,
                button: egui::PointerButton::Primary,
                pressed: false,
                modifiers: Default::default(),
            }],
        );
        assert!(!app.settings_open);
        settings_frame(&mut app, &ctx, vec![]);
        assert!(!app.settings_open);
        app.settings_open = true;
        settings_frame(
            &mut app,
            &ctx,
            vec![egui::Event::Key {
                key: egui::Key::Escape,
                physical_key: None,
                pressed: true,
                repeat: false,
                modifiers: Default::default(),
            }],
        );
        assert!(!app.settings_open);
    }
    #[test]
    fn attachment_responses_preserve_unsaved_fields_and_stale_choosers_cannot_cross_lock() {
        let (mut app, rx, ctx) = harness();
        open(&mut app, &ctx);
        let id = Uuid::new_v4();
        let mut draft = EntryDraft::default();
        draft.id = Some(id);
        draft.title = "Unsaved title".into();
        draft.password = "Unsaved secret".into();
        app.draft = Some(draft);
        app.draft_dirty = true;
        app.event(
            Event::Worker(Response::Attachments {
                entry: id,
                catalog: app.catalog.clone(),
                items: vec![passwords_keeper::vault::AttachmentSummary {
                    name: "test.bin".into(),
                    size: 42,
                }],
                exported: false,
            }),
            &ctx,
        );
        assert_eq!(app.draft.as_ref().unwrap().title, "Unsaved title");
        assert_eq!(app.draft.as_ref().unwrap().attachments.len(), 1);
        assert!(app.draft_dirty);
        let epoch = app.privacy_epoch;
        app.lock(&ctx);
        let _ = rx.try_recv().unwrap();
        app.event(
            Event::AttachmentChosen {
                path: Some(PathBuf::from("synthetic.bin")),
                entry: id,
                name: None,
                epoch,
            },
            &ctx,
        );
        app.event(
            Event::KeyFileChosen {
                result: Ok(Some(PathBuf::from("stale.keyx"))),
                target: KeyTarget::Unlock,
                epoch,
            },
            &ctx,
        );
        assert!(rx.try_recv().is_err());
        assert!(app.key_file.is_none());
        assert!(app.draft.is_none());
    }
    #[test]
    fn completed_key_change_retains_unlock_method_when_lock_was_queued() {
        let (mut app, _, ctx) = harness();
        open(&mut app, &ctx);
        app.key_editor = Some(KeyEditor::default());
        app.pending_rekey = Some((false, Some(PathBuf::from("new-synthetic.keyx"))));
        app.lock(&ctx);
        assert!(app.key_editor.is_none());
        app.event(
            Event::Worker(Response::Rekeyed {
                catalog: Catalog::default(),
                warning: None,
            }),
            &ctx,
        );
        assert!(!app.use_password);
        assert_eq!(app.key_file, Some(PathBuf::from("new-synthetic.keyx")));
        assert!(app.locking);
        assert!(app.screen == Screen::Unlock);
        assert!(app.catalog.entries.is_empty());
    }
    #[test]
    fn dirty_navigation_waits_and_lock_clears_visible_owned_secrets() {
        let (mut app, rx, ctx) = harness();
        open(&mut app, &ctx);
        let mut draft = EntryDraft::default();
        draft.group = app.catalog.groups[0].id;
        draft.password = "synthetic secret".into();
        app.draft = Some(draft.clone());
        app.draft_dirty = true;
        app.master.0 = "synthetic master".into();
        app.generated.0 = "generated synthetic".into();
        app.try_navigate(Next::New, &ctx);
        assert!(app.prompt.is_some());
        assert!(rx.try_recv().is_err());
        app.lock(&ctx);
        assert!(app.draft.is_none());
        assert!(app.master.0.is_empty());
        assert!(app.generated.0.is_empty());
        assert!(app.catalog.entries.is_empty());
        assert!(app.locking);
        assert!(matches!(rx.try_recv().unwrap(), Command::Lock(Some(_))));
        app.event(Event::Worker(Response::Entry(draft)), &ctx);
        assert!(app.draft.is_none());
        app.event(Event::Worker(Response::Locked { unsaved: true }), &ctx);
        app.ask_quit();
        assert!(matches!(app.prompt, Some(Prompt::LockedQuit)));
        assert!(!app.close_requested);
    }
    #[test]
    fn windows_lock_during_unlock_is_applied_after_worker_completion() {
        let (mut app, rx, ctx) = harness();
        app.screen = Screen::Unlock;
        app.busy = true;
        app.event(Event::System(SystemEvent::SessionLocked), &ctx);
        assert!(app.lock_after_open);
        open(&mut app, &ctx);
        assert!(app.screen == Screen::Unlock);
        assert!(app.locking);
        assert!(matches!(rx.try_recv().unwrap(), Command::Lock(_)));
    }
    #[test]
    fn idle_and_reveal_deadlines_are_finite_without_rendering() {
        let (mut app, _, ctx) = harness();
        open(&mut app, &ctx);
        app.last_activity = Instant::now() - Duration::from_secs(3601);
        assert!(app.timers(&ctx));
        assert!(app.screen == Screen::Unlock);
        assert!(app.deadline().is_none());
    }
}
