use crate::ui::{App, Effect, Event};
use egui_software_backend::{BufferMutRef, ColorFieldOrder, EguiSoftwareRender};
use passwords_keeper::{
    native::{Monitor, WindowsClipboard},
    service,
    settings::Settings,
    updates,
};
use std::{
    num::NonZeroU32,
    sync::Arc,
    time::{Duration, Instant},
};
use winit::{
    application::ApplicationHandler,
    event::WindowEvent,
    event_loop::{ActiveEventLoop, ControlFlow, EventLoop, EventLoopProxy},
    window::{Window, WindowId},
};

pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    let event_loop = EventLoop::<Event>::with_user_event().build()?;
    let proxy = event_loop.create_proxy();
    let response_proxy = proxy.clone();
    let worker = service::spawn(move |response| {
        let _ = response_proxy.send_event(Event::Worker(response));
    });
    let prefs = Settings::load(&Settings::path());
    let app = App::new(worker.sender.clone(), prefs);
    let context = egui::Context::default();
    let wake_proxy = proxy.clone();
    context.set_request_repaint_callback(move |info| {
        let _ = wake_proxy.send_event(Event::Repaint(Instant::now() + info.delay));
    });
    let prefs_proxy = proxy.clone();
    let preferences = crate::preferences_worker::PreferencesWorker::start(move || {
        let _ = prefs_proxy.send_event(Event::PreferencesSaved(false));
    });
    let mut host = Desktop {
        surface: None,
        state: None,
        window: None,
        buffer_context: None,
        renderer: EguiSoftwareRender::new(ColorFieldOrder::Bgra),
        ctx: context,
        app,
        proxy,
        monitor: None,
        worker: Some(worker),
        clipboard_worker: None,
        preferences,
        repaint: None,
        occluded: false,
        frames: 0,
        raster_time: Duration::ZERO,
        present_time: Duration::ZERO,
        diagnostics: std::env::args().any(|a| a == "--diagnostics"),
        modifiers: Default::default(),
        pending_paste: None,
    };
    event_loop.run_app(&mut host)?;
    Ok(())
}
struct Desktop {
    // Surface and input state must drop before the native window.
    surface: Option<softbuffer::Surface<Arc<Window>, Arc<Window>>>,
    state: Option<egui_winit::State>,
    window: Option<Arc<Window>>,
    buffer_context: Option<softbuffer::Context<Arc<Window>>>,
    renderer: EguiSoftwareRender,
    ctx: egui::Context,
    app: App,
    proxy: EventLoopProxy<Event>,
    monitor: Option<Monitor>,
    repaint: Option<Instant>,
    occluded: bool,
    worker: Option<service::VaultWorker>,
    clipboard_worker: Option<service::ClipboardWorker>,
    preferences: crate::preferences_worker::PreferencesWorker,
    frames: u64,
    raster_time: Duration,
    present_time: Duration,
    diagnostics: bool,
    modifiers: winit::keyboard::ModifiersState,
    pending_paste: Option<(u64, passwords_keeper::security::Secret)>,
}
impl Desktop {
    fn redraw(&self) {
        if self.app.visible
            && !self.occluded
            && let Some(window) = &self.window
            && window.is_minimized() != Some(true)
        {
            window.request_redraw();
        }
    }
    fn effects(&mut self, event_loop: &ActiveEventLoop) {
        for effect in std::mem::take(&mut self.app.effects) {
            let proxy = self.proxy.clone();
            match effect {
                Effect::Choose(create) => {
                    std::thread::spawn(move || {
                        let dialog = rfd::FileDialog::new().add_filter("KeePass KDBX", &["kdbx"]);
                        let path = if create {
                            dialog.set_file_name("Vault.kdbx").save_file()
                        } else {
                            dialog.pick_file()
                        };
                        let _ = proxy.send_event(Event::Chosen(path, create));
                    });
                }
                Effect::Export => {
                    std::thread::spawn(move || {
                        let path = rfd::FileDialog::new()
                            .add_filter("KeePass KDBX", &["kdbx"])
                            .set_file_name("Vault-copy.kdbx")
                            .save_file();
                        let _ = proxy.send_event(Event::ExportChosen(path));
                    });
                }
                Effect::KeyFile {
                    create,
                    target,
                    epoch,
                } => {
                    std::thread::spawn(move || {
                        let dialog = rfd::FileDialog::new();
                        let path = if create {
                            dialog
                                .add_filter("KeePass key file", &["keyx"])
                                .set_file_name("Vault.keyx")
                                .save_file()
                        } else {
                            dialog.pick_file()
                        };
                        let result = match path {
                            Some(path) if create => {
                                passwords_keeper::keyfile::generate(&path).map(|()| Some(path))
                            }
                            path => Ok(path),
                        };
                        let _ = proxy.send_event(Event::KeyFileChosen {
                            result,
                            target,
                            epoch,
                        });
                    });
                }
                Effect::Attachment { entry, name, epoch } => {
                    std::thread::spawn(move || {
                        let dialog = rfd::FileDialog::new();
                        let path = if let Some(name) = &name {
                            dialog.set_file_name(name).save_file()
                        } else {
                            dialog.pick_file()
                        };
                        let _ = proxy.send_event(Event::AttachmentChosen {
                            path,
                            entry,
                            name,
                            epoch,
                        });
                    });
                }
                Effect::CheckUpdates(startup) => {
                    std::thread::spawn(move || {
                        let result = updates::check();
                        let _ = proxy.send_event(Event::UpdateChecked(result, startup));
                    });
                }
                Effect::Download(update) => {
                    std::thread::spawn(move || {
                        let progress_proxy = proxy.clone();
                        let result = updates::download(&update, move |progress| {
                            let _ = progress_proxy.send_event(Event::Progress(progress));
                        });
                        let _ = proxy.send_event(Event::Downloaded(result));
                    });
                }
                Effect::SavePreferences(prefs) => {
                    if let Some(monitor) = &self.monitor {
                        monitor.set_language(prefs.language);
                    }
                    self.preferences.save(prefs);
                }
                Effect::Hide => {
                    self.app.visible = false;
                    self.repaint = None;
                    if let Some(window) = &self.window {
                        window.set_visible(false);
                    }
                }
                Effect::Install(stage) => {
                    std::thread::spawn(move || {
                        let result = updates::start_install(&stage).is_ok();
                        if result {
                            std::mem::forget(stage);
                        }
                        let _ = proxy.send_event(Event::InstallFinished(result));
                    });
                }
            }
        }
        if self.app.close_requested {
            event_loop.exit();
        }
    }
    fn frame(&mut self, event_loop: &ActiveEventLoop) -> Result<(), Box<dyn std::error::Error>> {
        let Some(window) = &self.window else {
            return Ok(());
        };
        let size = window.inner_size();
        if !self.app.visible
            || self.occluded
            || window.is_minimized() == Some(true)
            || size.width == 0
            || size.height == 0
        {
            return Ok(());
        }
        let Some(state) = self.state.as_mut() else {
            return Ok(());
        };
        let mut input = state.take_egui_input(window);
        if let Some((epoch, mut secret)) = self.pending_paste.take()
            && epoch == self.app.privacy_epoch
        {
            input
                .events
                .push(egui::Event::Paste(std::mem::take(&mut secret.0)));
        }
        let mut output = self.ctx.run(input, |ctx| self.app.show(ctx));
        let mut commands = Vec::new();
        for command in std::mem::take(&mut output.platform_output.commands) {
            if let egui::OutputCommand::CopyText(text) = command {
                if let Some(clipboard) = &self.app.clipboard {
                    let _ = clipboard.send(service::ClipboardCommand::Copy(
                        zeroize::Zeroizing::new(text),
                        Duration::from_secs(self.app.prefs.clipboard_seconds as u64),
                    ));
                }
            } else {
                commands.push(command);
            }
        }
        output.platform_output.commands = commands;
        state.handle_platform_output(window, output.platform_output);
        let primitives = self.ctx.tessellate(output.shapes, output.pixels_per_point);
        let surface = self
            .surface
            .as_mut()
            .ok_or("Software surface unavailable")?;
        surface.resize(
            NonZeroU32::new(size.width).ok_or("Zero width")?,
            NonZeroU32::new(size.height).ok_or("Zero height")?,
        )?;
        let mut buffer = surface.buffer_mut()?;
        let start = Instant::now();
        let pixels: &mut [[u8; 4]] = bytemuck::cast_slice_mut(&mut buffer);
        self.renderer.render(
            &mut BufferMutRef::new(pixels, size.width as usize, size.height as usize),
            &primitives,
            &output.textures_delta,
            output.pixels_per_point,
        );
        self.raster_time += start.elapsed();
        let present = Instant::now();
        buffer.present()?;
        self.present_time += present.elapsed();
        self.frames += 1;
        if let Some(root) = output.viewport_output.get(&egui::ViewportId::ROOT)
            && root.repaint_delay < Duration::from_secs(3600)
        {
            self.repaint = Some(Instant::now() + root.repaint_delay);
        }
        self.effects(event_loop);
        Ok(())
    }
}
impl ApplicationHandler<Event> for Desktop {
    fn resumed(&mut self, event_loop: &ActiveEventLoop) {
        if self.window.is_some() {
            return;
        }
        let icon =
            winit::window::Icon::from_rgba(include_bytes!("../assets/icon.rgba").to_vec(), 64, 64)
                .ok();
        let attributes = Window::default_attributes()
            .with_title("Passwords Keeper")
            .with_inner_size(winit::dpi::LogicalSize::new(1160., 780.))
            .with_min_inner_size(winit::dpi::LogicalSize::new(980., 640.))
            .with_window_icon(icon);
        let setup = (|| -> Result<(), Box<dyn std::error::Error>> {
            let window = Arc::new(event_loop.create_window(attributes)?);
            let buffer_context = softbuffer::Context::new(window.clone())?;
            let surface = softbuffer::Surface::new(&buffer_context, window.clone())?;
            self.state = Some(egui_winit::State::new(
                self.ctx.clone(),
                egui::ViewportId::ROOT,
                window.as_ref(),
                Some(window.scale_factor() as f32),
                window.theme(),
                None,
            ));
            self.surface = Some(surface);
            self.buffer_context = Some(buffer_context);
            self.window = Some(window);
            let proxy = self.proxy.clone();
            let monitor = Monitor::start(self.app.prefs.language, move |action| {
                let _ = proxy.send_event(Event::System(action));
            })?;
            let proxy = self.proxy.clone();
            let paste_proxy = self.proxy.clone();
            let clipboard_worker = service::spawn_clipboard(
                WindowsClipboard::new(monitor.hwnd),
                move || {
                    let _ = proxy.send_event(Event::ClipboardError);
                },
                move |epoch, text| {
                    let _ = paste_proxy.send_event(Event::Paste(
                        epoch,
                        passwords_keeper::security::Secret((*text).clone()),
                    ));
                },
            );
            self.app.clipboard = Some(clipboard_worker.sender.clone());
            self.clipboard_worker = Some(clipboard_worker);
            self.monitor = Some(monitor);
            Ok(())
        })();
        if let Err(error) = setup {
            passwords_keeper::native::error_dialog(&format!(
                "The desktop could not be initialized: {error}"
            ));
            event_loop.exit();
            return;
        }
        if self.diagnostics {
            eprintln!(
                "renderer=egui_software_backend; presentation=softbuffer/Win32; scheduling=event-driven"
            );
        }
        self.effects(event_loop);
        self.redraw();
    }
    fn user_event(&mut self, event_loop: &ActiveEventLoop, event: Event) {
        if let Event::Paste(epoch, secret) = event {
            if epoch == self.app.privacy_epoch && self.app.visible {
                self.pending_paste = Some((epoch, secret));
                self.redraw();
            }
            return;
        }
        if let Event::Repaint(when) = event {
            if self.app.visible && !self.occluded {
                self.repaint = Some(self.repaint.map_or(when, |old| old.min(when)));
            }
            return;
        }
        let show = matches!(
            &event,
            Event::System(passwords_keeper::native::SystemEvent::Open)
        );
        self.app.event(event, &self.ctx);
        if show {
            self.occluded = false;
            if let Some(window) = &self.window {
                window.set_visible(true);
                window.set_minimized(false);
                window.focus_window();
            }
        }
        self.effects(event_loop);
        self.redraw();
    }
    fn window_event(
        &mut self,
        event_loop: &ActiveEventLoop,
        _window_id: WindowId,
        event: WindowEvent,
    ) {
        match &event {
            WindowEvent::ModifiersChanged(modifiers) => self.modifiers = modifiers.state(),
            WindowEvent::KeyboardInput { event, .. }
                if event.state.is_pressed()
                    && self.modifiers.control_key()
                    && !self.modifiers.alt_key()
                    && matches!(&event.logical_key,winit::keyboard::Key::Character(key) if key.eq_ignore_ascii_case("v")) =>
            {
                self.app.activity();
                if let Some(clipboard) = &self.app.clipboard {
                    let _ = clipboard.send(service::ClipboardCommand::Read(self.app.privacy_epoch));
                }
                return;
            }
            WindowEvent::CloseRequested => {
                self.app.ask_quit();
                self.effects(event_loop);
                self.redraw();
                return;
            }
            WindowEvent::Occluded(value) => {
                self.occluded = *value;
                if *value {
                    self.repaint = None;
                } else {
                    self.redraw();
                }
            }
            WindowEvent::KeyboardInput { .. }
            | WindowEvent::MouseInput { .. }
            | WindowEvent::MouseWheel { .. }
            | WindowEvent::CursorMoved { .. }
            | WindowEvent::Touch(_) => self.app.activity(),
            _ => {}
        }
        if matches!(event, WindowEvent::RedrawRequested) {
            self.repaint = None;
            if let Err(error) = self.frame(event_loop) {
                passwords_keeper::native::error_dialog(&format!(
                    "Software rendering failed: {error}"
                ));
                event_loop.exit();
            }
            return;
        }
        if let (Some(state), Some(window)) = (&mut self.state, &self.window) {
            let response = state.on_window_event(window, &event);
            if response.repaint {
                self.redraw();
            }
        }
    }
    fn about_to_wait(&mut self, event_loop: &ActiveEventLoop) {
        if self.app.timers(&self.ctx) {
            self.effects(event_loop);
            self.redraw();
        }
        if self.repaint.is_some_and(|when| Instant::now() >= when) {
            self.repaint = None;
            self.redraw();
        }
        let redraw = if self.app.visible && !self.occluded {
            self.repaint
        } else {
            None
        };
        if let Some(deadline) = [self.app.deadline(), redraw].into_iter().flatten().min() {
            event_loop.set_control_flow(ControlFlow::WaitUntil(deadline));
        } else {
            event_loop.set_control_flow(ControlFlow::Wait);
        }
    }
    fn exiting(&mut self, _: &ActiveEventLoop) {
        self.app.clipboard = None;
        self.clipboard_worker = None;
        self.worker = None;
        self.monitor = None;
        if self.diagnostics {
            eprintln!(
                "frames={}; raster_ms={}; present_ms={}",
                self.frames,
                self.raster_time.as_millis(),
                self.present_time.as_millis()
            );
        }
    }
}
