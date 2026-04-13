use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::ErrorKind;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use clap::Parser;
use fs2::FileExt;

use egui::style::ScrollStyle;
use egui::{Color32, Modal};
use egui_file_dialog::FileDialog as EguiFileDialog;
use nullspace_client::{Client, Config, Event, UploadedRoot};
use nullspace_crypt::hash::Hash;
use nullspace_crypt::signing::SigningPublic;
use nullspace_structs::username::UserName;
use pollster::FutureExt;
use smol::channel::Receiver;
use url::Url;
use uuid::Uuid;

use crate::events::{event_loop, spawn_audio_thread};
use crate::fonts::load_fonts;
use crate::utils::prefs::{AppTheme, PrefData};
use crate::utils::profile_loader::ProfileLoader;

macro_rules! ui_unwrap {
    ($ui:ident, $res:expr) => {
        match $res {
            Ok(res) => res,
            Err(err) => return $ui.label(err),
        }
    };
}

mod events;
mod fonts;
mod notify;
mod rpc;
mod screens;
mod tray;
mod utils;
mod widgets;

const DEFAULT_DIR_ENDPOINT: &str = "https://xirtam-test-directory.nullfruit.net/";
const DEFAULT_DIR_ANCHOR_PK: &str = "bpOJ5ga-oQjb0njgBV5CtEZIVU6wjvltXjsQ_10BNlM";
const INSTANCE_LOCK_FILE: &str = "instance.lock";
#[cfg(unix)]
const INSTANCE_SIGNAL_SOCKET: &str = "instance.sock";

#[derive(Debug, Parser)]
#[command(name = "nullspace-egui", about = "Minimal nullspace GUI client")]
struct Cli {
    #[arg(long)]
    data_dir: Option<PathBuf>,
    #[arg(long, default_value = DEFAULT_DIR_ENDPOINT)]
    dir_endpoint: String,
    #[arg(long, default_value = DEFAULT_DIR_ANCHOR_PK)]
    dir_anchor_pk: String,
}

struct NullspaceApp {
    _single_instance: SingleInstanceGuard,
    #[cfg(unix)]
    activation_listener: Option<ActivationListener>,
    recv_event: Receiver<Event>,
    focused: Arc<AtomicBool>,
    file_dialog: EguiFileDialog,
    profile_file_dialog: EguiFileDialog,
    tray: Option<tray::Tray>,
    tray_hidden: bool,
    pending_quit: bool,
    supports_hide: bool,

    state: AppState,
}

struct AppState {
    logged_in: Option<bool>,
    own_username: Option<UserName>,
    msg_updates: u64,
    error_dialog: Option<String>,
    prefs: PrefData,
    last_saved_prefs: PrefData,

    profile_loader: ProfileLoader,

    attach_updates: u64,

    upload_progress: BTreeMap<Uuid, (u64, u64)>,
    upload_done: BTreeMap<Uuid, UploadedRoot>,
    upload_error: BTreeMap<Uuid, String>,
    download_progress: BTreeMap<Hash, (u64, u64)>,
    download_error: BTreeMap<Hash, String>,

    image_viewer: Option<PathBuf>,
}

impl NullspaceApp {
    fn new(
        cc: &eframe::CreationContext<'_>,
        single_instance: SingleInstanceGuard,
        client: Client,
        prefs: PrefData,
    ) -> Self {
        crate::rpc::init_rpc(client.rpc());
        let (event_tx, recv_event) = smol::channel::bounded(64);
        let focused = Arc::new(AtomicBool::new(true));
        let audio_tx = spawn_audio_thread();
        let ctx = cc.egui_ctx.clone();
        smol::spawn(event_loop(ctx, event_tx, focused.clone(), audio_tx)).detach();
        egui_extras::install_image_loaders(&cc.egui_ctx);
        configure_theme_styles(&cc.egui_ctx);
        cc.egui_ctx
            .options_mut(|opt| opt.fallback_theme = egui::Theme::Light);
        apply_theme_preference(&cc.egui_ctx, prefs.theme);

        let fonts = egui::FontDefinitions::default();
        cc.egui_ctx.set_fonts(load_fonts(fonts));
        cc.egui_ctx
            .set_zoom_factor(prefs.zoom_percent as f32 / 100.0);
        let tray = if supports_hide_window() {
            match tray::Tray::init("nullspace-egui") {
                Ok(tray) => Some(tray),
                Err(err) => {
                    tracing::warn!(error = %err, "failed to initialize tray");
                    None
                }
            }
        } else {
            None
        };
        let supports_hide = supports_hide_window();
        #[cfg(unix)]
        let activation_listener = activation_listener();
        Self {
            _single_instance: single_instance,
            #[cfg(unix)]
            activation_listener,
            recv_event,
            focused,
            file_dialog: EguiFileDialog::new(),
            profile_file_dialog: EguiFileDialog::new(),
            tray,
            tray_hidden: false,
            pending_quit: false,
            supports_hide,
            state: AppState {
                logged_in: None,
                own_username: None,
                msg_updates: 0,
                error_dialog: None,
                prefs: prefs.clone(),
                last_saved_prefs: prefs,
                profile_loader: ProfileLoader::new(crate::utils::folders::profile_cache_dir()),
                attach_updates: 0,
                upload_progress: BTreeMap::new(),
                upload_done: BTreeMap::new(),
                upload_error: BTreeMap::new(),
                download_progress: BTreeMap::new(),
                download_error: BTreeMap::new(),
                image_viewer: None,
            },
        }
    }
}

impl eframe::App for NullspaceApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let start = Instant::now();
        // hack to speed up touchpad scroll while not speeding up mouse scroll too much
        ctx.options_mut(|opt| opt.input_options.line_scroll_speed = 18.0);
        ctx.input_mut(|input| input.smooth_scroll_delta *= 4.0);

        #[cfg(unix)]
        if let Some(listener) = self.activation_listener.as_mut()
            && listener.poll_activation()
        {
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
            ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
            ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
            self.tray_hidden = false;
        }

        ctx.set_zoom_factor(self.state.prefs.zoom_percent as f32 / 100.0);
        apply_theme_preference(ctx, self.state.prefs.theme);
        apply_debug_mode(ctx, self.state.prefs.debug_mode);
        let close_requested = ctx.input(|i| i.viewport().close_requested());
        let focused = ctx.input(|i| i.viewport().focused).unwrap_or(true);

        self.focused.store(focused, Ordering::Relaxed);
        if let Some(tray) = &self.tray {
            while let Some(action) = tray.try_recv() {
                match action {
                    tray::TrayAction::Show => {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                        ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
                        ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
                        self.tray_hidden = false;
                    }
                    tray::TrayAction::Hide => {
                        if self.supports_hide {
                            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
                            self.tray_hidden = true;
                        }
                    }
                    tray::TrayAction::Quit => {
                        self.pending_quit = true;
                    }
                }
            }
        }
        if close_requested && self.tray.is_some() && self.supports_hide && !self.pending_quit {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
            self.tray_hidden = true;
        }
        if self.pending_quit {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
        while let Ok(event) = self.recv_event.try_recv() {
            tracing::debug!(event = ?event, "processing nullspace event");
            match event {
                Event::State { logged_in } => {
                    self.state.logged_in = Some(logged_in);
                    if logged_in {
                        self.state.own_username = crate::rpc::flatten_rpc(
                            crate::rpc::get_rpc().own_username().block_on(),
                        )
                        .ok();
                    } else {
                        self.state.own_username = None;
                    }
                }
                Event::ConvoUpdated { convo_id } => {
                    let _ = convo_id;
                    self.state.msg_updates = self.state.msg_updates.saturating_add(1);
                }
                Event::UploadProgress {
                    id,
                    uploaded_size,
                    total_size,
                } => {
                    tracing::debug!(id = %id, uploaded_size, total_size, "upload progress event");

                    self.state
                        .upload_progress
                        .insert(id, (uploaded_size, total_size));
                }
                Event::UploadDone { id, root } => {
                    tracing::debug!(id = %id, root = ?root, "upload done event");
                    self.state.upload_progress.remove(&id);
                    self.state.upload_done.insert(id, root);
                    self.state.upload_error.remove(&id);
                    self.state.attach_updates += 1;
                }
                Event::UploadFailed { id, error } => {
                    tracing::warn!(id = %id, error = %error, "upload failed event");
                    self.state.upload_progress.remove(&id);
                    self.state.upload_error.insert(id, error.to_string());
                    self.state.attach_updates += 1;
                }
                Event::DownloadProgress {
                    attachment_id,
                    downloaded_size,
                    total_size,
                } => {
                    tracing::debug!(
                        attachment_id = ?attachment_id,
                        downloaded_size,
                        total_size,
                        "download progress event"
                    );
                    self.state
                        .download_progress
                        .insert(attachment_id, (downloaded_size, total_size));
                }
                Event::DownloadDone {
                    attachment_id,
                    absolute_path,
                } => {
                    tracing::debug!(
                        attachment_id = ?attachment_id,
                        path = ?absolute_path,
                        "download done event"
                    );
                    self.state.download_progress.remove(&attachment_id);
                    self.state.download_error.remove(&attachment_id);
                    self.state.attach_updates += 1;
                }
                Event::DownloadFailed {
                    attachment_id,
                    error,
                } => {
                    tracing::warn!(
                        attachment_id = ?attachment_id,
                        error = %error,
                        "download failed event"
                    );
                    self.state.download_progress.remove(&attachment_id);
                    self.state
                        .download_error
                        .insert(attachment_id, error.to_string());
                    self.state.attach_updates += 1;
                }
            }
        }
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add(screens::image_viewer::ImageViewer(
                &mut self.state.image_viewer,
            ));
            if let Some(e) = self.state.error_dialog.clone() {
                Modal::new("error_modal".into()).show(ctx, |ui| {
                    ui.heading("Error");
                    ui.label(e);
                    if ui.button("OK").clicked() {
                        self.state.error_dialog = None;
                    }
                });
            }
            match self.state.logged_in {
                Some(true) => {
                    ui.push_id("steady_state", |ui| {
                        ui.add(screens::steady_state::SteadyState(self));
                    });
                }
                Some(false) => {
                    ui.push_id("login", |ui| {
                        ui.add(screens::login::Login(self));
                    });
                }
                None => {}
            }
        });
        if self.state.prefs.debug_mode {
            show_debug_ui(ctx);
        }
        if self.state.prefs != self.state.last_saved_prefs {
            if let Err(err) = save_prefs(&crate::utils::folders::prefs_path(), &self.state.prefs) {
                tracing::warn!(error = %err, "failed to save prefs");
            } else {
                self.state.last_saved_prefs = self.state.prefs.clone();
            }
        }
        if start.elapsed() > Duration::from_millis(10) {
            tracing::warn!(elapsed = debug(start.elapsed()), "drawn took a while :(");
        }
    }
}

fn main() -> eframe::Result<()> {
    // #[cfg(target_os = "linux")]
    // {
    //     // SAFETY: this happens at process start, before any threads are spawned.
    //     unsafe {
    //         std::env::set_var("WINIT_UNIX_BACKEND", "x11");
    //         std::env::set_var("XDG_SESSION_TYPE", "x11");
    //         std::env::remove_var("WAYLAND_DISPLAY");
    //     }
    // }
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(
            "nullspace=debug,nullspace_egui=debug",
        ))
        .init();

    let cli = Cli::parse();
    tracing::info!(
        winit_unix_backend = %std::env::var("WINIT_UNIX_BACKEND").unwrap_or_else(|_| "<unset>".to_string()),
        xdg_session_type = %std::env::var("XDG_SESSION_TYPE").unwrap_or_else(|_| "<unset>".to_string()),
        wayland_display = %std::env::var("WAYLAND_DISPLAY").unwrap_or_else(|_| "<unset>".to_string()),
        "window backend environment"
    );

    if let Err(err) = crate::utils::folders::init(cli.data_dir) {
        tracing::warn!(error = %err, "failed to initialize folders");
        return Ok(());
    }
    let single_instance = match init_single_instance() {
        Ok(Some(guard)) => guard,
        Ok(None) => return Ok(()),
        Err(err) => {
            tracing::warn!(error = %err, "single-instance setup failed");
            return Ok(());
        }
    };
    let prefs_path = crate::utils::folders::prefs_path();
    let prefs = load_prefs(&prefs_path).unwrap_or_default();
    let config = Config {
        db_path: crate::utils::folders::db_path(),
        dir_endpoint: Url::parse(&cli.dir_endpoint).expect("dir endpoint"),
        dir_anchor_pk: cli
            .dir_anchor_pk
            .parse::<SigningPublic>()
            .expect("dir anchor pk"),
    };
    let client = Client::new(config);
    let options = eframe::NativeOptions {
        renderer: eframe::Renderer::Glow,
        ..Default::default()
    };

    eframe::run_native(
        "nullspace-egui",
        options,
        Box::new(move |cc| {
            Ok(Box::new(NullspaceApp::new(
                cc,
                single_instance,
                client,
                prefs,
            )))
        }),
    )
}

fn supports_hide_window() -> bool {
    if cfg!(target_os = "linux") {
        if matches!(
            std::env::var("WINIT_UNIX_BACKEND").ok().as_deref(),
            Some("x11")
        ) {
            return true;
        }
        if std::env::var_os("WAYLAND_DISPLAY").is_some() {
            return false;
        }
        if matches!(
            std::env::var("XDG_SESSION_TYPE").ok().as_deref(),
            Some("wayland")
        ) {
            return false;
        }
    }
    true
}

fn configure_theme_styles(ctx: &egui::Context) {
    for theme in [egui::Theme::Light, egui::Theme::Dark] {
        ctx.style_mut_of(theme, |style| {
            style.spacing.item_spacing = egui::vec2(6.0, 6.0);
            style.spacing.window_margin = egui::Margin::same(8);
            style.spacing.button_padding = egui::vec2(8.0, 4.0);
            style.spacing.scroll = ScrollStyle::floating();
            for wid in [
                &mut style.visuals.widgets.active,
                &mut style.visuals.widgets.hovered,
                &mut style.visuals.widgets.noninteractive,
                &mut style.visuals.widgets.open,
                &mut style.visuals.widgets.inactive,
            ] {
                wid.corner_radius = egui::CornerRadius::ZERO.at_least(6);
            }
            style.visuals.widgets.hovered.expansion = 0.0;
            style.visuals.widgets.active.expansion = 0.0;
            style.visuals.widgets.open.expansion = 0.0;
            style.text_styles.insert(
                egui::TextStyle::Heading,
                egui::FontId::new(14.0, egui::FontFamily::Name("main_bold".into())),
            );
            style.visuals.window_shadow.offset = [0, 0];
            style.visuals.window_shadow.blur = 30;
            style.visuals.window_shadow.color = Color32::from_black_alpha(25);
            style.visuals.popup_shadow = style.visuals.window_shadow;
            style.interaction.selectable_labels = false;
            style.visuals.interact_cursor = Some(egui::CursorIcon::PointingHand);
        });
    }
}

fn apply_theme_preference(ctx: &egui::Context, theme: AppTheme) {
    ctx.set_theme(theme.to_egui());
}

fn apply_debug_mode(ctx: &egui::Context, debug_mode: bool) {
    #[cfg(debug_assertions)]
    ctx.set_debug_on_hover(debug_mode);

    #[cfg(not(debug_assertions))]
    let _ = (ctx, debug_mode);
}

fn show_debug_ui(ctx: &egui::Context) {
    egui::Window::new("egui Debug")
        .default_width(420.0)
        .vscroll(true)
        .show(ctx, |ui| {
            egui::warn_if_debug_build(ui);

            ui.collapsing("Settings", |ui| {
                ctx.settings_ui(ui);
            });
            ui.collapsing("Inspection", |ui| {
                ctx.inspection_ui(ui);
            });
            ui.collapsing("Memory", |ui| {
                ctx.memory_ui(ui);
            });
            ui.collapsing("Style", |ui| {
                ctx.style_ui(ui, ctx.theme());
            });
        });
}

fn load_prefs(path: &PathBuf) -> Option<PrefData> {
    let data = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&data).ok()
}

fn save_prefs(path: &PathBuf, prefs: &PrefData) -> Result<(), anyhow::Error> {
    let data = serde_json::to_string_pretty(prefs)?;
    std::fs::write(path, data)?;
    Ok(())
}

struct SingleInstanceGuard {
    _lock_file: std::fs::File,
}

fn init_single_instance() -> anyhow::Result<Option<SingleInstanceGuard>> {
    let dir = crate::utils::folders::root_dir();
    let lock_path = dir.join(INSTANCE_LOCK_FILE);
    let lock_file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(lock_path)?;

    match lock_file.try_lock_exclusive() {
        Ok(()) => Ok(Some(SingleInstanceGuard {
            _lock_file: lock_file,
        })),
        Err(err) if matches!(err.kind(), ErrorKind::WouldBlock) => {
            if let Err(signal_err) = signal_existing_instance() {
                tracing::warn!(error = %signal_err, "failed to notify existing instance");
            }
            Ok(None)
        }
        Err(err) => Err(err.into()),
    }
}

#[cfg(unix)]
fn signal_existing_instance() -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    let socket_path = crate::utils::folders::root_dir().join(INSTANCE_SIGNAL_SOCKET);
    let mut last_err = None;
    for _ in 0..20 {
        match UnixStream::connect(&socket_path) {
            Ok(mut stream) => {
                stream.write_all(&[1])?;
                return Ok(());
            }
            Err(err) => {
                last_err = Some(err);
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
    Err(last_err.unwrap_or_else(|| std::io::Error::other("failed to notify instance")))
}

#[cfg(not(unix))]
fn signal_existing_instance() -> std::io::Result<()> {
    Ok(())
}

#[cfg(unix)]
struct ActivationListener {
    listener: std::os::unix::net::UnixListener,
    socket_path: PathBuf,
}

#[cfg(unix)]
impl ActivationListener {
    fn bind(dir: &std::path::Path) -> std::io::Result<Self> {
        let socket_path = dir.join(INSTANCE_SIGNAL_SOCKET);
        let _ = std::fs::remove_file(&socket_path);
        let listener = std::os::unix::net::UnixListener::bind(&socket_path)?;
        listener.set_nonblocking(true)?;
        Ok(Self {
            listener,
            socket_path,
        })
    }

    fn poll_activation(&mut self) -> bool {
        let mut activated = false;
        loop {
            match self.listener.accept() {
                Ok((_stream, _addr)) => {
                    activated = true;
                }
                Err(err) if matches!(err.kind(), ErrorKind::WouldBlock) => break,
                Err(err) => {
                    tracing::warn!(error = %err, "activation listener failed");
                    break;
                }
            }
        }
        activated
    }
}

#[cfg(unix)]
impl Drop for ActivationListener {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

#[cfg(unix)]
fn activation_listener() -> Option<ActivationListener> {
    match ActivationListener::bind(crate::utils::folders::root_dir()) {
        Ok(listener) => Some(listener),
        Err(err) => {
            tracing::warn!(error = %err, "failed to start activation listener");
            None
        }
    }
}
