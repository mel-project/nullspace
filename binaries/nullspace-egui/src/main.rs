use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use clap::Parser;

use egui::{Modal, Spinner};
use egui_file_dialog::FileDialog as EguiFileDialog;
use nullspace_client::{Client, Config, internal::Event};
use nullspace_crypt::hash::Hash;
use nullspace_crypt::signing::SigningPublic;
use nullspace_structs::fragment::Attachment;
use tokio::{
    runtime::Runtime,
    sync::mpsc::{self, Receiver},
};
use url::Url;

use crate::events::{event_loop, spawn_audio_thread};
use crate::fonts::load_fonts;
use crate::utils::prefs::PrefData;
use crate::utils::profile_loader::ProfileLoader;

mod events;
mod fonts;
mod notify;
mod promises;
mod rpc;
mod screens;
mod tray;
mod utils;
mod widgets;

const DEFAULT_DIR_ENDPOINT: &str = "https://xirtam-test-directory.nullfruit.net/";
const DEFAULT_DIR_ANCHOR_PK: &str = "bpOJ5ga-oQjb0njgBV5CtEZIVU6wjvltXjsQ_10BNlM";

#[derive(Debug, Parser)]
#[command(name = "nullspace-egui", about = "Minimal nullspace GUI client")]
struct Cli {
    #[arg(long)]
    db_path: Option<PathBuf>,
    #[arg(long)]
    prefs_path: Option<PathBuf>,
    #[arg(long, default_value = DEFAULT_DIR_ENDPOINT)]
    dir_endpoint: String,
    #[arg(long, default_value = DEFAULT_DIR_ANCHOR_PK)]
    dir_anchor_pk: String,
}

struct NullspaceApp {
    recv_event: Receiver<Event>,
    focused: Arc<AtomicBool>,
    prefs_path: PathBuf,
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
    msg_updates: u64,
    error_dialog: Option<String>,
    prefs: PrefData,
    last_saved_prefs: PrefData,

    profile_loader: ProfileLoader,

    attach_updates: u64,

    upload_progress: BTreeMap<i64, (u64, u64)>,
    upload_done: BTreeMap<i64, Attachment>,
    upload_error: BTreeMap<i64, String>,
    download_progress: BTreeMap<Hash, (u64, u64)>,
    download_error: BTreeMap<Hash, String>,
}

impl NullspaceApp {
    fn new(
        cc: &eframe::CreationContext<'_>,
        client: Client,
        prefs_path: PathBuf,
        prefs: PrefData,
    ) -> Self {
        crate::rpc::init_rpc(client.rpc());
        let (event_tx, recv_event) = mpsc::channel(64);
        let focused = Arc::new(AtomicBool::new(true));
        let audio_tx = spawn_audio_thread();
        let ctx = cc.egui_ctx.clone();
        tokio::spawn(event_loop(ctx, event_tx, focused.clone(), audio_tx));
        egui_extras::install_image_loaders(&cc.egui_ctx);
        cc.egui_ctx.set_visuals(egui::Visuals::light());
        catppuccin_egui::set_theme(&cc.egui_ctx, catppuccin_egui::LATTE);

        // Enable multi-pass layout for egui_taffy
        cc.egui_ctx.options_mut(|options| {
            options.max_passes = std::num::NonZeroUsize::new(2).unwrap();
        });

        cc.egui_ctx.style_mut(|style| {
            style.spacing.item_spacing = egui::vec2(6.0, 6.0);
            // style.spacing.window_margin = egui::Margin::same(24);
            style.spacing.button_padding = egui::vec2(6.0, 4.0);
            style.spacing.indent = 16.0;
            // style.spacing.scroll = ScrollStyle::solid();
            // for wid in [
            //     &mut style.visuals.widgets.active,
            //     &mut style.visuals.widgets.hovered,
            //     &mut style.visuals.widgets.noninteractive,
            //     &mut style.visuals.widgets.open,
            //     &mut style.visuals.widgets.inactive,
            // ] {
            //     wid.corner_radius = egui::CornerRadius::ZERO.at_least(4);
            // }
            // style.debug.debug_on_hover = true; // show callstack / rects on hover
            // style.debug.show_expand_width = true; // highlight width expanders
            // style.debug.show_expand_height = true; // highlight height expanders
            // style.debug.show_resize = true; // show resize handles
        });
        // cc.egui_ctx.set_zoom_factor(1.25);
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
        let cache_dir = prefs_path
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."))
            .join("profile-cache");
        Self {
            recv_event,
            focused,
            prefs_path,
            file_dialog: EguiFileDialog::new(),
            profile_file_dialog: EguiFileDialog::new(),
            tray,
            tray_hidden: false,
            pending_quit: false,
            supports_hide,
            state: AppState {
                logged_in: None,
                msg_updates: 0,
                error_dialog: None,
                prefs: prefs.clone(),
                last_saved_prefs: prefs,
                profile_loader: ProfileLoader::new(cache_dir),
                attach_updates: 0,
                upload_progress: BTreeMap::new(),
                upload_done: BTreeMap::new(),
                upload_error: BTreeMap::new(),
                download_progress: BTreeMap::new(),
                download_error: BTreeMap::new(),
            },
        }
    }
}

impl eframe::App for NullspaceApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        ctx.set_zoom_factor(self.state.prefs.zoom_percent as f32 / 100.0);
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
                Event::State { logged_in } => self.state.logged_in = Some(logged_in),
                Event::ConvoUpdated { convo_id } => {
                    let _ = convo_id;
                    self.state.msg_updates = self.state.msg_updates.saturating_add(1);
                }
                Event::GroupUpdated { group } => {
                    let _ = group;
                    self.state.msg_updates = self.state.msg_updates.saturating_add(1);
                }
                Event::UploadProgress {
                    id,
                    uploaded_size,
                    total_size,
                } => {
                    tracing::debug!(id, uploaded_size, total_size, "upload progress event");

                    self.state
                        .upload_progress
                        .insert(id, (uploaded_size, total_size));
                }
                Event::UploadDone { id, root } => {
                    tracing::debug!(id, root = ?root, "upload done event");
                    self.state.upload_progress.remove(&id);
                    self.state.upload_done.insert(id, root);
                    self.state.upload_error.remove(&id);
                    self.state.attach_updates += 1;
                }
                Event::UploadFailed { id, error } => {
                    tracing::warn!(id, error = %error, "upload failed event");
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
                None => {
                    ui.push_id("loading", |ui| {
                        ui.add(Spinner::new());
                    });
                }
            }
        });
        if self.state.prefs != self.state.last_saved_prefs {
            if let Err(err) = save_prefs(&self.prefs_path, &self.state.prefs) {
                tracing::warn!(error = %err, "failed to save prefs");
            } else {
                self.state.last_saved_prefs = self.state.prefs.clone();
            }
        }
        let repaint_after = if self.tray_hidden {
            Duration::from_secs(1)
        } else {
            Duration::from_millis(100)
        };
        ctx.request_repaint_after(repaint_after);
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

    let runtime = Runtime::new().expect("tokio runtime");
    let _guard = runtime.enter();
    let prefs_path = cli.prefs_path.unwrap_or_else(default_prefs_path);
    let prefs = load_prefs(&prefs_path).unwrap_or_default();
    let config = Config {
        db_path: cli.db_path.unwrap_or_else(default_db_path),
        dir_endpoint: Url::parse(&cli.dir_endpoint).expect("dir endpoint"),
        dir_anchor_pk: cli
            .dir_anchor_pk
            .parse::<SigningPublic>()
            .expect("dir anchor pk"),
    };
    let client = Client::new(config);
    let mut options = eframe::NativeOptions::default();
    options.renderer = eframe::Renderer::Wgpu;

    eframe::run_native(
        "nullspace-egui",
        options,
        Box::new(move |cc| Ok(Box::new(NullspaceApp::new(cc, client, prefs_path, prefs)))),
    )
}

fn default_db_path() -> PathBuf {
    let base_dir = dirs::config_dir()
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_else(|| PathBuf::from("."));
    let dir = base_dir.join("nullspace-egui");
    if let Err(err) = std::fs::create_dir_all(&dir) {
        tracing::warn!(error = %err, "failed to create config dir");
    }
    dir.join("nullspace-client.db")
}

fn default_prefs_path() -> PathBuf {
    let base_dir = dirs::config_dir()
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_else(|| PathBuf::from("."));
    let dir = base_dir.join("nullspace-egui");
    if let Err(err) = std::fs::create_dir_all(&dir) {
        tracing::warn!(error = %err, "failed to create config dir");
    }
    dir.join("nullspace-egui.json")
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

fn load_prefs(path: &PathBuf) -> Option<PrefData> {
    let data = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&data).ok()
}

fn save_prefs(path: &PathBuf, prefs: &PrefData) -> Result<(), anyhow::Error> {
    let data = serde_json::to_string_pretty(prefs)?;
    std::fs::write(path, data)?;
    Ok(())
}
