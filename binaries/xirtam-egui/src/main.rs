use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use clap::Parser;
use eframe::egui::{self, Modal, Spinner};
use notify_rust::Notification;
use tokio::{
    runtime::Runtime,
    sync::mpsc::{self, Receiver},
};
use url::Url;
use xirtam_client::{
    Client, Config,
    internal::{DmDirection, Event},
};
use xirtam_crypt::signing::SigningPublic;

use crate::promises::flatten_rpc;
use crate::utils::prefs::PrefData;

mod promises;
mod screens;
mod utils;
mod widgets;

const DEFAULT_DIR_ENDPOINT: &str = "https://xirtam-test-directory.nullfruit.net/";
const DEFAULT_DIR_ANCHOR_PK: &str = "M7nRvqmTOKOyF2HxhjdVxAKUIqANb4jXa5EKZ2UFD8I";

#[derive(Debug, Parser)]
#[command(name = "xirtam-egui", about = "Minimal xirtam GUI client")]
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

struct XirtamApp {
    client: Client,
    recv_event: Receiver<Event>,
    focused: Arc<AtomicBool>,
    prefs_path: PathBuf,
    state: AppState,
}

#[derive(Default)]
struct AppState {
    logged_in: Option<bool>,
    update_count: u64,
    error_dialog: Option<String>,
    prefs: PrefData,
    last_saved_prefs: PrefData,
}

impl XirtamApp {
    fn new(
        cc: &eframe::CreationContext<'_>,
        client: Client,
        recv_event: Receiver<Event>,
        focused: Arc<AtomicBool>,
        prefs_path: PathBuf,
        prefs: PrefData,
    ) -> Self {
        cc.egui_ctx.set_visuals(egui::Visuals::light());
        cc.egui_ctx.style_mut(|style| {
            style.spacing.item_spacing = egui::vec2(6.0, 6.0);
            style.spacing.window_margin = egui::Margin::same(24);
            style.spacing.button_padding = egui::vec2(6.0, 4.0);
            style.spacing.indent = 16.0;
            for wid in [
                &mut style.visuals.widgets.active,
                &mut style.visuals.widgets.hovered,
                &mut style.visuals.widgets.noninteractive,
                &mut style.visuals.widgets.open,
                &mut style.visuals.widgets.inactive,
            ] {
                wid.corner_radius = egui::CornerRadius::ZERO;
            }
        });
        // cc.egui_ctx.set_zoom_factor(1.25);
        let mut fonts = egui::FontDefinitions::default();
        fonts.font_data.insert(
            "fantasque".to_string(),
            egui::FontData::from_static(include_bytes!("fonts/FantasqueSansMono-Regular.ttf"))
                .into(),
        );
        fonts.font_data.insert(
            "fantasque_bold".to_string(),
            egui::FontData::from_static(include_bytes!("fonts/FantasqueSansMono-Bold.ttf")).into(),
        );
        fonts.font_data.insert(
            "fantasque_italic".to_string(),
            egui::FontData::from_static(include_bytes!("fonts/FantasqueSansMono-Italic.ttf"))
                .into(),
        );
        fonts.font_data.insert(
            "fantasque_bold_italic".to_string(),
            egui::FontData::from_static(include_bytes!("fonts/FantasqueSansMono-BoldItalic.ttf"))
                .into(),
        );
        fonts.families.insert(
            egui::FontFamily::Name("fantasque".into()),
            vec!["fantasque".to_string()],
        );
        fonts.families.insert(
            egui::FontFamily::Name("fantasque_bold".into()),
            vec!["fantasque_bold".to_string()],
        );
        fonts.families.insert(
            egui::FontFamily::Name("fantasque_italic".into()),
            vec!["fantasque_italic".to_string()],
        );
        fonts.families.insert(
            egui::FontFamily::Name("fantasque_bold_italic".into()),
            vec!["fantasque_bold_italic".to_string()],
        );
        fonts.families.insert(
            egui::FontFamily::Proportional,
            vec!["fantasque".to_string()],
        );
        fonts
            .families
            .insert(egui::FontFamily::Monospace, vec!["fantasque".to_string()]);
        cc.egui_ctx.set_fonts(fonts);
        cc.egui_ctx
            .set_zoom_factor(prefs.zoom_percent as f32 / 100.0);
        Self {
            client,
            recv_event,
            focused,
            prefs_path,
            state: AppState {
                prefs: prefs.clone(),
                last_saved_prefs: prefs,
                ..AppState::default()
            },
        }
    }
}

impl eframe::App for XirtamApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        ctx.set_zoom_factor(self.state.prefs.zoom_percent as f32 / 100.0);
        let focused = ctx.input(|i| i.viewport().focused).unwrap_or(true);
        tracing::debug!(focused, "am I focused?");
        self.focused.store(focused, Ordering::Relaxed);
        if let Ok(event) = self.recv_event.try_recv() {
            tracing::debug!(event = ?event, "processing xirtam event");
            match event {
                Event::State { logged_in } => self.state.logged_in = Some(logged_in),
                Event::DmUpdated { peer } => {
                    let _ = peer;
                    self.state.update_count = self.state.update_count.saturating_add(1);
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
                eprintln!("failed to save prefs: {err}");
            } else {
                self.state.last_saved_prefs = self.state.prefs.clone();
            }
        }
        ctx.request_repaint_after(Duration::from_millis(200));
    }
}

fn main() -> eframe::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(
            "xirtam=debug,xirtam_egui=debug",
        ))
        .init();
    let cli = Cli::parse();
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
    let rpc = client.rpc();
    let (event_tx, event_rx) = mpsc::channel(64);
    let focused = Arc::new(AtomicBool::new(true));
    let focused_task = focused.clone();
    runtime.spawn(async move {
        let mut max_notified = 0;
        loop {
            // tokio::time::sleep(Duration::from_secs(1)).await;
            match rpc.next_event().await {
                Ok(event) => {
                    if let Event::DmUpdated { peer } = &event {
                        if !focused_task.load(Ordering::Relaxed) {
                            match flatten_rpc(rpc.dm_history(peer.clone(), None, None, 1).await) {
                                Ok(messages) => {
                                    if let Some(message) = messages.last() {
                                        if matches!(message.direction, DmDirection::Incoming)
                                            && message.received_at.unwrap_or_default().0
                                                > max_notified
                                        {
                                            max_notified =
                                                message.received_at.unwrap_or_default().0;
                                            let body =
                                                String::from_utf8_lossy(&message.body).to_string();
                                            if let Err(err) = Notification::new()
                                                .summary(&format!(
                                                    "Message from {}",
                                                    message.sender
                                                ))
                                                .body(&body)
                                                .show()
                                            {
                                                eprintln!("notification error: {err}");
                                            }
                                        }
                                    }
                                }
                                Err(err) => {
                                    eprintln!("failed to fetch latest message: {err}");
                                }
                            }
                        }
                    }
                    if event_tx.send(event).await.is_err() {
                        break;
                    }
                }
                Err(err) => {
                    eprintln!("event loop error: {err}");
                }
            }
        }
    });
    let options = eframe::NativeOptions::default();
    eframe::run_native(
        "xirtam-egui",
        options,
        Box::new(move |cc| {
            Ok(Box::new(XirtamApp::new(
                cc, client, event_rx, focused, prefs_path, prefs,
            )))
        }),
    )
}

fn default_db_path() -> PathBuf {
    let base_dir = dirs::config_dir()
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_else(|| PathBuf::from("."));
    let dir = base_dir.join("xirtam");
    if let Err(err) = std::fs::create_dir_all(&dir) {
        eprintln!("failed to create config dir: {err}");
    }
    dir.join("xirtam-client.db")
}

fn default_prefs_path() -> PathBuf {
    let base_dir = dirs::config_dir()
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_else(|| PathBuf::from("."));
    let dir = base_dir.join("xirtam");
    if let Err(err) = std::fs::create_dir_all(&dir) {
        eprintln!("failed to create config dir: {err}");
    }
    dir.join("xirtam-egui.json")
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
