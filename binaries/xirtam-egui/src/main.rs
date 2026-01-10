use std::path::PathBuf;

use eframe::egui::{self, Modal, Spinner};
use tokio::{
    runtime::Runtime,
    sync::mpsc::{self, Receiver},
};
use url::Url;
use xirtam_client::{Client, Config, internal::Event};
use xirtam_crypt::signing::SigningPublic;

mod component;
mod promises;
mod screens;

const DEFAULT_DIR_ENDPOINT: &str = "http://127.0.0.1:4000";
const DEFAULT_DIR_ANCHOR_PK: &str = "OnF3Jh7tZ4o3g3bmUdgjTDa4qlMHN-2Q4RrJQD6K124";

struct XirtamApp {
    client: Client,
    recv_event: Receiver<Event>,
    state: AppState,
}

#[derive(Default)]
struct AppState {
    logged_in: Option<bool>,
    update_count: u64,
    error_dialog: Option<String>,
}

impl XirtamApp {
    fn new(cc: &eframe::CreationContext<'_>, client: Client, recv_event: Receiver<Event>) -> Self {
        cc.egui_ctx.set_visuals(egui::Visuals::light());
        cc.egui_ctx.style_mut(|style| {
            style.spacing.item_spacing = egui::vec2(4.0, 4.0);
            style.spacing.window_margin = egui::Margin::same(24);
            style.spacing.button_padding = egui::vec2(8.0, 4.0);
            style.spacing.indent = 16.0;
        });
        cc.egui_ctx.set_zoom_factor(1.25);
        let mut fonts = egui::FontDefinitions::default();
        fonts.font_data.insert(
            "fantasque".to_string(),
            egui::FontData::from_static(include_bytes!("fonts/FantasqueSansMono-Regular.ttf"))
                .into(),
        );
        fonts.families.insert(
            egui::FontFamily::Proportional,
            vec!["fantasque".to_string()],
        );
        fonts
            .families
            .insert(egui::FontFamily::Monospace, vec!["fantasque".to_string()]);
        cc.egui_ctx.set_fonts(fonts);
        Self {
            client,
            recv_event,
            state: AppState::default(),
        }
    }
}

impl eframe::App for XirtamApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
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
                    ui.add(screens::steady_state::SteadyState(self));
                }
                Some(false) => {
                    ui.add(screens::login::Login(self));
                }
                None => {
                    ui.add(Spinner::new());
                }
            }
        });
    }
}

fn main() -> eframe::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(
            "xirtam=debug,xirtam_egui=debug",
        ))
        .init();
    let runtime = Runtime::new().expect("tokio runtime");
    let _guard = runtime.enter();
    let config = Config {
        db_path: default_db_path(),
        dir_endpoint: Url::parse(DEFAULT_DIR_ENDPOINT).expect("dir endpoint"),
        dir_anchor_pk: DEFAULT_DIR_ANCHOR_PK
            .parse::<SigningPublic>()
            .expect("dir anchor pk"),
    };
    let client = Client::new(config);
    let rpc = client.rpc();
    let (event_tx, event_rx) = mpsc::channel(64);
    runtime.spawn(async move {
        loop {
            match rpc.next_event().await {
                Ok(event) => {
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
        Box::new(move |cc| Ok(Box::new(XirtamApp::new(cc, client, event_rx)))),
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
