use core::f32;
use std::path::PathBuf;

use eframe::egui::{Response, RichText, Widget};
use egui::{
    Align, Color32, CornerRadius, Frame, Layout, Margin, ProgressBar, TextFormat, TextStyle,
    text::LayoutJob,
};
use egui_hooks::UseHookExt;
use nullspace_client::internal::{ConvoMessage, MessageContent};
use nullspace_crypt::hash::Hash;
use nullspace_structs::{timestamp::NanoTimestamp, username::UserName};
use pollster::FutureExt;

use crate::promises::flatten_rpc;
use crate::rpc::get_rpc;
use crate::utils::color::username_color;
use crate::utils::markdown::layout_md_raw;
use crate::utils::prefs::ConvoRowStyle;
use crate::utils::speed::speed_fmt;
use crate::utils::units::{format_filesize, unit_for_bytes};
use crate::widgets::smooth::SmoothImage;
use crate::{NullspaceApp, widgets::avatar::Avatar};

pub struct ConvoRow<'a> {
    pub app: &'a mut NullspaceApp,
    pub message: &'a ConvoMessage,
    pub style: ConvoRowStyle,
}

impl Widget for ConvoRow<'_> {
    fn ui(self, ui: &mut eframe::egui::Ui) -> Response {
        match self.style {
            ConvoRowStyle::Text => self.text_ui(ui),
            ConvoRowStyle::Bubbles => self.bubble_ui(ui),
        }
    }
}

impl ConvoRow<'_> {
    fn text_ui(self, ui: &mut eframe::egui::Ui) -> Response {
        let sender_label = self
            .app
            .state
            .profile_loader
            .label_for(&self.message.sender);

        let sender_color = username_color(&self.message.sender);
        let timestamp = format_timestamp(self.message.received_at);

        ui.horizontal_top(|ui| {
            ui.label(RichText::new(format!("[{timestamp}]")).color(Color32::GRAY));
            ui.colored_label(sender_color, format!("{}: ", sender_label));
            render_message_body(ui, self.app, self.message);
        });
        ui.add_space(4.0);
        ui.response()
    }

    fn bubble_ui(self, ui: &mut eframe::egui::Ui) -> Response {
        let sender_label = self
            .app
            .state
            .profile_loader
            .label_for(&self.message.sender);
        let sender_color = username_color(&self.message.sender);
        let avatar = self
            .app
            .state
            .profile_loader
            .view(&self.message.sender)
            .and_then(|details| details.avatar);
        let timestamp = format_timestamp(self.message.received_at);
        ui.push_id(self.message.received_at, |ui| {
            ui.horizontal_top(|ui| {
                ui.add(Avatar {
                    sender: self.message.sender.clone(),
                    attachment: avatar,
                    size: 36.0,
                });
                ui.vertical(|ui| {
                    ui.horizontal_top(|ui| {
                        ui.label(
                            RichText::new(sender_label)
                                .color(sender_color)
                                .family(egui::FontFamily::Name("main_bold".into())),
                        );
                        ui.label(RichText::new(format!("{timestamp}")).color(Color32::GRAY));
                    });
                    render_message_body(ui, self.app, self.message);
                })
            });
            ui.add_space(8.0);
            ui.response()
        })
        .response
    }
}

fn render_message_body(ui: &mut eframe::egui::Ui, app: &mut NullspaceApp, message: &ConvoMessage) {
    let font_id = ui
        .style()
        .text_styles
        .get(&TextStyle::Body)
        .cloned()
        .unwrap();
    let mut base_text_format = TextFormat {
        color: Color32::BLACK,
        font_id,
        ..Default::default()
    };
    if message.send_error.is_some() {
        base_text_format.strikethrough = egui::Stroke::new(1.0, Color32::BLACK);
    }
    ui.vertical(|ui| {
        match &message.body {
            MessageContent::GroupInvite { invite_id } => {
                ui.horizontal_top(|ui| {
                    ui.colored_label(Color32::GRAY, "Invitation to group");
                    if ui.link("Accept").clicked() {
                        let invite_id = *invite_id;
                        tokio::spawn(async move {
                            let _ = flatten_rpc(get_rpc().group_accept_invite(invite_id).await);
                        });
                    }
                });
            }
            MessageContent::Attachment {
                id,
                size,
                mime,
                filename,
            } => {
                ui.push_id(id, |ui| {
                    ui.add(AttachmentContent {
                        app,
                        id: *id,
                        size: *size,
                        mime,
                        filename,
                    });
                });
            }
            MessageContent::PlainText(text) => {
                let mut job = LayoutJob::default();
                job.append(text, 0.0, base_text_format.clone());
                ui.label(job);
            }
            MessageContent::Markdown(text) => {
                let mut job = LayoutJob::default();
                layout_md_raw(&mut job, base_text_format.clone(), text);
                ui.label(job);
            }
        };

        if let Some(err) = &message.send_error {
            ui.label(
                RichText::new(format!("Send failed: {err}"))
                    .color(Color32::RED)
                    .size(11.0),
            );
        }
    });
}

struct AttachmentContent<'a> {
    app: &'a mut NullspaceApp,
    id: Hash,
    size: u64,
    mime: &'a str,
    filename: &'a str,
}

impl Widget for AttachmentContent<'_> {
    fn ui(self, ui: &mut eframe::egui::Ui) -> Response {
        let status = ui.use_memo(
            || flatten_rpc(get_rpc().attachment_status(self.id).block_on()),
            self.app.state.attach_updates,
        );
        let dl_path = status.as_ref().ok().and_then(|s| s.saved_to.as_ref());
        let dl_progress = self
            .app
            .state
            .download_progress
            .get(&self.id)
            .map(|(downloaded, total)| (*downloaded, *total));
        let dl_error = self.app.state.download_error.get(&self.id);
        let image_downloading = ui.use_state(|| false, ());

        defmac::defmac!(start_dl => {
            let save_dir = default_download_dir();
            let _ = flatten_rpc(get_rpc().attachment_download(self.id, save_dir).block_on());
        });
        let (unit_scale, unit_suffix) = unit_for_bytes(self.size);
        let size_text = format_filesize(self.size, unit_scale);
        let attachment_label =
            format!("\u{ea7b} [{} {}] {}", size_text, unit_suffix, self.filename);

        ui.colored_label(Color32::DARK_BLUE, attachment_label);

        if self.mime.starts_with("image/") {
            if let Some(path) = dl_path {
                let box_width = ui.available_width().min(500.0);
                let max_box = egui::vec2(ui.available_width(), box_width * 0.6);

                ui.add(
                    SmoothImage::new(path.as_path())
                        .fit_to_size(max_box)
                        .corner_radius(CornerRadius::ZERO.at_least(8)),
                );
            } else if !*image_downloading
                && let Some(limit) = self.app.state.prefs.max_auto_image_download_bytes
                && self.size <= limit
            {
                image_downloading.set_next(true);
                start_dl!();
            }
        }

        if let Some((downloaded, total)) = dl_progress {
            let speed_key = format!("download-{}", self.id);
            let (left, speed, _) = speed_fmt(&speed_key, downloaded, total);
            let speed_text = format!("{left} @ {speed}");
            ui.add(
                ProgressBar::new(downloaded as f32 / total.max(1) as f32)
                    .text(speed_text)
                    .desired_width(400.0),
            );
        } else if let Some(error) = dl_error {
            ui.label(
                RichText::new(format!("Download failed: {error}"))
                    .color(Color32::RED)
                    .size(11.0),
            );
        } else {
            ui.horizontal(|ui| {
                if let Ok(status) = status.as_ref()
                    && let Some(path) = &status.saved_to
                {
                    if ui.small_button("Open").clicked() {
                        let _ = open::that_detached(path.clone());
                    }
                    if ui.small_button("Show in folder").clicked() {
                        let _ = open::that_detached(path.parent().unwrap());
                    }
                } else if ui.small_button("Download").clicked() {
                    start_dl!();
                }
            });
        }

        ui.response()
    }
}

fn format_timestamp(ts: Option<NanoTimestamp>) -> String {
    let Some(ts) = ts else {
        return "--:--".to_string();
    };
    let secs = (ts.0 / 1_000_000_000) as i64;
    let nsec = (ts.0 % 1_000_000_000) as u32;
    let Some(dt) = chrono::DateTime::from_timestamp(secs, nsec) else {
        return "--:--".to_string();
    };
    let local = dt.with_timezone(&chrono::Local);
    local.format("%H:%M").to_string()
}

fn default_download_dir() -> PathBuf {
    dirs::download_dir()
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_else(|| PathBuf::from("."))
}
