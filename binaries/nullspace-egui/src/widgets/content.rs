use core::f32;
use std::path::PathBuf;

use crate::utils::color::username_color;

use eframe::egui::{Response, RichText, Widget};
use egui::{Color32, ProgressBar, Rect, Sense, TextFormat};
use egui::{TextStyle, text::LayoutJob};
use egui_hooks::UseHookExt;
use nullspace_client::internal::MessageContent;
use nullspace_crypt::hash::Hash;
use pollster::FutureExt;

use crate::NullspaceApp;
use crate::promises::flatten_rpc;
use crate::utils::markdown::layout_md_raw;
use crate::utils::speed::speed_fmt;
use crate::utils::units::{format_filesize, unit_for_bytes};

pub struct Content<'a> {
    pub app: &'a mut NullspaceApp,
    pub message: &'a nullspace_client::internal::ConvoMessage,
}

impl Widget for Content<'_> {
    fn ui(self, ui: &mut eframe::egui::Ui) -> Response {
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
        if self.message.send_error.is_some() {
            base_text_format.strikethrough = egui::Stroke::new(1.0, Color32::BLACK);
        }
        let sender_color = username_color(&self.message.sender);

        ui.horizontal_top(|ui| {
            ui.colored_label(sender_color, format!("{}: ", self.message.sender));
            ui.vertical(|ui| {
                match &self.message.body {
                    MessageContent::GroupInvite { invite_id } => {
                        ui.horizontal_top(|ui| {
                            ui.colored_label(Color32::GRAY, "Invitation to group");
                            if ui.link("Accept").clicked() {
                                let rpc = self.app.client.rpc();
                                let invite_id = *invite_id;
                                tokio::spawn(async move {
                                    let _ = flatten_rpc(rpc.group_accept_invite(invite_id).await);
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
                                app: self.app,
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

                if let Some(err) = &self.message.send_error {
                    ui.label(
                        RichText::new(format!("Send failed: {err}"))
                            .color(Color32::RED)
                            .size(11.0),
                    );
                }
            })
        });
        ui.response()
    }
}

pub struct AttachmentContent<'a> {
    pub app: &'a mut NullspaceApp,
    pub id: Hash,
    pub size: u64,
    pub mime: &'a str,
    pub filename: &'a str,
}

impl Widget for AttachmentContent<'_> {
    fn ui(self, ui: &mut eframe::egui::Ui) -> Response {
        let status = ui.use_memo(
            || flatten_rpc(self.app.client.rpc().attachment_status(self.id).block_on()),
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
            let rpc = self.app.client.rpc();
            let _ = flatten_rpc(rpc.attachment_download(self.id, save_dir).block_on());
        });
        let (unit_scale, unit_suffix) = unit_for_bytes(self.size);
        let size_text = format_filesize(self.size, unit_scale);
        let attachment_label =
            format!("\u{ea7b} [{} {}] {}", size_text, unit_suffix, self.filename);

        ui.colored_label(Color32::DARK_BLUE, attachment_label);

        if self.mime.starts_with("image/") {
            if let Some(path) = dl_path {
                // WORKAROUND: egui doesn't actually want a "real" URI with URI-encoding etc.
                let path_str = path.to_string_lossy();
                #[cfg(windows)]
                let path_str = path_str.replace('\\', "/");
                let uri = format!("file://{path_str}");
                let box_width = ui.available_width().min(500.0);
                let max_box = egui::vec2(ui.available_width(), box_width * 0.6);
                ui.add(
                    egui::Image::from_uri(uri)
                        .fit_to_exact_size(max_box)
                        .show_loading_spinner(false),
                );
            } else if !*image_downloading {
                if let Some(limit) = self.app.state.prefs.max_auto_image_download_bytes
                    && self.size <= limit
                {
                    image_downloading.set_next(true);
                    start_dl!();
                }
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

pub fn default_download_dir() -> PathBuf {
    dirs::download_dir()
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_else(|| PathBuf::from("."))
}
