use crate::utils::color::username_color;
use crate::widgets::convo::default_download_dir;
use eframe::egui::{Response, RichText, Widget};
use egui::{Color32, TextFormat};
use egui::{TextStyle, text::LayoutJob};
use nullspace_client::internal::MessageContent;
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
        render_content(ui, self.app, self.message)
    }
}

fn render_content(
    ui: &mut eframe::egui::Ui,
    app: &mut NullspaceApp,
    message: &nullspace_client::internal::ConvoMessage,
) -> Response {
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
    let sender_color = username_color(&message.sender);

    ui.horizontal_top(|ui| {
        ui.colored_label(sender_color, format!("{}: ", message.sender));
        ui.vertical(|ui| {
            match &message.body {
                MessageContent::GroupInvite { invite_id } => {
                    ui.horizontal_top(|ui| {
                        ui.colored_label(Color32::GRAY, "Invitation to group");
                        if ui.link("Accept").clicked() {
                            let rpc = app.client.rpc();
                            let invite_id = *invite_id;
                            tokio::spawn(async move {
                                let _ = flatten_rpc(rpc.group_accept_invite(invite_id).await);
                            });
                        }
                    });
                }
                MessageContent::Attachment { id, size, mime } => {
                    let (unit_scale, unit_suffix) = unit_for_bytes(*size);
                    let size_text = format_filesize(*size, unit_scale);
                    let attachment_label = format!("[{mime} {size_text} {unit_suffix}]");
                    ui.horizontal_top(|ui| {
                        ui.colored_label(Color32::DARK_BLUE, attachment_label);
                        if ui.small_button("Open").clicked() {
                            if let Ok(Ok(status)) =
                                app.client.rpc().attachment_status(*id).block_on()
                                && let Some(path) = status.saved_to
                            {
                                let _ = open::that_detached(path);
                            } else {
                                let save_dir = default_download_dir();
                                let rpc = app.client.rpc();
                                let Ok(download_id) =
                                    flatten_rpc(rpc.attachment_download(*id, save_dir).block_on())
                                else {
                                    return;
                                };
                                app.state.download_for_msg.insert(message.id, download_id);
                            }
                        }
                    });
                    if let Some(download_id) = app.state.download_for_msg.get(&message.id) {
                        if let Some((downloaded, total)) =
                            app.state.download_progress.get(download_id)
                        {
                            let speed_key = format!("download-{download_id}");
                            let (left, speed, right) = speed_fmt(&speed_key, *downloaded, *total);
                            let speed_text = if right.is_empty() {
                                if speed.is_empty() {
                                    format!("Downloading: {left}")
                                } else {
                                    format!("Downloading: {left} @ {speed}")
                                }
                            } else if speed.is_empty() {
                                format!("Downloading: {left}, {right} remaining")
                            } else {
                                format!("Downloading: {left} @ {speed}, {right} remaining")
                            };
                            ui.label(
                                RichText::new(speed_text.to_string())
                                    .color(Color32::GRAY)
                                    .size(11.0),
                            );
                        } else if let Some(error) = app.state.download_error.get(download_id) {
                            ui.label(
                                RichText::new(format!("Download failed: {error}"))
                                    .color(Color32::RED)
                                    .size(11.0),
                            );
                        }
                    }
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
        })
    });
    ui.response()
}
