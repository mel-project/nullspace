use core::f32;
use std::path::PathBuf;

use eframe::egui::{Response, RichText, Widget};
use egui::{Color32, ProgressBar, Sense, TextFormat, TextStyle, text::LayoutJob};
use egui_hooks::UseHookExt;
use fast_thumbhash::thumb_hash_from_b91;
use nullspace_client::internal::ConvoMessage;
use nullspace_crypt::hash::BcsHashExt;
use nullspace_crypt::hash::Hash;
use nullspace_structs::event::MessageText;
use nullspace_structs::timestamp::NanoTimestamp;
use pollster::FutureExt;

use crate::rpc::flatten_rpc;
use crate::rpc::get_rpc;
use crate::utils::color::username_color;
use crate::utils::folders;
use crate::utils::prefs::ConvoRowStyle;
use crate::utils::speed::speed_fmt;
use crate::utils::units::{format_filesize, unit_for_bytes};
use crate::widgets::smooth::SmoothImage;
use crate::{NullspaceApp, widgets::avatar::Avatar};

const IMAGE_MAX_WIDTH: f32 = 400.0;
const IMAGE_MAX_HEIGHT: f32 = 400.0;

pub struct ConvoRow<'a> {
    pub app: &'a mut NullspaceApp,
    pub message: &'a ConvoMessage,
    pub style: ConvoRowStyle,
    pub is_beginning: bool,
    pub is_end: bool,
}

impl Widget for ConvoRow<'_> {
    fn ui(self, ui: &mut eframe::egui::Ui) -> Response {
        match self.style {
            ConvoRowStyle::Text => self.text_ui(ui),
            ConvoRowStyle::Friendly => self.friendly_ui(ui),
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
        ui.response()
    }

    fn friendly_ui(self, ui: &mut eframe::egui::Ui) -> Response {
        if self.message.received_at.is_none() {
            ui.set_opacity(0.5);
        }
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

        ui.horizontal_top(|ui| {
            // This "trick" makes avatar and no-avatar take the same space
            if self.is_beginning {
                let rect = egui::Rect::from_min_size(ui.cursor().min, egui::vec2(36.0, 36.0));
                ui.place(
                    rect,
                    Avatar {
                        sender: self.message.sender.clone(),
                        attachment: avatar,
                        size: 36.0,
                    },
                );
            }
            ui.add_space(36.0 + ui.style().spacing.item_spacing.x);

            ui.vertical(|ui| {
                if self.is_beginning {
                    ui.horizontal_top(|ui| {
                        ui.label(
                            RichText::new(sender_label)
                                .color(sender_color)
                                .family(egui::FontFamily::Name("main_bold".into())),
                        );
                        ui.label(RichText::new(timestamp.to_string()).color(Color32::GRAY));
                    });
                }
                render_message_body(ui, self.app, self.message);
            })
        });
        if self.is_end {
            ui.add_space(8.0);
        }
        ui.response()
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
        let text = match &message.body.payload {
            MessageText::Plain(text) | MessageText::Rich(text) => text,
        };
        if !text.is_empty() {
            let mut job = LayoutJob::default();
            job.append(text, 0.0, base_text_format.clone());
            ui.label(job);
        }

        for attachment in &message.body.attachments {
            let id = attachment.bcs_hash();
            ui.push_id(id, |ui| {
                ui.add(AttachmentContent {
                    app,
                    id,
                    size: attachment.total_size(),
                    filename: &attachment.filename,
                    mime: &attachment.mime,
                });
            });
        }

        for image in &message.body.images {
            let id = image.inner.bcs_hash();
            ui.push_id(id, |ui| {
                ui.add(ImageAttachmentContent {
                    app,
                    id,
                    size: image.inner.total_size(),
                    width: image.width,
                    height: image.height,
                    thumbhash: &image.thumbhash,
                    filename: &image.inner.filename,
                });
            });
        }

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
    filename: &'a str,
    mime: &'a str,
}

impl Widget for AttachmentContent<'_> {
    fn ui(self, ui: &mut eframe::egui::Ui) -> Response {
        let status = ui.use_memo(
            || flatten_rpc(get_rpc().attachment_status(self.id).block_on()),
            self.app.state.attach_updates,
        );
        let dl_progress = self
            .app
            .state
            .download_progress
            .get(&self.id)
            .map(|(downloaded, total)| (*downloaded, *total));
        let dl_error = self.app.state.download_error.get(&self.id);

        defmac::defmac!(start_dl => {
            let dir = default_download_dir();
            let filename = sanitize_filename(self.filename);
            let save_path = unique_path(&dir, &filename);
            let _ = flatten_rpc(get_rpc().attachment_download(self.id, save_path).block_on());
        });
        let (unit_scale, unit_suffix) = unit_for_bytes(self.size);
        let size_text = format_filesize(self.size, unit_scale);
        let attachment_label =
            format!("\u{ea7b} [{} {}] {}", size_text, unit_suffix, self.filename);

        ui.colored_label(Color32::DARK_BLUE, attachment_label);

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
                        if self.mime.starts_with("image/") {
                            self.app.state.image_viewer = Some(path.clone());
                        } else {
                            let _ = open::that_detached(path.clone());
                        }
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

struct ImageAttachmentContent<'a> {
    app: &'a mut NullspaceApp,
    id: Hash,
    size: u64,
    width: u32,
    height: u32,
    thumbhash: &'a str,
    filename: &'a str,
}

impl Widget for ImageAttachmentContent<'_> {
    fn ui(self, ui: &mut eframe::egui::Ui) -> Response {
        let status = ui.use_memo(
            || flatten_rpc(get_rpc().attachment_status(self.id).block_on()),
            self.app.state.attach_updates,
        );
        let dl_progress = self
            .app
            .state
            .download_progress
            .get(&self.id)
            .map(|(downloaded, total)| (*downloaded, *total));
        let dl_error = self.app.state.download_error.get(&self.id);
        let auto_dl_started = ui.use_state(|| false, ());
        let auto_limit = self.app.state.prefs.max_auto_image_download_bytes;
        let should_auto_download = auto_limit.map(|max| self.size <= max).unwrap_or(false);

        defmac::defmac!(start_dl => {
            let dir = image_cache_dir();
            let filename = sanitize_filename(self.filename);
            let save_path = dir.join(&filename);
            let _ = flatten_rpc(get_rpc().attachment_download(self.id, save_path).block_on());
        });

        let downloaded_path = status
            .as_ref()
            .ok()
            .and_then(|status| status.saved_to.clone());

        if downloaded_path.is_none()
            && dl_progress.is_none()
            && dl_error.is_none()
            && should_auto_download
            && !*auto_dl_started
        {
            auto_dl_started.set_next(true);
            start_dl!();
        }

        let aspect = if self.width > 0 && self.height > 0 {
            self.width as f32 / self.height as f32
        } else {
            return ui.label("CANNOT COMPUTE ASPECT RATIO");
        };
        let max_width = IMAGE_MAX_WIDTH.min(ui.available_width());

        if let Some(path) = downloaded_path {
            let response = ui.add(
                SmoothImage::new(path.as_path())
                    .thumbhash(Some(self.thumbhash))
                    .fit_to_size(egui::vec2(max_width, IMAGE_MAX_HEIGHT))
                    .corner_radius(egui::CornerRadius::same(8))
                    .preserve_aspect_ratio(true)
                    .aspect_ratio(aspect)
                    .sense(Sense::click()),
            );
            if response.clicked() {
                self.app.state.image_viewer = Some(path);
            }
            return response;
        }

        let (width, height) = fit_size_preserving_aspect(aspect, max_width, IMAGE_MAX_HEIGHT);
        let (rect, response) = ui.allocate_exact_size(egui::vec2(width, height), Sense::hover());
        paint_thumbhash(ui, rect, self.id, self.thumbhash);

        ui.scope_builder(egui::UiBuilder::new().max_rect(rect), |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(ui.available_height() / 2.0 - 40.0);
                ui.painter().rect_filled(
                    rect,
                    egui::CornerRadius::same(8),
                    Color32::from_white_alpha(200),
                );
                if let Some((downloaded, total)) = dl_progress {
                    ui.label(format!("{:.2}%", downloaded as f32 / total as f32 * 100.0));
                    ui.spinner();
                } else if let Some(error) = dl_error {
                    ui.label(
                        RichText::new(format!("Download failed: {error}"))
                            .color(Color32::RED)
                            .size(11.0),
                    );
                } else if !should_auto_download {
                    let (unit_scale, unit_suffix) = unit_for_bytes(self.size);
                    let size_text = format_filesize(self.size, unit_scale);
                    ui.label(format!("{size_text} {unit_suffix}"));
                    if ui.button("Download").clicked() {
                        start_dl!();
                    }
                } else {
                    ui.label(RichText::new("Auto-downloading image...").color(Color32::GRAY));
                }
            });
        });

        response
    }
}

fn paint_thumbhash(ui: &mut egui::Ui, rect: egui::Rect, id: Hash, thumbhash: &str) {
    let Ok((thumb_w, thumb_h, rgba)) = thumb_hash_from_b91(thumbhash) else {
        ui.painter()
            .rect_filled(rect, egui::CornerRadius::same(8), Color32::from_gray(180));
        return;
    };
    let image = egui::ColorImage::from_rgba_unmultiplied([thumb_w, thumb_h], &rgba);
    let texture = ui.ctx().load_texture(
        format!("thumbhash-{id}"),
        image,
        egui::TextureOptions::LINEAR,
    );
    egui::Image::from_texture(&texture)
        .corner_radius(egui::CornerRadius::same(8))
        .fit_to_exact_size(rect.size())
        .paint_at(ui, rect);
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

fn image_cache_dir() -> PathBuf {
    folders::image_cache_dir()
}

fn sanitize_filename(name: &str) -> String {
    let mut out = String::with_capacity(name.len().max(12));
    for ch in name.chars() {
        if ch == '/' || ch == '\\' || ch.is_control() {
            continue;
        }
        out.push(ch);
    }
    let trimmed = out.trim();
    if trimmed.is_empty() {
        "attachment.bin".to_string()
    } else {
        trimmed.to_string()
    }
}

fn unique_path(dir: &std::path::Path, filename: &str) -> PathBuf {
    let base = dir.join(filename);
    if !base.exists() {
        return base;
    }
    let (stem, ext) = split_extension(filename);
    for i in 1..=9999 {
        let candidate = if ext.is_empty() {
            dir.join(format!("{stem} ({i})"))
        } else {
            dir.join(format!("{stem} ({i}).{ext}"))
        };
        if !candidate.exists() {
            return candidate;
        }
    }
    base
}

fn split_extension(filename: &str) -> (&str, &str) {
    let Some(pos) = filename.rfind('.') else {
        return (filename, "");
    };
    let (stem, ext) = filename.split_at(pos);
    let ext = ext.trim_start_matches('.');
    if stem.is_empty() || ext.is_empty() {
        (filename, "")
    } else {
        (stem, ext)
    }
}

fn fit_size_preserving_aspect(aspect: f32, max_width: f32, max_height: f32) -> (f32, f32) {
    let safe_aspect = if aspect.is_finite() && aspect > 0.0 {
        aspect
    } else {
        1.0
    };
    let mut width = max_width;
    let mut height = width / safe_aspect;
    if height > max_height {
        height = max_height;
        width = height * safe_aspect;
    }
    (width.max(1.0), height.max(1.0))
}
