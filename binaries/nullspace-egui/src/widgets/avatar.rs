use std::path::PathBuf;

use eframe::egui::{Response, Widget};
use egui_hooks::UseHookExt;
use nullspace_crypt::hash::BcsHashExt;
use nullspace_structs::fragment::ImageAttachment;
use nullspace_structs::username::UserName;

use crate::rpc::flatten_rpc;
use crate::rpc::get_rpc;
use crate::utils::color::username_color;
use crate::utils::folders;
use crate::widgets::smooth::SmoothImage;

pub struct Avatar {
    pub sender: UserName,
    pub attachment: Option<ImageAttachment>,
    pub size: f32,
}

impl Widget for Avatar {
    fn ui(self, ui: &mut eframe::egui::Ui) -> Response {
        let id = ui.next_auto_id().with(&self.attachment);
        ui.push_id(id, |ui| {
            let radius_u8 = (self.size / 2.0).round().clamp(0.0, u8::MAX as f32) as u8;
            let circle_corner_radius = eframe::egui::CornerRadius::same(radius_u8);
            let sense = eframe::egui::Sense::empty();
            let Some(attachment) = self.attachment.as_ref() else {
                let (rect, response) =
                    ui.allocate_exact_size(eframe::egui::vec2(self.size, self.size), sense);
                paint_avatar_placeholder(ui, rect, &self.sender);
                return response;
            };
            let Some(path) = avatar_cache_path(attachment) else {
                let (rect, response) =
                    ui.allocate_exact_size(eframe::egui::vec2(self.size, self.size), sense);
                paint_avatar_placeholder(ui, rect, &self.sender);
                return response;
            };

            let download_started = ui.use_state(|| false, ());
            if !path.exists() && !*download_started {
                download_started.set_next(true);
                if let Some(parent) = path.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                let sender = self.sender.clone();
                let attachment = attachment.clone();
                let save_to = path.clone();
                smol::spawn(async move {
                    let _ = flatten_rpc(
                        get_rpc()
                            .attachment_download_oneshot(sender, attachment.inner, save_to)
                            .await,
                    );
                })
                .detach();
            }

            if path.exists() {
                let size = eframe::egui::vec2(self.size, self.size);
                ui.add(
                    SmoothImage::new(path.as_path())
                        .thumbhash(Some(attachment.thumbhash.as_str()))
                        .fit_to_size(size)
                        .corner_radius(circle_corner_radius)
                        .preserve_aspect_ratio(false)
                        .sense(sense),
                )
            } else {
                let (rect, response) =
                    ui.allocate_exact_size(eframe::egui::vec2(self.size, self.size), sense);
                paint_avatar_placeholder(ui, rect, &self.sender);
                response
            }
        })
        .response
    }
}

fn paint_avatar_placeholder(ui: &eframe::egui::Ui, rect: eframe::egui::Rect, username: &UserName) {
    let radius = rect.width().min(rect.height()) / 2.0;
    let bg = username_color(username);
    ui.painter().circle_filled(rect.center(), radius, bg);

    let label = username.as_str().trim_start_matches('@');
    let letter = label
        .chars()
        .next()
        .map(|ch| ch.to_ascii_uppercase())
        .unwrap_or('?')
        .to_string();
    let font_size = (rect.height() * 0.55).clamp(8.0, 48.0);
    ui.painter().text(
        rect.center(),
        eframe::egui::Align2::CENTER_CENTER,
        letter,
        eframe::egui::FontId::proportional(font_size),
        eframe::egui::Color32::WHITE,
    );
}

fn avatar_cache_path(attachment: &ImageAttachment) -> Option<PathBuf> {
    let base = folders::avatar_cache_dir();
    let filename = attachment.inner.bcs_hash().to_string();
    Some(base.join(filename))
}
