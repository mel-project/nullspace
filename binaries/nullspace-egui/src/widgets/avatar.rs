use std::path::PathBuf;

use eframe::egui::{Response, Widget};
use egui_hooks::UseHookExt;
use nullspace_crypt::hash::BcsHashExt;
use nullspace_structs::fragment::ImageAttachment;
use nullspace_structs::group::GroupId;
use nullspace_structs::username::UserName;

use crate::rpc::flatten_rpc;
use crate::rpc::get_rpc;
use crate::utils::color::identity_color;
use crate::utils::folders;
use crate::widgets::lib::SmoothImage;

const GROUP_AVATAR_ICON: &str = "\u{f0849}";

pub struct Avatar {
    pub color_key: String,
    pub attachment: Option<ImageAttachment>,
    pub placeholder: AvatarPlaceholder,
    pub sense: eframe::egui::Sense,
    pub size: f32,
}

pub enum AvatarPlaceholder {
    UserMonogram(String),
    GroupIcon,
}

impl Avatar {
    pub fn for_user(username: &UserName, attachment: Option<ImageAttachment>, size: f32) -> Self {
        Self {
            color_key: username.to_string(),
            attachment,
            placeholder: AvatarPlaceholder::UserMonogram(username.to_string()),
            sense: eframe::egui::Sense::empty(),
            size,
        }
    }

    pub fn for_group(group_id: GroupId, attachment: Option<ImageAttachment>, size: f32) -> Self {
        Self {
            color_key: group_id.to_string(),
            attachment,
            placeholder: AvatarPlaceholder::GroupIcon,
            sense: eframe::egui::Sense::empty(),
            size,
        }
    }

    pub fn sense(mut self, sense: eframe::egui::Sense) -> Self {
        self.sense = sense;
        self
    }
}

impl Widget for Avatar {
    fn ui(self, ui: &mut eframe::egui::Ui) -> Response {
        let id = ui.next_auto_id().with(&self.attachment);
        ui.push_id(id, |ui| {
            let radius_u8 = (self.size / 2.0).round().clamp(0.0, u8::MAX as f32) as u8;
            let circle_corner_radius = eframe::egui::CornerRadius::same(radius_u8);
            let sense = self.sense;
            let Some(attachment) = self.attachment.as_ref() else {
                let (rect, response) =
                    ui.allocate_exact_size(eframe::egui::vec2(self.size, self.size), sense);
                paint_avatar_placeholder(ui, rect, &self.color_key, &self.placeholder);
                return response;
            };
            let path = avatar_cache_path(attachment);

            let download_started = ui.use_state(|| false, ());
            if !path.exists() && !*download_started {
                download_started.set_next(true);
                if let Some(parent) = path.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                let attachment = attachment.clone();
                let save_to = path.clone();
                smol::spawn(async move {
                    let _ = flatten_rpc(
                        get_rpc()
                            .attachment_download_oneshot(attachment.inner, save_to)
                            .await,
                    );
                })
                .detach();
            }

            let size = eframe::egui::vec2(self.size, self.size);
            ui.add(
                SmoothImage::new(path.as_path())
                    .thumbhash(Some(attachment.thumbhash.as_str()))
                    .max_size(size)
                    .corner_radius(circle_corner_radius)
                    .preserve_aspect_ratio(false)
                    .sense(sense),
            )
        })
        .response
    }
}

fn paint_avatar_placeholder(
    ui: &eframe::egui::Ui,
    rect: eframe::egui::Rect,
    color_key: &str,
    placeholder: &AvatarPlaceholder,
) {
    let radius = rect.width().min(rect.height()) / 2.0;
    let bg = identity_color(color_key);
    ui.painter().circle_filled(rect.center(), radius, bg);

    let (label, font_size) = match placeholder {
        AvatarPlaceholder::UserMonogram(identity) => (
            user_avatar_monogram(identity),
            (rect.height() * 0.55).clamp(8.0, 48.0),
        ),
        AvatarPlaceholder::GroupIcon => (
            group_avatar_icon().to_owned(),
            (rect.height() * 0.72).clamp(10.0, 56.0),
        ),
    };
    ui.painter().text(
        rect.center(),
        eframe::egui::Align2::CENTER_CENTER,
        label,
        eframe::egui::FontId::proportional(font_size),
        eframe::egui::Color32::WHITE,
    );
}

fn user_avatar_monogram(identity: &str) -> String {
    identity
        .trim_start_matches('@')
        .chars()
        .next()
        .map(|ch| ch.to_ascii_uppercase())
        .unwrap_or('?')
        .to_string()
}

fn group_avatar_icon() -> &'static str {
    GROUP_AVATAR_ICON
}

fn avatar_cache_path(attachment: &ImageAttachment) -> PathBuf {
    let base = folders::avatar_cache_dir();
    let filename = attachment.inner.bcs_hash().to_string();
    base.join(filename)
}

#[cfg(test)]
mod tests {
    use super::{group_avatar_icon, user_avatar_monogram};

    #[test]
    fn user_avatar_monogram_uses_first_visible_character() {
        assert_eq!(user_avatar_monogram("@alice"), "A");
        assert_eq!(user_avatar_monogram("bob"), "B");
    }

    #[test]
    fn group_avatar_icon_matches_nerd_font_codepoint() {
        assert_eq!(group_avatar_icon(), "\u{f0849}");
    }
}
