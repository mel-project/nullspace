use std::path::{Path, PathBuf};

use eframe::egui::{Button, Response, TextEdit, TextWrapMode, Widget, Window};
use egui::{Color32, RichText};
use egui_hooks::UseHookExt;
use egui_hooks::hook::state::{State, Var};
use egui_taffy::{Tui, TuiBuilderLogic, tui};
use nullspace_client::internal::{UploadedRoot, UserDetails};
use nullspace_structs::fragment::ImageAttachment;
use pollster::FutureExt;
use taffy::style_helpers::{auto, fr, length};
use taffy::{AlignItems, Dimension, Display, FlexDirection, Size as TaffySize, Style};

use crate::NullspaceApp;
use crate::rpc::flatten_rpc;
use crate::rpc::get_rpc;
use crate::utils::generational::GBox;
use crate::utils::hooks::CustomHooksExt;
use crate::utils::color::username_color;
use crate::widgets::avatar::Avatar;

#[derive(Clone)]
enum AvatarChoice {
    Keep,
    Clear,
    Set(ImageAttachment),
}

pub struct Profile<'a> {
    pub app: &'a mut NullspaceApp,
    pub open: &'a mut bool,
}

impl Widget for Profile<'_> {
    fn ui(self, ui: &mut eframe::egui::Ui) -> Response {
        if *self.open {
            let mut window_open = *self.open;
            let center = ui.ctx().content_rect().center();
            Window::new("Edit profile")
                .collapsible(false)
                .default_pos(center)
                .open(&mut window_open)
                .show(ui.ctx(), |ui| {
                    ui.add(ProfileInner { app: self.app });
                });
            *self.open = window_open;
        }
        ui.response()
    }
}

pub struct ProfileInner<'a> {
    pub app: &'a mut NullspaceApp,
}

impl Widget for ProfileInner<'_> {
    fn ui(self, ui: &mut eframe::egui::Ui) -> Response {
        let Some(username) = self.app.state.own_username.clone() else {
            return ui.response();
        };

        // Fetch profile once; on error fall back to empty.
        let fetch_username = username.clone();
        let profile_result = ui.use_async(
            async move { flatten_rpc(get_rpc().user_details(fetch_username).await) },
            (),
        );
        let profile = profile_result
            .as_deref()
            .and_then(|r| r.as_ref().ok().cloned())
            .unwrap_or_else(|| UserDetails {
                username: username.clone(),
                display_name: None,
                avatar: None,
                server_name: None,
                common_groups: vec![],
                last_dm_message: None,
            });

        let initial_display_name = profile.display_name.clone().unwrap_or_default();
        let mut display_name_input: Var<String> = ui
            .use_state(
                move || initial_display_name.clone(),
                profile.display_name.clone(),
            )
            .into_var();
        let avatar_choice: State<AvatarChoice> = ui.use_state(|| AvatarChoice::Keep, ());
        let avatar_upload_id: State<Option<i64>> = ui.use_state(|| None, ());
        let save_error: GBox<Option<String>> = ui.use_gbox(|| None, ());
        let save_busy: GBox<bool> = ui.use_gbox(|| false, ());
        let save_succeeded: GBox<bool> = ui.use_gbox(|| false, ());

        if save_succeeded.get() {
            save_succeeded.set(false);
            self.app.state.profile_loader.invalidate(&username);
        }

        tui(ui, ui.id().with("profile_editor"))
            .style(Style {
                flex_direction: FlexDirection::Column,
                gap: TaffySize::length(12.),
                ..Default::default()
            })
            .show(|tui| {
                // Username
                tui.ui(|ui| {
                    ui.label(RichText::new(username.as_str()).color(username_color(&username)));
                });

                // Display name row
                profile_row(tui, "Display name", |tui| {
                    tui.style(Style {
                        min_size: TaffySize {
                            width: Dimension::Length(200.),
                            height: Dimension::Auto,
                        },
                        ..Default::default()
                    })
                    .ui(|ui| {
                        ui.add(
                            TextEdit::singleline(&mut *display_name_input)
                                .desired_width(ui.available_width()),
                        );
                    });
                });

                // Avatar row
                profile_row(tui, "Avatar", |tui| {
                    tui.style(Style {
                        flex_direction: FlexDirection::Row,
                        align_items: Some(AlignItems::Center),
                        gap: TaffySize::length(8.),
                        ..Default::default()
                    })
                    .add(|tui| {
                        // Avatar preview
                        tui.style(Style {
                            flex_shrink: 0.,
                            ..Default::default()
                        })
                        .ui(|ui| {
                            let size = 64.0;
                            let attachment = match &*avatar_choice {
                                AvatarChoice::Keep => profile.avatar.clone(),
                                AvatarChoice::Clear => None,
                                AvatarChoice::Set(attachment) => Some(attachment.clone()),
                            };
                            ui.add(Avatar {
                                sender: username.clone(),
                                attachment,
                                size,
                            });
                        });

                        // Buttons
                        tui.style(Style {
                            flex_direction: FlexDirection::Column,
                            gap: TaffySize::length(4.),
                            ..Default::default()
                        })
                        .wrap_mode(TextWrapMode::Extend)
                        .add(|tui| {
                            tui.ui(|ui| {
                                if ui.button("Change…").clicked() {
                                    self.app.profile_file_dialog.pick_file();
                                }
                            });
                            tui.ui(|ui| {
                                if ui.button("Remove").clicked() {
                                    avatar_choice.set_next(AvatarChoice::Clear);
                                }
                            });
                        });
                    });
                });

                // Upload progress/error
                if let Some(upload_id) = *avatar_upload_id {
                    tui.ui(|ui| {
                        if let Some((uploaded, total)) =
                            self.app.state.upload_progress.get(&upload_id)
                        {
                            let progress = if *total == 0 {
                                0.0
                            } else {
                                (*uploaded as f32 / *total as f32).clamp(0.0, 1.0)
                            };
                            ui.add(eframe::egui::ProgressBar::new(progress).text("Uploading..."));
                        } else if let Some(done) = self.app.state.upload_done.get(&upload_id) {
                            let root = done.clone();
                            match root {
                                UploadedRoot::ImageAttachment(root) => {
                                    avatar_choice.set_next(AvatarChoice::Set(root));
                                }
                                UploadedRoot::Attachment(_) => {
                                    self.app.state.error_dialog = Some(
                                        "avatar upload produced non-image payload".to_string(),
                                    );
                                }
                            }
                            avatar_upload_id.set_next(None);
                            self.app.state.upload_done.remove(&upload_id);
                            self.app.state.upload_progress.remove(&upload_id);
                            self.app.state.upload_error.remove(&upload_id);
                        } else if let Some(error) = self.app.state.upload_error.get(&upload_id) {
                            ui.label(
                                RichText::new(format!("Upload failed: {error}"))
                                    .color(Color32::RED)
                                    .size(11.0),
                            );
                            if ui.button("Clear error").clicked() {
                                avatar_upload_id.set_next(None);
                                self.app.state.upload_done.remove(&upload_id);
                                self.app.state.upload_progress.remove(&upload_id);
                                self.app.state.upload_error.remove(&upload_id);
                            }
                        } else {
                            ui.spinner();
                        }
                    });
                }

                // Save error
                if let Some(err) = save_error.get() {
                    tui.ui(|ui| {
                        ui.colored_label(Color32::RED, format!("Save failed: {err}"));
                    });
                }

                // Save button
                tui.ui(|ui| {
                    let display_name_trimmed = display_name_input.trim();
                    let new_display_name = if display_name_trimmed.is_empty() {
                        None
                    } else {
                        Some(display_name_trimmed.to_string())
                    };

                    let existing_display_name = profile.display_name.clone();
                    let existing_avatar = profile.avatar.clone();

                    let avatar_to_send = match &*avatar_choice {
                        AvatarChoice::Keep => existing_avatar,
                        AvatarChoice::Clear => None,
                        AvatarChoice::Set(attachment) => Some(attachment.clone()),
                    };

                    let display_changed = new_display_name != existing_display_name;
                    let avatar_changed = !matches!(&*avatar_choice, AvatarChoice::Keep);

                    let upload_busy = avatar_upload_id.is_some();
                    let can_save =
                        (display_changed || avatar_changed) && !upload_busy && !save_busy.get();

                    if ui.add_enabled(can_save, Button::new("Save")).clicked() {
                        save_busy.set(true);
                        save_error.set(None);
                        let display_name = new_display_name.clone();
                        let avatar = avatar_to_send.clone();
                        smol::spawn(async move {
                            match flatten_rpc(
                                get_rpc().own_profile_set(display_name, avatar).await,
                            ) {
                                Ok(()) => {
                                    save_error.set(None);
                                    save_succeeded.set(true);
                                }
                                Err(err) => {
                                    save_error.set(Some(err));
                                }
                            }
                            save_busy.set(false);
                        })
                        .detach();
                    }
                });
            });

        self.app.profile_file_dialog.update(ui.ctx());
        if let Some(path) = self.app.profile_file_dialog.take_picked() {
            start_avatar_upload(self.app, &avatar_upload_id, path);
        }

        ui.response()
    }
}

fn profile_row(tui: &mut Tui, label: &str, content: impl FnOnce(&mut Tui)) {
    tui.style(Style {
        display: Display::Grid,
        grid_template_columns: vec![length(120.0), fr(1.0)],
        grid_auto_rows: vec![auto()],
        align_items: Some(AlignItems::Center),
        gap: TaffySize::length(16.),
        ..Default::default()
    })
    .add(|tui| {
        tui.wrap_mode(TextWrapMode::Extend).label(label);
        tui.add(|tui| content(tui));
    });
}

fn start_avatar_upload(app: &mut NullspaceApp, upload_id: &State<Option<i64>>, path: PathBuf) {
    let mime = infer_mime(&path);
    if !mime.starts_with("image/") {
        app.state.error_dialog = Some("avatar must be an image".to_string());
        return;
    }
    let Ok(id) = flatten_rpc(get_rpc().image_attachment_upload(path).block_on()) else {
        return;
    };
    upload_id.set_next(Some(id));
}

fn infer_mime(path: &Path) -> smol_str::SmolStr {
    infer::get_from_path(path)
        .ok()
        .flatten()
        .map(|kind| smol_str::SmolStr::new(kind.mime_type()))
        .unwrap_or_else(|| smol_str::SmolStr::new("application/octet-stream"))
}
