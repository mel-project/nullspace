use std::path::{Path, PathBuf};

use eframe::egui::{Button, Response, TextEdit, TextWrapMode, Widget, Window};
use egui::{Color32, RichText};
use egui_hooks::UseHookExt;
use egui_hooks::hook::state::Var;
use egui_taffy::{Tui, TuiBuilderLogic, tui};
use nullspace_structs::fragment::Attachment;
use poll_promise::Promise;
use pollster::FutureExt;
use taffy::style_helpers::{auto, fr, length};
use taffy::{AlignItems, Dimension, Display, FlexDirection, Size as TaffySize, Style};

use crate::NullspaceApp;
use crate::promises::{PromiseSlot, flatten_rpc};
use crate::rpc::get_rpc;
use crate::widgets::avatar::Avatar;

#[derive(Clone)]
enum AvatarChoice {
    Keep,
    Clear,
    Set(Attachment),
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
        let username_promise = ui.use_state(
            PromiseSlot::<Result<nullspace_structs::username::UserName, String>>::new,
            (),
        );
        let mut username_error_reported: Var<bool> = ui.use_state(|| false, ()).into_var();
        let mut display_name_input: Var<String> = ui.use_state(String::new, ()).into_var();
        let mut initialized: Var<bool> = ui.use_state(|| false, ()).into_var();
        let mut avatar_choice: Var<AvatarChoice> =
            ui.use_state(|| AvatarChoice::Keep, ()).into_var();
        let mut avatar_upload_id: Var<Option<i64>> = ui.use_state(|| None, ()).into_var();
        let save_promise = ui.use_state(PromiseSlot::<Result<(), String>>::new, ());

        if username_promise.is_idle() {
            let promise =
                Promise::spawn_async(async move { flatten_rpc(get_rpc().own_username().await) });
            username_promise.start(promise);
        }

        let username = match username_promise.poll() {
            Some(Ok(username)) => username,
            Some(Err(err)) => {
                if !*username_error_reported {
                    self.app.state.error_dialog = Some(err);
                    *username_error_reported = true;
                }
                ui.label("Unable to load profile.");
                return ui.response();
            }
            None => {
                ui.label("Loading...");
                return ui.response();
            }
        };

        let profile_view = self.app.state.profile_loader.view(&username);

        if !profile_view.loaded {
            ui.label("Loading...");
            return ui.response();
        }

        if !*initialized {
            *display_name_input = profile_view.display_name.clone().unwrap_or_default();
            *avatar_choice = AvatarChoice::Keep;
            *initialized = true;
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
                    ui.label(RichText::new(username.as_str()).color(Color32::GRAY));
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
                            match &*avatar_choice {
                                AvatarChoice::Set(attachment) => {
                                    ui.add(Avatar {
                                        sender: &username,
                                        attachment,
                                        size,
                                    });
                                }
                                AvatarChoice::Clear => {
                                    paint_placeholder(ui, size);
                                }
                                AvatarChoice::Keep => {
                                    if let Some(attachment) = profile_view.avatar.as_ref() {
                                        ui.add(Avatar {
                                            sender: &username,
                                            attachment,
                                            size,
                                        });
                                    } else {
                                        paint_placeholder(ui, size);
                                    }
                                }
                            }
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
                                    *avatar_choice = AvatarChoice::Clear;
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
                            *avatar_choice = AvatarChoice::Set(root);
                            *avatar_upload_id = None;
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
                                *avatar_upload_id = None;
                                self.app.state.upload_done.remove(&upload_id);
                                self.app.state.upload_progress.remove(&upload_id);
                                self.app.state.upload_error.remove(&upload_id);
                            }
                        } else {
                            ui.spinner();
                        }
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

                    let existing_display_name = profile_view.display_name.clone();
                    let existing_avatar = profile_view.avatar.clone();

                    let avatar_to_send = match &*avatar_choice {
                        AvatarChoice::Keep => existing_avatar,
                        AvatarChoice::Clear => None,
                        AvatarChoice::Set(attachment) => Some(attachment.clone()),
                    };

                    let display_changed = new_display_name != existing_display_name;
                    let avatar_changed = !matches!(&*avatar_choice, AvatarChoice::Keep);

                    let upload_busy = avatar_upload_id.is_some();
                    let save_busy = save_promise.is_running();
                    let can_save =
                        (display_changed || avatar_changed) && !upload_busy && !save_busy;

                    if ui.add_enabled(can_save, Button::new("Save")).clicked() {
                        let display_name = new_display_name.clone();
                        let avatar = avatar_to_send.clone();
                        let promise = Promise::spawn_async(async move {
                            flatten_rpc(get_rpc().own_profile_set(display_name, avatar).await)
                        });
                        save_promise.start(promise);
                    }

                    if let Some(result) = save_promise.take() {
                        match result {
                            Ok(()) => {
                                self.app.state.error_dialog = Some("Profile updated".to_string());
                                self.app.state.profile_loader.invalidate(&username);
                                *avatar_choice = AvatarChoice::Keep;
                            }
                            Err(err) => {
                                self.app.state.error_dialog = Some(err);
                            }
                        }
                    }
                });
            });

        self.app.profile_file_dialog.update(ui.ctx());
        if let Some(path) = self.app.profile_file_dialog.take_picked() {
            start_avatar_upload(self.app, &mut avatar_upload_id, path);
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

fn paint_placeholder(ui: &mut egui::Ui, size: f32) {
    let (rect, _) =
        ui.allocate_exact_size(eframe::egui::vec2(size, size), eframe::egui::Sense::hover());
    ui.painter().rect_filled(rect, 0.0, Color32::LIGHT_GRAY);
}

fn start_avatar_upload(app: &mut NullspaceApp, upload_id: &mut Var<Option<i64>>, path: PathBuf) {
    let mime = infer_mime(&path);
    if !mime.starts_with("image/") {
        app.state.error_dialog = Some("avatar must be an image".to_string());
        return;
    }
    let Ok(id) = flatten_rpc(get_rpc().attachment_upload(path, mime).block_on()) else {
        return;
    };
    upload_id.replace(id);
}

fn infer_mime(path: &Path) -> smol_str::SmolStr {
    infer::get_from_path(path)
        .ok()
        .flatten()
        .map(|kind| smol_str::SmolStr::new(kind.mime_type()))
        .unwrap_or_else(|| smol_str::SmolStr::new("application/octet-stream"))
}
