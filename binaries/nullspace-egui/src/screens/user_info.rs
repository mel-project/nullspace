use chrono::{DateTime, Local};
use eframe::egui::{Grid, Response, TextWrapMode, Ui, Widget, WidgetText, Window};
use egui::RichText;
use egui_hooks::UseHookExt;
use nullspace_client::UserDetails;
use nullspace_structs::timestamp::NanoTimestamp;
use nullspace_structs::username::UserName;

use crate::NullspaceApp;
use crate::utils::color::identity_color;
use crate::widgets::avatar::Avatar;

pub struct UserInfo<'a> {
    pub app: &'a mut NullspaceApp,
    pub target: Option<UserName>,
}

impl Widget for UserInfo<'_> {
    fn ui(self, ui: &mut eframe::egui::Ui) -> Response {
        let mut open = ui.use_state(|| false, ()).into_var();
        let mut selected = ui.use_state(|| None, ()).into_var();
        if let Some(username) = self.target {
            *selected = Some(username);
            *open = true;
        }

        if !*open {
            return ui.response();
        }
        let Some(username) = selected.clone() else {
            return ui.response();
        };

        let mut window_open = *open;
        Window::new("User info")
            .collapsible(false)
            .vscroll(true)
            .open(&mut window_open)
            .show(ui.ctx(), |ui| {
                let details = self
                    .app
                    .state
                    .profile_loader
                    .view(&username)
                    .unwrap_or_else(|| UserDetails {
                        username: username.clone(),
                        display_name: None,
                        avatar: None,
                        server_name: None,
                        common_groups: vec![],
                        last_dm_message: None,
                    });

                ui.vertical(|ui| {
                    ui.horizontal(|ui| {
                        let size = 48.0;
                        ui.add(Avatar::for_user(
                            &details.username,
                            details.avatar.clone(),
                            size,
                        ));
                        ui.add_space(12.0);
                        ui.vertical(|ui| {
                            ui.spacing_mut().item_spacing.y = 4.0;
                            let display = details
                                .display_name
                                .as_deref()
                                .unwrap_or_else(|| details.username.as_str());
                            ui.heading(display);
                            ui.label(
                                RichText::new(details.username.as_str())
                                    .color(identity_color(&details.username)),
                            );
                        });
                    });
                    ui.add_space(12.0);

                    Grid::new(ui.id().with("user_info_grid"))
                        .num_columns(2)
                        .min_col_width(120.0)
                        .spacing([16.0, 12.0])
                        .show(ui, |ui| {
                            let server_label = details
                                .server_name
                                .as_ref()
                                .map(|s| s.to_string())
                                .unwrap_or_else(|| "unknown".to_string());
                            render_info_row(ui, "Server", |ui| {
                                extend_label(ui, server_label);
                            });

                            render_info_row(ui, "Common groups", |ui| {
                                if details.common_groups.is_empty() {
                                    extend_label(ui, "None");
                                } else {
                                    ui.vertical(|ui| {
                                        ui.spacing_mut().item_spacing.y = 4.0;
                                        for group in &details.common_groups {
                                            extend_label(ui, format!("Group {}", group.short_id()));
                                        }
                                    });
                                }
                            });

                            render_info_row(ui, "Last message", |ui| {
                                if let Some(last) = details.last_dm_message.as_ref() {
                                    let time = format_timestamp(last.received_at);
                                    extend_label(ui, time);
                                } else {
                                    extend_label(ui, "None");
                                }
                            });
                        });
                });
            });

        if !window_open {
            *open = false;
            *selected = None;
        }

        ui.response()
    }
}

fn render_info_row(ui: &mut Ui, label: &str, content: impl FnOnce(&mut Ui)) {
    extend_label(ui, label);
    content(ui);
    ui.end_row();
}

fn extend_label(ui: &mut Ui, text: impl Into<WidgetText>) {
    ui.scope(|ui| {
        ui.style_mut().wrap_mode = Some(TextWrapMode::Extend);
        ui.label(text);
    });
}

fn format_timestamp(ts: Option<NanoTimestamp>) -> String {
    let Some(ts) = ts else {
        return "--:--".to_string();
    };
    let secs = (ts.0 / 1_000_000_000) as i64;
    let nsec = (ts.0 % 1_000_000_000) as u32;
    let Some(dt) = DateTime::from_timestamp(secs, nsec) else {
        return "--:--".to_string();
    };
    dt.with_timezone(&Local)
        .format("%Y-%m-%d %H:%M")
        .to_string()
}
