use chrono::{DateTime, Local};
use eframe::egui::{Response, TextWrapMode, Widget, Window};
use egui::{Color32, RichText};
use egui_hooks::UseHookExt;
use egui_taffy::{Tui, TuiBuilderLogic, tui};
use nullspace_client::internal::UserDetails;
use nullspace_structs::timestamp::NanoTimestamp;
use nullspace_structs::username::UserName;
use poll_promise::Promise;
use taffy::style_helpers::{auto, fr, length};
use taffy::{AlignItems, Display, FlexDirection, LengthPercentage, Size as TaffySize, Style};

use crate::promises::{PromiseSlot, flatten_rpc};
use crate::rpc::get_rpc;
use crate::widgets::avatar::Avatar;

pub struct UserInfo(pub Option<UserName>);

impl Widget for UserInfo {
    fn ui(self, ui: &mut eframe::egui::Ui) -> Response {
        let mut open = ui.use_state(|| false, ()).into_var();
        let mut selected = ui.use_state(|| None, ()).into_var();
        if let Some(username) = self.0 {
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
            .open(&mut window_open)
            .show(ui.ctx(), |ui| {
                let details_promise = ui.use_state(
                    PromiseSlot::<Result<UserDetails, String>>::new,
                    username.clone(),
                );

                if details_promise.is_idle() {
                    let username = username.clone();
                    let promise = Promise::spawn_async(async move {
                        flatten_rpc(get_rpc().user_details(username).await)
                    });
                    details_promise.start(promise);
                }

                let details = match details_promise.poll() {
                    Some(Ok(details)) => details,
                    Some(Err(err)) => {
                        ui.label(RichText::new(err).color(Color32::RED));
                        return;
                    }
                    None => {
                        ui.spinner();
                        return;
                    }
                };

                // Main container with taffy
                tui(ui, ui.id().with("user_info"))
                    .style(Style {
                        flex_direction: FlexDirection::Column,
                        gap: TaffySize::length(12.),
                        ..Default::default()
                    })
                    .show(|tui| {
                        // Header: Avatar + Name
                        tui.style(Style {
                            flex_direction: FlexDirection::Row,
                            align_items: Some(AlignItems::Center),
                            gap: TaffySize::length(12.),
                            ..Default::default()
                        })
                        .add(|tui| {
                            // Avatar (fixed size, no shrink)
                            tui.style(Style {
                                flex_shrink: 0.,
                                ..Default::default()
                            })
                            .ui(|ui| {
                                let size = 48.0;
                                ui.add(Avatar {
                                    sender: details.username.clone(),
                                    attachment: details.avatar.clone(),
                                    size,
                                });
                            });

                            // Name section (grows to fill space)
                            tui.style(Style {
                                flex_direction: FlexDirection::Column,
                                gap: TaffySize {
                                    width: LengthPercentage::Length(4.),
                                    height: LengthPercentage::Length(4.),
                                },
                                flex_grow: 1.,
                                ..Default::default()
                            })
                            .ui(|ui| {
                                let display = details
                                    .display_name
                                    .as_deref()
                                    .unwrap_or_else(|| details.username.as_str());
                                ui.heading(display);
                                ui.label(
                                    RichText::new(details.username.as_str()).color(Color32::GRAY),
                                );
                            });
                        });

                        // Info rows
                        tui.style(Style {
                            flex_direction: FlexDirection::Column,
                            gap: TaffySize::length(12.),
                            ..Default::default()
                        })
                        .add(|tui| {
                            // Server row
                            let server_label = details
                                .server_name
                                .as_ref()
                                .map(|s| s.to_string())
                                .unwrap_or_else(|| "unknown".to_string());
                            render_info_row(tui, "Server", |tui| {
                                tui.wrap_mode(TextWrapMode::Extend).label(&server_label);
                            });

                            // Common groups row
                            render_info_row(tui, "Common groups", |tui| {
                                if details.common_groups.is_empty() {
                                    tui.wrap_mode(TextWrapMode::Extend).label("None");
                                } else {
                                    tui.style(Style {
                                        flex_direction: FlexDirection::Column,
                                        gap: TaffySize::length(4.),
                                        ..Default::default()
                                    })
                                    .wrap_mode(TextWrapMode::Extend)
                                    .add(|tui| {
                                        for group in &details.common_groups {
                                            tui.label(format!("Group {}", short_group_id(group)));
                                        }
                                    });
                                }
                            });

                            // Last message row
                            render_info_row(tui, "Last message", |tui| {
                                if let Some(last) = details.last_dm_message.as_ref() {
                                    let time = format_timestamp(last.received_at);
                                    tui.wrap_mode(TextWrapMode::Extend).label(time);
                                } else {
                                    tui.wrap_mode(TextWrapMode::Extend).label("None");
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

fn render_info_row(tui: &mut Tui, label: &str, content: impl FnOnce(&mut Tui)) {
    tui.style(Style {
        display: Display::Grid,
        grid_template_columns: vec![length(120.0), fr(1.0)],
        grid_auto_rows: vec![auto()],
        gap: TaffySize::length(16.),
        ..Default::default()
    })
    .add(|tui| {
        // Label (fixed width via grid column)
        tui.wrap_mode(TextWrapMode::Extend).label(label);

        // Content (flexible via grid column)
        tui.add(|tui| content(tui));
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

fn short_group_id(group: &nullspace_structs::group::GroupId) -> String {
    let bytes = group.as_bytes();
    let mut out = String::with_capacity(8);
    for byte in bytes.iter().take(4) {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}
