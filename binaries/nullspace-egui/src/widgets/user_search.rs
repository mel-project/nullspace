use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use eframe::egui::{
    Checkbox, CursorIcon, Rect, Response, RichText, Sense, TextEdit, TextWrapMode, Widget, vec2,
};
use egui_hooks::UseHookExt;
use egui_hooks::hook::state::Var;
use egui_taffy::{TuiBuilderLogic, tui};
use nullspace_client::{ConvoId, ConvoSummary, UserDetails};
use nullspace_structs::username::UserName;
use taffy::{AlignItems, Dimension, FlexDirection, Size as TaffySize, Style};

use crate::NullspaceApp;
use crate::rpc::{flatten_rpc, get_rpc};
use crate::utils::hooks::CustomHooksExt;
use crate::widgets::avatar::Avatar;

pub fn known_dm_peers(convos: &[ConvoSummary]) -> Vec<UserName> {
    let mut peers = BTreeSet::new();
    for convo in convos {
        if let ConvoId::Direct { peer } = &convo.convo_id {
            peers.insert(peer.clone());
        }
    }
    peers.into_iter().collect()
}

pub enum UserSearchSelection<'a> {
    Single(&'a mut Option<UserName>),
    Multi(&'a mut BTreeSet<UserName>),
}

impl UserSearchSelection<'_> {
    fn is_selected(&self, username: &UserName) -> bool {
        match self {
            UserSearchSelection::Single(selected) => selected.as_ref() == Some(username),
            UserSearchSelection::Multi(selected) => selected.contains(username),
        }
    }

    fn activate(&mut self, username: &UserName) {
        match self {
            UserSearchSelection::Single(selected) => {
                **selected = Some(username.clone());
            }
            UserSearchSelection::Multi(selected) => {
                if !selected.insert(username.clone()) {
                    selected.remove(username);
                }
            }
        }
    }
}

pub struct UserSearch<'a> {
    pub app: &'a mut NullspaceApp,
    pub id_source: &'a str,
    pub known_users: &'a [UserName],
    pub selection: UserSearchSelection<'a>,
    pub user_info_target: &'a mut Option<UserName>,
    pub disabled_reasons: &'a BTreeMap<UserName, String>,
    pub placeholder: &'a str,
    pub empty_text: &'a str,
}

impl Widget for UserSearch<'_> {
    fn ui(mut self, ui: &mut eframe::egui::Ui) -> Response {
        ui.push_id(self.id_source, |ui| {
            let mut query: Var<String> = ui.use_state(String::new, ()).into_var();
            let trimmed = query.trim().to_string();
            let normalized = trimmed.to_lowercase();

            ui.add(
                TextEdit::singleline(&mut *query)
                    .desired_width(f32::INFINITY)
                    .hint_text(self.placeholder),
            );

            let exact_lookup = ui.use_async_memo(
                {
                    let trimmed = trimmed.clone();
                    async move {
                        smol::Timer::after(Duration::from_millis(120)).await;
                        let Ok(username) = UserName::parse(trimmed) else {
                            return None;
                        };
                        Some((
                            username.clone(),
                            flatten_rpc(get_rpc().user_details(username).await),
                        ))
                    }
                },
                trimmed.clone(),
            );

            let mut rows: Vec<SearchRow> = Vec::new();
            let mut seen = BTreeSet::new();

            let mut known_users = self.known_users.to_vec();
            known_users.sort();

            for username in known_users {
                let label = self.app.state.profile_loader.label_for(&username);
                let details = self.app.state.profile_loader.view(&username);
                let username_match = username.as_str().to_lowercase().contains(&normalized);
                let label_match = label.to_lowercase().contains(&normalized);
                if !normalized.is_empty() && !username_match && !label_match {
                    continue;
                }
                if !seen.insert(username.clone()) {
                    continue;
                }
                rows.push(SearchRow::from_known(username, details));
            }

            let mut exact_error = None;
            if let Some(result) = exact_lookup.as_ref()
                && let Some((username, details_result)) = result.as_ref()
            {
                match details_result {
                    Ok(details) => {
                        if seen.insert(username.clone()) {
                            rows.push(SearchRow::from_details(details.clone()));
                        }
                    }
                    Err(err) => {
                        exact_error = Some(err.clone());
                    }
                }
            }

            if rows.is_empty() {
                ui.add_space(6.0);
                if let Some(err) = exact_error.filter(|_| !trimmed.is_empty()) {
                    ui.label(
                        RichText::new(format!("No match for {trimmed}: {err}"))
                            .color(ui.visuals().weak_text_color()),
                    );
                } else {
                    ui.label(RichText::new(self.empty_text).color(ui.visuals().weak_text_color()));
                }
                return ui.response();
            }

            ui.add_space(6.0);
            for row in rows {
                let disabled_reason = self.disabled_reasons.get(&row.username);
                let enabled = disabled_reason.is_none();
                let selected = self.selection.is_selected(&row.username);
                let gap_x = ui.spacing().item_spacing.x;
                let row_start = ui.cursor().min;
                let row_width = ui.available_width();
                let mut avatar_clicked = false;
                let mut checkbox_clicked = false;
                let row_scope_response = ui
                    .scope(|ui| {
                        tui(ui, ui.id().with(("user_search_row", &row.username)))
                            .reserve_available_width()
                            .style(Style {
                                flex_direction: FlexDirection::Row,
                                align_items: Some(AlignItems::Center),
                                size: TaffySize {
                                    width: Dimension::Percent(1.0),
                                    height: Dimension::Auto,
                                },
                                gap: TaffySize::length(gap_x),
                                ..Default::default()
                            })
                            .show(|tui| {
                                tui.style(Style {
                                    flex_shrink: 0.0,
                                    ..Default::default()
                                })
                                .ui(|ui| {
                                    let avatar =
                                        Avatar::for_user(&row.username, row.avatar.clone(), 28.0)
                                            .sense(eframe::egui::Sense::click());
                                    if ui.add(avatar).clicked() {
                                        avatar_clicked = true;
                                        *self.user_info_target = Some(row.username.clone());
                                    }
                                });

                                tui.style(Style {
                                    flex_grow: 1.0,
                                    ..Default::default()
                                })
                                .ui(|ui| {
                                    ui.horizontal(|ui| {
                                        ui.label(row.primary_text(selected).color(if enabled {
                                            ui.visuals().text_color()
                                        } else {
                                            ui.visuals().weak_text_color()
                                        }));
                                        if row.primary_label != row.username.as_str() {
                                            ui.label(
                                                RichText::new(row.username.as_str())
                                                    .color(ui.visuals().weak_text_color()),
                                            );
                                        }
                                    });
                                });

                            tui.style(Style {
                                flex_shrink: 0.0,
                                ..Default::default()
                            })
                            .ui(|ui| {
                                if let Some(reason) = disabled_reason {
                                    ui.style_mut().wrap_mode = Some(TextWrapMode::Extend);
                                    ui.label(
                                        RichText::new(reason)
                                            .size(11.0)
                                            .color(ui.visuals().warn_fg_color),
                                    );
                                } else {
                                    let mut checked = selected;
                                    let checkbox_response = ui.add(Checkbox::without_text(&mut checked));
                                    checkbox_clicked = checkbox_response.clicked();
                                }
                            });
                    });
                    })
                    .response;
                let row_height = row_scope_response.rect.bottom() - row_start.y;
                let row_rect = Rect::from_min_size(row_start, vec2(row_width, row_height.max(0.0)));
                let row_response = if enabled {
                    ui.interact(
                        row_rect,
                        ui.id().with(("user_search_row_click", &row.username)),
                        Sense::click(),
                    )
                    .on_hover_cursor(CursorIcon::PointingHand)
                } else {
                    ui.interact(
                        row_rect,
                        ui.id().with(("user_search_row_click", &row.username)),
                        Sense::hover(),
                    )
                };
                if enabled && !avatar_clicked && (row_response.clicked() || checkbox_clicked) {
                    self.selection.activate(&row.username);
                }
                ui.add_space(2.0);
            }

            ui.response()
        })
        .inner
    }
}

#[derive(Clone)]
struct SearchRow {
    username: UserName,
    avatar: Option<nullspace_structs::fragment::ImageAttachment>,
    primary_label: String,
}

impl SearchRow {
    fn from_known(username: UserName, details: Option<UserDetails>) -> Self {
        match details {
            Some(details) => Self::from_details(details),
            None => Self {
                primary_label: username.as_str().to_string(),
                avatar: None,
                username,
            },
        }
    }

    fn from_details(details: UserDetails) -> Self {
        let primary_label = details
            .display_name
            .clone()
            .unwrap_or_else(|| details.username.as_str().to_string());

        Self {
            username: details.username,
            avatar: details.avatar,
            primary_label,
        }
    }
}

impl SearchRow {
    fn primary_text(&self, selected: bool) -> RichText {
        let mut text = RichText::new(self.primary_label.clone());
        if selected {
            text = text.strong();
        }
        text
    }
}
