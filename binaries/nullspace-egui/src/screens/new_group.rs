use std::collections::BTreeSet;

use eframe::egui::{Button, Checkbox, Response, RichText, TextEdit, Widget, Window};
use egui_hooks::UseHookExt;
use egui_hooks::hook::state::Var;
use nullspace_client::{ConvoId, ConvoSummary, GroupAction, GroupCreateRequest};
use nullspace_structs::group::GroupId;
use nullspace_structs::username::UserName;

use crate::NullspaceApp;
use crate::rpc::{flatten_rpc, get_rpc};
use crate::screens::user_info::UserInfo;
use crate::utils::hooks::CustomHooksExt;
use crate::widgets::user_search::{UserSearch, UserSearchSelection, known_dm_peers};

#[derive(Clone)]
struct CreateGroupOutcome {
    group_id: GroupId,
    invite_failures: Vec<(UserName, String)>,
}

pub struct NewGroup<'a> {
    pub app: &'a mut NullspaceApp,
    pub open: &'a mut bool,
    pub selected_chat: &'a mut Option<ConvoId>,
    pub convos: &'a [ConvoSummary],
}

impl Widget for NewGroup<'_> {
    fn ui(self, ui: &mut eframe::egui::Ui) -> Response {
        if !*self.open {
            return ui.response();
        }

        let create = ui.use_async_slot::<Result<CreateGroupOutcome, String>>(());
        let mut window_open = *self.open;
        let mut close_requested = false;
        Window::new("New group")
            .collapsible(false)
            .default_width(520.0)
            .vscroll(true)
            .open(&mut window_open)
            .show(ui.ctx(), |ui| {
                let busy = create.is_busy();
                let mut title: Var<String> = ui.use_state(String::new, ()).into_var();
                let mut description: Var<String> = ui.use_state(String::new, ()).into_var();
                let mut new_members_muted: Var<bool> = ui.use_state(|| false, ()).into_var();
                let mut allow_history: Var<bool> = ui.use_state(|| false, ()).into_var();
                let mut invitees: Var<BTreeSet<UserName>> =
                    ui.use_state(BTreeSet::<UserName>::new, ()).into_var();
                let mut inline_error: Var<Option<String>> =
                    ui.use_state(|| None::<String>, ()).into_var();
                let mut user_info_target: Var<Option<UserName>> =
                    ui.use_state(|| None::<UserName>, ()).into_var();
                let known_users = known_dm_peers(self.convos);

                ui.label(
                    RichText::new("Set up the group, then optionally invite people immediately.")
                        .color(ui.visuals().weak_text_color()),
                );
                ui.add_space(8.0);

                ui.label("Title");
                ui.add_enabled(
                    !busy,
                    TextEdit::singleline(&mut *title).desired_width(f32::INFINITY),
                );
                ui.add_space(6.0);

                ui.label("Description");
                ui.add_enabled(
                    !busy,
                    TextEdit::multiline(&mut *description)
                        .desired_width(f32::INFINITY)
                        .desired_rows(3),
                );
                ui.add_space(8.0);

                ui.add_enabled(
                    !busy,
                    Checkbox::new(&mut *new_members_muted, "Mute new members by default"),
                );
                ui.add_enabled(
                    !busy,
                    Checkbox::new(
                        &mut *allow_history,
                        "Allow new members to see history from before they joined",
                    ),
                );

                ui.separator();
                ui.heading("Invite people");
                ui.add(UserSearch {
                    app: self.app,
                    id_source: "new_group_search",
                    known_users: &known_users,
                    selection: UserSearchSelection::Multi(&mut *invitees),
                    user_info_target: &mut *user_info_target,
                    disabled_reasons: &Default::default(),
                    placeholder: "Search people or enter exact @username",
                    empty_text: "Select local people or enter an exact @username to invite someone new.",
                });

                if !invitees.is_empty() {
                    ui.add_space(6.0);
                    ui.label(
                        RichText::new(format!("Selected: {}", invitees.len()))
                            .color(ui.visuals().weak_text_color()),
                    );
                    ui.horizontal_wrapped(|ui| {
                        let selected: Vec<UserName> = invitees.iter().cloned().collect();
                        for username in selected {
                            if ui.small_button(username.as_str()).clicked() {
                                invitees.remove(&username);
                            }
                        }
                    });
                }

                if let Some(error) = inline_error.as_ref() {
                    ui.add_space(8.0);
                    ui.label(RichText::new(error).color(ui.visuals().error_fg_color));
                }

                ui.add_space(12.0);
                ui.horizontal(|ui| {
                    if ui.add_enabled(!busy, Button::new("Cancel")).clicked() {
                        close_requested = true;
                    }
                    if ui.add_enabled(!busy, Button::new("Create group")).clicked() {
                        let request = GroupCreateRequest {
                            title: non_empty(title.trim().to_string()),
                            description: non_empty(description.trim().to_string()),
                            new_members_muted: *new_members_muted,
                            allow_new_members_to_see_history: *allow_history,
                        };
                        let selected_invitees: Vec<UserName> = invitees.iter().cloned().collect();
                        create.start(async move {
                            let group_id = flatten_rpc(get_rpc().group_create(request).await)?;
                            let mut invite_failures = Vec::new();
                            for username in selected_invitees {
                                if let Err(err) = flatten_rpc(
                                    get_rpc()
                                        .group_action(group_id, GroupAction::ShareInvite {
                                            username: username.clone(),
                                        })
                                        .await,
                                ) {
                                    invite_failures.push((username, err));
                                }
                            }
                            Ok(CreateGroupOutcome {
                                group_id,
                                invite_failures,
                            })
                        });
                    }
                });

                if let Some(result) = create.take() {
                    match result {
                        Ok(outcome) => {
                            *self.selected_chat = Some(ConvoId::Group {
                                group_id: outcome.group_id,
                            });
                            *title = String::new();
                            *description = String::new();
                            *new_members_muted = false;
                            *allow_history = false;
                            invitees.clear();
                            if outcome.invite_failures.is_empty() {
                                *inline_error = None;
                                close_requested = true;
                            } else {
                                let summary = outcome
                                    .invite_failures
                                    .into_iter()
                                    .map(|(username, err)| format!("{username}: {err}"))
                                    .collect::<Vec<_>>()
                                    .join("\n");
                                *inline_error =
                                    Some(format!("Group created, but some invites failed:\n{summary}"));
                            }
                        }
                        Err(err) => {
                            *inline_error = Some(err);
                        }
                    }
                }

                ui.add(UserInfo {
                    app: self.app,
                    target: user_info_target.take(),
                });
            });
        if close_requested {
            window_open = false;
        }
        *self.open = window_open;
        ui.response()
    }
}

fn non_empty(value: String) -> Option<String> {
    if value.is_empty() { None } else { Some(value) }
}
