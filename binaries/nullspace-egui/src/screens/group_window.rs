use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;

use eframe::egui::{Button, Checkbox, Response, RichText, TextEdit, Ui, Widget, Window};
use egui_hooks::UseHookExt;
use egui_hooks::hook::state::Var;
use nullspace_client::{ConvoSummary, GroupAction, GroupRosterEntry, GroupView};
use nullspace_structs::group::GroupId;
use nullspace_structs::username::UserName;
use pollster::block_on;

use crate::NullspaceApp;
use crate::rpc::{flatten_rpc, get_rpc};
use crate::utils::hooks::{CustomHooksExt, Slot};
use crate::widgets::avatar::Avatar;
use crate::widgets::tabbed_pane::TabbedPane;
use crate::widgets::user_search::{UserSearch, UserSearchSelection, known_dm_peers};

#[derive(Clone)]
enum GroupActionFeedback {
    None,
    Message(String),
    CloseWindow,
}

type ActionSlot = Slot<Result<GroupActionFeedback, String>>;

pub struct GroupWindow<'a> {
    pub app: &'a mut NullspaceApp,
    pub open: &'a mut bool,
    pub group: GroupId,
    pub user_info: &'a mut Option<UserName>,
}

impl Widget for GroupWindow<'_> {
    fn ui(self, ui: &mut Ui) -> Response {
        if !*self.open {
            return ui.response();
        }

        let mut window_open = *self.open;
        let mut close_requested = false;
        Window::new("Group")
            .collapsible(false)
            .default_width(640.0)
            .default_height(520.0)
            .open(&mut window_open)
            .show(ui.ctx(), |ui| {
                let group_view =
                    ui.use_memo(
                        || flatten_rpc(block_on(get_rpc().group_view(self.group))),
                        (self.group, self.app.state.msg_updates),
                    );
                let convos = ui.use_memo(
                    || flatten_rpc(block_on(get_rpc().convo_list())),
                    self.app.state.msg_updates,
                );
                let actions = ui.use_async_slot::<Result<GroupActionFeedback, String>>(self.group);
                let mut inline_error: Var<Option<String>> =
                    ui.use_state(|| None::<String>, ()).into_var();

                let group_view = match group_view {
                    Ok(view) => view,
                    Err(err) => {
                        ui.label(RichText::new(err).color(ui.visuals().error_fg_color));
                        return;
                    }
                };
                let convos = match convos {
                    Ok(convos) => convos,
                    Err(err) => {
                        ui.label(RichText::new(err).color(ui.visuals().error_fg_color));
                        return;
                    }
                };

                if let Some(err) = inline_error.as_ref() {
                    ui.label(RichText::new(err).color(ui.visuals().error_fg_color));
                    ui.add_space(8.0);
                }

                let mut body = GroupWindowBody {
                    app: self.app,
                    group_id: self.group,
                    group_view: &group_view,
                    convos: &convos,
                    actions: &actions,
                    inline_error: &mut *inline_error,
                    user_info_target: self.user_info,
                    busy: actions.is_busy(),
                };

                TabbedPane::new("group_tabs")
                    .rail_width(120.0)
                    .show(ui, |tabs| {
                        tabs.tab("Overview", |ui| body.render_overview(ui));
                        tabs.tab("Members", |ui| body.render_members(ui));
                        tabs.tab("Settings", |ui| body.render_settings(ui));
                    });

                if let Some(result) = actions.take() {
                    match result {
                        Ok(GroupActionFeedback::None) => *inline_error = None,
                        Ok(GroupActionFeedback::Message(message)) => {
                            *inline_error = Some(message);
                        }
                        Ok(GroupActionFeedback::CloseWindow) => {
                            *inline_error = None;
                            close_requested = true;
                        }
                        Err(err) => *inline_error = Some(err),
                    }
                }
            });
        if close_requested {
            window_open = false;
        }
        *self.open = window_open;
        ui.response()
    }
}

struct GroupWindowBody<'a, 'b> {
    app: &'a mut NullspaceApp,
    group_id: GroupId,
    group_view: &'b GroupView,
    convos: &'b [ConvoSummary],
    actions: &'b ActionSlot,
    inline_error: &'b mut Option<String>,
    user_info_target: &'b mut Option<UserName>,
    busy: bool,
}

impl GroupWindowBody<'_, '_> {
    fn start_action(
        &mut self,
        future: impl Future<Output = Result<GroupActionFeedback, String>> + Send + 'static,
    ) {
        *self.inline_error = None;
        let actions = (*self.actions).clone();
        actions.start(future);
    }

    fn render_overview(&mut self, ui: &mut Ui) {
        let mut title_draft: Var<String> = ui.use_state(String::new, ()).into_var();
        let mut description_draft: Var<String> = ui.use_state(String::new, ()).into_var();
        let mut last_loaded_metadata: Var<Option<(Option<String>, Option<String>)>> = ui
            .use_state(|| None::<(Option<String>, Option<String>)>, ())
            .into_var();

        let loaded_pair = (
            self.group_view.title.clone(),
            self.group_view.description.clone(),
        );
        if *last_loaded_metadata != Some(loaded_pair.clone()) {
            let current_title = self.group_view.title.clone().unwrap_or_default();
            let current_description = self.group_view.description.clone().unwrap_or_default();
            let metadata_dirty =
                *title_draft != current_title || *description_draft != current_description;
            if !metadata_dirty || last_loaded_metadata.is_none() {
                *title_draft = current_title;
                *description_draft = current_description;
                *last_loaded_metadata = Some(loaded_pair);
            }
        }

        let active_count = self
            .group_view
            .roster
            .iter()
            .filter(|entry| !entry.is_banned)
            .count();
        let banned_count = self
            .group_view
            .roster
            .iter()
            .filter(|entry| entry.is_banned)
            .count();

        ui.heading(&self.group_view.display_title);
        ui.label(
            RichText::new(format!(
                "{}  •  {}",
                self.group_id, self.group_view.server
            ))
            .color(ui.visuals().weak_text_color()),
        );
        ui.add_space(10.0);

        ui.label(format!("Active members: {active_count}"));
        ui.label(format!("Banned users: {banned_count}"));
        ui.label(self.capabilities_summary());

        ui.separator();
        ui.heading("Group details");

        ui.label("Title");
        ui.add_enabled(
            self.group_view.capabilities.can_edit_metadata && !self.busy,
            TextEdit::singleline(&mut *title_draft).desired_width(f32::INFINITY),
        );
        ui.add_space(6.0);
        ui.label("Description");
        ui.add_enabled(
            self.group_view.capabilities.can_edit_metadata && !self.busy,
            TextEdit::multiline(&mut *description_draft)
                .desired_width(f32::INFINITY)
                .desired_rows(3),
        );

        let loaded_title = self.group_view.title.clone().unwrap_or_default();
        let loaded_description = self.group_view.description.clone().unwrap_or_default();
        let metadata_dirty =
            *title_draft != loaded_title || *description_draft != loaded_description;

        ui.add_space(8.0);
        ui.horizontal(|ui| {
            if ui
                .add_enabled(
                    self.group_view.capabilities.can_edit_metadata
                        && metadata_dirty
                        && !self.busy,
                    Button::new("Save"),
                )
                .clicked()
            {
                let title = non_empty(title_draft.trim().to_string());
                let description = non_empty(description_draft.trim().to_string());
                let group_id = self.group_id;
                self.start_action(async move {
                    flatten_rpc(
                        get_rpc()
                            .group_action(
                                group_id,
                                GroupAction::SetMetadata { title, description },
                            )
                            .await,
                    )?;
                    Ok(GroupActionFeedback::None)
                });
            }
            if ui
                .add_enabled(
                    self.group_view.capabilities.can_edit_metadata
                        && metadata_dirty
                        && !self.busy,
                    Button::new("Reset"),
                )
                .clicked()
            {
                *title_draft = loaded_title;
                *description_draft = loaded_description;
                *self.inline_error = None;
            }
        });
    }

    fn render_members(&mut self, ui: &mut Ui) {
        let mut invitees: Var<BTreeSet<UserName>> =
            ui.use_state(BTreeSet::<UserName>::new, ()).into_var();
        let mut known_users = known_dm_peers(self.convos);
        for entry in &self.group_view.roster {
            known_users.push(entry.username.clone());
        }
        known_users.sort();
        known_users.dedup();

        let mut disabled_reasons = BTreeMap::new();
        for entry in &self.group_view.roster {
            let reason = if entry.is_banned {
                "Banned; unban first"
            } else {
                "Already in group"
            };
            disabled_reasons.insert(entry.username.clone(), reason.to_string());
        }

        ui.heading("Invite people");
        ui.add(UserSearch {
            app: self.app,
            id_source: "group_invite_search",
            known_users: &known_users,
            selection: UserSearchSelection::Multi(&mut *invitees),
            user_info_target: self.user_info_target,
            disabled_reasons: &disabled_reasons,
            placeholder: "Search people or enter exact @username",
            empty_text: "Enter an exact @username to invite someone not already visible here.",
            max_height: 180.0,
        });

        ui.add_space(6.0);
        ui.horizontal(|ui| {
            if !invitees.is_empty() {
                ui.label(
                    RichText::new(format!("Selected: {}", invitees.len()))
                        .color(ui.visuals().weak_text_color()),
                );
            }
            if ui
                .add_enabled(
                    self.group_view.capabilities.can_share_invites
                        && !invitees.is_empty()
                        && !self.busy,
                    Button::new("Send invites"),
                )
                .clicked()
            {
                let selected_invitees: Vec<UserName> = invitees.iter().cloned().collect();
                let group_id = self.group_id;
                self.start_action(async move {
                    let mut failures = Vec::new();
                    for username in selected_invitees {
                        if let Err(err) = flatten_rpc(
                            get_rpc()
                                .group_action(
                                    group_id,
                                    GroupAction::ShareInvite {
                                        username: username.clone(),
                                    },
                                )
                                .await,
                        ) {
                            failures.push((username, err));
                        }
                    }
                    if failures.is_empty() {
                        Ok(GroupActionFeedback::None)
                    } else {
                        let summary = failures
                            .into_iter()
                            .map(|(username, err)| format!("{username}: {err}"))
                            .collect::<Vec<_>>()
                            .join("\n");
                        Ok(GroupActionFeedback::Message(format!(
                            "Some invites failed:\n{summary}"
                        )))
                    }
                });
                invitees.clear();
            }
        });

        ui.separator();
        ui.heading("Members");
        let mut active_members = self
            .group_view
            .roster
            .iter()
            .filter(|entry| !entry.is_banned)
            .cloned()
            .collect::<Vec<_>>();
        active_members.sort_by(|a, b| a.username.cmp(&b.username));
        for entry in active_members {
            self.render_member_row(ui, &entry);
        }

        ui.separator();
        ui.heading("Banned");
        let mut banned_members = self
            .group_view
            .roster
            .iter()
            .filter(|entry| entry.is_banned)
            .cloned()
            .collect::<Vec<_>>();
        banned_members.sort_by(|a, b| a.username.cmp(&b.username));
        if banned_members.is_empty() {
            ui.label(RichText::new("No banned users").color(ui.visuals().weak_text_color()));
        } else {
            for entry in banned_members {
                self.render_member_row(ui, &entry);
            }
        }
    }

    fn render_member_row(&mut self, ui: &mut Ui, entry: &GroupRosterEntry) {
        let label = self.app.state.profile_loader.label_for(&entry.username);
        let details = self.app.state.profile_loader.view(&entry.username);
        let is_self = self.app.state.own_username.as_ref() == Some(&entry.username);

        ui.horizontal(|ui| {
            ui.add(Avatar {
                sender: entry.username.clone(),
                attachment: details.as_ref().and_then(|details| details.avatar.clone()),
                size: 28.0,
            });

            let mut headline = label;
            if is_self {
                headline.push_str(" (You)");
            }
            if entry.is_admin {
                headline.push_str(" [admin]");
            }
            if entry.is_muted {
                headline.push_str(" [muted]");
            }

            if ui.selectable_label(false, headline).clicked() {
                *self.user_info_target = Some(entry.username.clone());
            }
            ui.label(
                RichText::new(entry.username.as_str()).color(ui.visuals().weak_text_color()),
            );

            if is_self {
                return;
            }

            ui.menu_button("Actions", |ui| {
                if entry.is_banned {
                    if ui
                        .add_enabled(
                            self.group_view.capabilities.can_manage_members && !self.busy,
                            Button::new("Unban"),
                        )
                        .clicked()
                    {
                        let username = entry.username.clone();
                        let group_id = self.group_id;
                        self.start_action(async move {
                            flatten_rpc(
                                get_rpc()
                                    .group_action(
                                        group_id,
                                        GroupAction::SetBanned {
                                            username,
                                            banned: false,
                                        },
                                    )
                                    .await,
                            )?;
                            Ok(GroupActionFeedback::None)
                        });
                        ui.close();
                    }
                    return;
                }

                if ui
                    .add_enabled(
                        self.group_view.capabilities.can_manage_mutes && !self.busy,
                        Button::new(if entry.is_muted { "Unmute" } else { "Mute" }),
                    )
                    .clicked()
                {
                    let username = entry.username.clone();
                    let muted = !entry.is_muted;
                    let group_id = self.group_id;
                    self.start_action(async move {
                        flatten_rpc(
                            get_rpc()
                                .group_action(
                                    group_id,
                                    GroupAction::SetMemberMuted { username, muted },
                                )
                                .await,
                        )?;
                        Ok(GroupActionFeedback::None)
                    });
                    ui.close();
                }

                if ui
                    .add_enabled(
                        self.group_view.capabilities.can_manage_admins && !self.busy,
                        Button::new(if entry.is_admin {
                            "Remove admin"
                        } else {
                            "Make admin"
                        }),
                    )
                    .clicked()
                {
                    let username = entry.username.clone();
                    let is_admin = !entry.is_admin;
                    let group_id = self.group_id;
                    self.start_action(async move {
                        flatten_rpc(
                            get_rpc()
                                .group_action(
                                    group_id,
                                    GroupAction::SetAdmin { username, is_admin },
                                )
                                .await,
                        )?;
                        Ok(GroupActionFeedback::None)
                    });
                    ui.close();
                }

                if ui
                    .add_enabled(
                        self.group_view.capabilities.can_manage_members && !self.busy,
                        Button::new("Ban"),
                    )
                    .clicked()
                {
                    let username = entry.username.clone();
                    let group_id = self.group_id;
                    self.start_action(async move {
                        flatten_rpc(
                            get_rpc()
                                .group_action(
                                    group_id,
                                    GroupAction::SetBanned {
                                        username,
                                        banned: true,
                                    },
                                )
                                .await,
                        )?;
                        Ok(GroupActionFeedback::None)
                    });
                    ui.close();
                }
            });
        });
    }

    fn render_settings(&mut self, ui: &mut Ui) {
        let mut new_members_muted: Var<bool> = ui.use_state(|| false, ()).into_var();
        let mut allow_history: Var<bool> = ui.use_state(|| false, ()).into_var();
        let mut last_loaded_settings: Var<Option<(bool, bool)>> =
            ui.use_state(|| None::<(bool, bool)>, ()).into_var();
        let mut confirm_leave: Var<bool> = ui.use_state(|| false, ()).into_var();

        let loaded_pair = (
            self.group_view.settings.new_members_muted,
            self.group_view.settings.allow_new_members_to_see_history,
        );
        if *last_loaded_settings != Some(loaded_pair) {
            let settings_dirty =
                *new_members_muted != loaded_pair.0 || *allow_history != loaded_pair.1;
            if !settings_dirty || last_loaded_settings.is_none() {
                *new_members_muted = loaded_pair.0;
                *allow_history = loaded_pair.1;
                *last_loaded_settings = Some(loaded_pair);
            }
        }
        let settings_dirty =
            *new_members_muted != loaded_pair.0 || *allow_history != loaded_pair.1;

        ui.heading("Member defaults");
        ui.add_enabled(
            self.group_view.capabilities.can_manage_members && !self.busy,
            Checkbox::new(&mut *new_members_muted, "Mute new members by default"),
        );
        ui.add_enabled(
            self.group_view.capabilities.can_manage_members && !self.busy,
            Checkbox::new(
                &mut *allow_history,
                "Allow new members to see history from before they joined",
            ),
        );

        ui.add_space(8.0);
        ui.horizontal(|ui| {
            if ui
                .add_enabled(
                    self.group_view.capabilities.can_manage_members
                        && settings_dirty
                        && !self.busy,
                    Button::new("Save"),
                )
                .clicked()
            {
                let muted = *new_members_muted;
                let allow = *allow_history;
                let group_id = self.group_id;
                self.start_action(async move {
                    flatten_rpc(
                        get_rpc()
                            .group_action(
                                group_id,
                                GroupAction::SetNewMembersMuted { muted },
                            )
                            .await,
                    )?;
                    flatten_rpc(
                        get_rpc()
                            .group_action(
                                group_id,
                                GroupAction::SetAllowNewMembersToSeeHistory { allow },
                            )
                            .await,
                    )?;
                    Ok(GroupActionFeedback::None)
                });
            }
            if ui
                .add_enabled(
                    self.group_view.capabilities.can_manage_members
                        && settings_dirty
                        && !self.busy,
                    Button::new("Reset"),
                )
                .clicked()
            {
                *new_members_muted = loaded_pair.0;
                *allow_history = loaded_pair.1;
                *self.inline_error = None;
            }
        });

        ui.separator();
        ui.heading("Danger zone");
        ui.label(
            RichText::new("Leaving removes this group from your active local state.")
                .color(ui.visuals().warn_fg_color),
        );
        if !*confirm_leave {
            if ui
                .add_enabled(
                    self.group_view.capabilities.can_leave && !self.busy,
                    Button::new("Leave group"),
                )
                .clicked()
            {
                *confirm_leave = true;
            }
        } else {
            ui.horizontal(|ui| {
                if ui
                    .add_enabled(
                        self.group_view.capabilities.can_leave && !self.busy,
                        Button::new("Confirm leave"),
                    )
                    .clicked()
                {
                    let group_id = self.group_id;
                    self.start_action(async move {
                        flatten_rpc(
                            get_rpc()
                                .group_action(group_id, GroupAction::Leave)
                                .await,
                        )?;
                        Ok(GroupActionFeedback::CloseWindow)
                    });
                    *confirm_leave = false;
                }
                if ui.button("Cancel").clicked() {
                    *confirm_leave = false;
                }
            });
        }
    }

    fn capabilities_summary(&self) -> String {
        let mut caps = Vec::new();
        if self.group_view.capabilities.can_send_messages {
            caps.push("can send");
        }
        if self.group_view.capabilities.can_share_invites {
            caps.push("can invite");
        }
        if self.group_view.capabilities.can_manage_members {
            caps.push("can manage members");
        }
        if self.group_view.capabilities.can_manage_admins {
            caps.push("can manage admins");
        }
        if caps.is_empty() {
            "Read-only member".to_string()
        } else {
            format!("Capabilities: {}", caps.join(", "))
        }
    }
}

fn non_empty(value: String) -> Option<String> {
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}
