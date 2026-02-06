use eframe::egui::{Button, Modal, Response, TextEdit, Widget};
use egui::{Color32, RichText};
use egui_hooks::UseHookExt;
use egui_hooks::hook::state::Var;
use nullspace_client::internal::GroupMemberStatus;
use nullspace_structs::group::GroupId;
use nullspace_structs::username::UserName;
use poll_promise::Promise;
use pollster::block_on;

use crate::NullspaceApp;
use crate::promises::{PromiseSlot, flatten_rpc};
use crate::rpc::get_rpc;

pub struct GroupRoster<'a> {
    pub app: &'a mut NullspaceApp,
    pub open: &'a mut bool,
    pub group: GroupId,
    pub user_info: &'a mut Option<UserName>,
}

impl Widget for GroupRoster<'_> {
    fn ui(self, ui: &mut eframe::egui::Ui) -> Response {
        let mut invite_username: Var<String> = ui.use_state(String::new, ()).into_var();
        let invite_promise = ui.use_state(PromiseSlot::<Result<(), String>>::new, ());

        if *self.open {
            Modal::new("group_roster_modal".into()).show(ui.ctx(), |ui| {
                ui.heading("Group members");
                let members = ui.use_memo(
                    || {
                        let result = block_on(get_rpc().group_members(self.group));
                        flatten_rpc(result)
                    },
                    (self.group, self.app.state.msg_updates),
                );

                match members {
                    Ok(members) => {
                        for member in members {
                            let mut label = self
                                .app
                                .state
                                .profile_loader
                                .label_for(&member.username);
                            if member.is_admin {
                                label.push_str(" [admin]");
                            }
                            let status = match member.status {
                                GroupMemberStatus::Pending => "pending",
                                GroupMemberStatus::Accepted => "accepted",
                                GroupMemberStatus::Banned => "banned",
                            };
                            ui.horizontal(|ui| {
                                let response =
                                    ui.add(egui::Label::new(label).sense(egui::Sense::click()));
                                ui.label(RichText::new(status).color(Color32::GRAY));
                                if response.clicked() {
                                    *self.user_info = Some(member.username.clone());
                                }
                            });
                        }
                    }
                    Err(err) => {
                        self.app.state.error_dialog = Some(err.to_string());
                    }
                }

                ui.separator();
                let busy = invite_promise.is_running();
                ui.horizontal(|ui| {
                    ui.label("Invite");
                    ui.add_enabled(
                        !busy,
                        TextEdit::singleline(&mut *invite_username).desired_width(200.0),
                    );
                    if ui.add_enabled(!busy, Button::new("Send")).clicked() {
                        let username = match UserName::parse(invite_username.trim()) {
                            Ok(username) => username,
                            Err(err) => {
                                self.app.state.error_dialog =
                                    Some(format!("invalid username: {err}"));
                                return;
                            }
                        };
                        let group = self.group;
                        let promise = Promise::spawn_async(async move {
                            flatten_rpc(get_rpc().group_invite(group, username).await)
                        });
                        invite_promise.start(promise);
                    }
                });
                if let Some(result) = invite_promise.take() {
                    match result {
                        Ok(()) => {
                            invite_username.clear();
                        }
                        Err(err) => {
                            self.app.state.error_dialog = Some(err);
                        }
                    }
                }
                ui.add_space(8.0);
                if ui.add(Button::new("Close")).clicked() {
                    *self.open = false;
                }
            });
        }
        ui.response()
    }
}
