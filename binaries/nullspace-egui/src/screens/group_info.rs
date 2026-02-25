use eframe::egui::{Grid, Response, TextEdit, Widget, Window};
use egui::{Color32, RichText};
use egui_hooks::UseHookExt;
use egui_hooks::hook::state::Var;
use nullspace_client::internal::GroupMemberStatus;
use nullspace_structs::group::GroupId;
use nullspace_structs::username::UserName;

use pollster::{FutureExt, block_on};

use crate::NullspaceApp;
use crate::rpc::flatten_rpc;
use crate::rpc::get_rpc;

pub struct GroupInfo<'a> {
    pub app: &'a mut NullspaceApp,
    pub open: &'a mut bool,
    pub group: GroupId,
    pub user_info: &'a mut Option<UserName>,
}

impl Widget for GroupInfo<'_> {
    fn ui(self, ui: &mut eframe::egui::Ui) -> Response {
        if !*self.open {
            return ui.response();
        }

        let mut invite_username: Var<String> = ui.use_state(String::new, ()).into_var();

        let mut window_open = *self.open;
        Window::new("Group info")
            .collapsible(false)
            .open(&mut window_open)
            .show(ui.ctx(), |ui| {
                ui.label(
                    RichText::new(format!("Group {}", self.group.short_id())).color(Color32::GRAY),
                );
                ui.add_space(4.0);

                ui.heading("Members");
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
                            let mut label =
                                self.app.state.profile_loader.label_for(&member.username);
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

                Grid::new("group_invite_grid")
                    .num_columns(3)
                    .spacing([8.0, 8.0])
                    .show(ui, |ui| {
                        ui.label("Invite");
                        ui.add(TextEdit::singleline(&mut *invite_username).desired_width(200.0));
                        if ui.button("Send").clicked() {
                            let username = match UserName::parse(invite_username.trim()) {
                                Ok(username) => username,
                                Err(err) => {
                                    self.app.state.error_dialog =
                                        Some(format!("invalid username: {err}"));
                                    return;
                                }
                            };
                            let group = self.group;
                            let _ =
                                flatten_rpc(get_rpc().group_invite(group, username).block_on());
                        }
                        ui.end_row();
                    });
            });
        *self.open = window_open;

        ui.response()
    }
}
