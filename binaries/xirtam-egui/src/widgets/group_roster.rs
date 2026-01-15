use eframe::egui::{Button, Modal, Response, TextEdit, Widget};
use egui::{Color32, RichText};
use egui_hooks::UseHookExt;
use egui_hooks::hook::state::Var;
use poll_promise::Promise;
use pollster::block_on;
use xirtam_client::internal::GroupMemberStatus;
use xirtam_structs::group::GroupId;
use xirtam_structs::handle::Handle;

use crate::XirtamApp;
use crate::promises::{PromiseSlot, flatten_rpc};

pub struct GroupRoster<'a> {
    pub app: &'a mut XirtamApp,
    pub open: &'a mut bool,
    pub group: GroupId,
}

impl Widget for GroupRoster<'_> {
    fn ui(self, ui: &mut eframe::egui::Ui) -> Response {
        let mut invite_handle: Var<String> = ui.use_state(String::new, ()).into_var();
        let invite_promise = ui.use_state(PromiseSlot::new, ());

        if *self.open {
            Modal::new("group_roster_modal".into()).show(ui.ctx(), |ui| {
                ui.heading("Group members");
                let members = ui.use_memo(
                    || {
                        let rpc = self.app.client.rpc();
                        let result = block_on(rpc.group_members(self.group));
                        flatten_rpc(result)
                    },
                    (self.group, self.app.state.update_count),
                );

                match members {
                    Ok(members) => {
                        for member in members {
                            let mut label = member.handle.to_string();
                            if member.is_admin {
                                label.push_str(" [admin]");
                            }
                            let status = match member.status {
                                GroupMemberStatus::Pending => "pending",
                                GroupMemberStatus::Accepted => "accepted",
                                GroupMemberStatus::Banned => "banned",
                            };
                            ui.horizontal(|ui| {
                                ui.label(label);
                                ui.label(RichText::new(status).color(Color32::GRAY));
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
                        TextEdit::singleline(&mut *invite_handle).desired_width(200.0),
                    );
                    if ui.add_enabled(!busy, Button::new("Send")).clicked() {
                        let handle = match Handle::parse(invite_handle.trim()) {
                            Ok(handle) => handle,
                            Err(err) => {
                                self.app.state.error_dialog =
                                    Some(format!("invalid handle: {err}"));
                                return;
                            }
                        };
                        let rpc = self.app.client.rpc();
                        let group = self.group;
                        let promise = Promise::spawn_async(async move {
                            flatten_rpc(rpc.group_invite(group, handle).await)
                        });
                        invite_promise.start(promise);
                    }
                });
                if let Some(result) = invite_promise.poll() {
                    match result {
                        Ok(()) => {
                            invite_handle.clear();
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
