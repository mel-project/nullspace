use eframe::egui::{Button, Modal, Response, Spinner, Widget};
use nullspace_client::GroupCreateRequest;
use nullspace_structs::group::GroupId;

use crate::NullspaceApp;
use crate::rpc::{flatten_rpc, get_rpc};
use crate::utils::hooks::CustomHooksExt;

pub struct AddGroup<'a> {
    pub app: &'a mut NullspaceApp,
    pub open: &'a mut bool,
}

impl Widget for AddGroup<'_> {
    fn ui(self, ui: &mut eframe::egui::Ui) -> Response {
        let create = ui.use_async_slot::<Result<GroupId, String>>(());

        if *self.open {
            Modal::new("add_group_modal".into()).show(ui.ctx(), |ui| {
                ui.heading("New group");
                let busy = create.is_busy();
                ui.horizontal(|ui| {
                    if ui.add_enabled(!busy, Button::new("Cancel")).clicked() {
                        *self.open = false;
                    }
                    if ui.add_enabled(!busy, Button::new("Create")).clicked() {
                        create.start(async move {
                            flatten_rpc(
                                get_rpc()
                                    .group_create(GroupCreateRequest {
                                        title: None,
                                        description: None,
                                        new_members_muted: false,
                                        allow_new_members_to_see_history: false,
                                    })
                                    .await,
                            )
                        });
                    }
                });
                if create.is_busy() {
                    ui.add(Spinner::new());
                }
                if let Some(result) = create.take() {
                    match result {
                        Ok(_group_id) => {
                            *self.open = false;
                        }
                        Err(err) => {
                            self.app.state.error_dialog = Some(err);
                        }
                    }
                }
            });
        }
        ui.response()
    }
}
