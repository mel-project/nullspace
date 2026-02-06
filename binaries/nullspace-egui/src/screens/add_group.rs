use eframe::egui::{Button, Modal, Response, Spinner, Widget};
use egui_hooks::UseHookExt;
use poll_promise::Promise;

use crate::NullspaceApp;
use crate::promises::{PromiseSlot, flatten_rpc};
use crate::rpc::get_rpc;

pub struct AddGroup<'a> {
    pub app: &'a mut NullspaceApp,
    pub open: &'a mut bool,
}

impl Widget for AddGroup<'_> {
    fn ui(self, ui: &mut eframe::egui::Ui) -> Response {
        let create_group =
            ui.use_state(PromiseSlot::<Result<nullspace_client::internal::ConvoId, String>>::new, ());
        let server = ui.use_memo(
            || {
                let result = pollster::block_on(get_rpc().own_server());
                flatten_rpc(result)
            },
            self.app.state.msg_updates,
        );

        if *self.open {
            Modal::new("add_group_modal".into()).show(ui.ctx(), |ui| {
                ui.heading("New group");
                let busy = create_group.is_running();
                match &server {
                    Ok(name) => {
                        ui.horizontal(|ui| {
                            ui.label("Server");
                            ui.label(name.as_str());
                        });
                    }
                    Err(err) => {
                        ui.label(format!("Server lookup failed: {err}"));
                    }
                }
                ui.horizontal(|ui| {
                    if ui.add_enabled(!busy, Button::new("Cancel")).clicked() {
                        *self.open = false;
                    }
                    let can_create = !busy && server.is_ok();
                    if ui.add_enabled(can_create, Button::new("Create")).clicked() {
                        let server = server.clone().unwrap_or_else(|_| {
                            unreachable!("server must be available when create is enabled")
                        });
                        let promise = Promise::spawn_async(async move {
                            flatten_rpc(get_rpc().convo_create_group(server).await)
                        });
                        create_group.start(promise);
                    }
                });
                if create_group.is_running() {
                    ui.add(Spinner::new());
                }
                if let Some(result) = create_group.take() {
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
