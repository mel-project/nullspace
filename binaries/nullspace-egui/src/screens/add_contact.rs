use bytes::Bytes;
use eframe::egui::{Button, Modal, Response, Spinner, TextEdit, Widget};
use egui_hooks::UseHookExt;
use egui_hooks::hook::state::Var;
use poll_promise::Promise;
use nullspace_client::internal::ConvoId;
use nullspace_structs::username::UserName;

use crate::NullspaceApp;
use crate::promises::{PromiseSlot, flatten_rpc};
use crate::rpc::get_rpc;

pub struct AddContact<'a> {
    pub app: &'a mut NullspaceApp,
    pub open: &'a mut bool,
}

impl Widget for AddContact<'_> {
    fn ui(self, ui: &mut eframe::egui::Ui) -> Response {
        let mut username_str: Var<String> = ui.use_state(String::new, ()).into_var();
        let mut message_str: Var<String> = ui.use_state(String::new, ()).into_var();
        let add_contact = ui.use_state(PromiseSlot::<Result<(), String>>::new, ());

        if *self.open {
            Modal::new("add_contact_modal".into()).show(ui.ctx(), |ui| {
                ui.heading("Add contact");
                let busy = add_contact.is_running();
                ui.horizontal(|ui| {
                    ui.label("UserName");
                    ui.add_enabled(
                        !busy,
                        TextEdit::singleline(&mut *username_str).desired_width(240.0),
                    );
                });
                ui.horizontal(|ui| {
                    ui.label("Message");
                    ui.add_enabled(
                        !busy,
                        TextEdit::multiline(&mut *message_str).desired_width(240.0),
                    );
                });
                ui.horizontal(|ui| {
                    if ui.add_enabled(!busy, Button::new("Cancel")).clicked() {
                        *self.open = false;
                    }
                    if ui.add_enabled(!busy, Button::new("Add")).clicked() {
                        let username = match UserName::parse(username_str.trim()) {
                            Ok(username) => username,
                            Err(err) => {
                                self.app.state.error_dialog =
                                    Some(format!("invalid username: {err}"));
                                return;
                            }
                        };
                        let init_msg = message_str.clone();
                        let convo_id = ConvoId::Direct { peer: username };
                        let body = Bytes::from(init_msg);
                        let promise = Promise::spawn_async(async move {
                            flatten_rpc(
                                get_rpc()
                                    .convo_send(convo_id, "text/plain".into(), body)
                                    .await,
                            )
                            .map(|_| ())
                        });
                        add_contact.start(promise);
                    }
                });
                if add_contact.is_running() {
                    ui.add(Spinner::new());
                }
                if let Some(result) = add_contact.take() {
                    match result {
                        Ok(()) => {
                            *self.open = false;
                            username_str.clear();
                            message_str.clear();
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
