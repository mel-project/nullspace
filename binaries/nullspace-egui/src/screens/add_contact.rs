use eframe::egui::{Button, Grid, Response, Spinner, TextEdit, Widget, Window};
use egui_hooks::UseHookExt;
use egui_hooks::hook::state::Var;
use nullspace_client::internal::{ConvoId, OutgoingMessage};
use nullspace_structs::username::UserName;
use poll_promise::Promise;

use crate::NullspaceApp;
use crate::promises::{PromiseSlot, flatten_rpc};
use crate::rpc::get_rpc;

pub struct AddContact<'a> {
    pub app: &'a mut NullspaceApp,
    pub open: &'a mut bool,
}

impl Widget for AddContact<'_> {
    fn ui(self, ui: &mut eframe::egui::Ui) -> Response {
        if !*self.open {
            return ui.response();
        }
        ui.scope(|ui| {
            let mut username_str: Var<String> = ui.use_state(String::new, ()).into_var();
            let mut message_str: Var<String> = ui.use_state(String::new, ()).into_var();
            let add_contact = ui.use_state(PromiseSlot::<Result<(), String>>::new, ());

            let busy = add_contact.is_running();

            let mut window_open = *self.open;
            Window::new("Add contact")
                .collapsible(false)
                .open(&mut window_open)
                .show(ui.ctx(), |ui| {
                    Grid::new("add_contact_grid")
                        .num_columns(2)
                        .spacing([16.0, 12.0])
                        .show(ui, |ui| {
                            ui.label("Username");
                            ui.add_enabled(
                                !busy,
                                TextEdit::singleline(&mut *username_str).desired_width(240.0),
                            );
                            ui.end_row();

                            ui.label("Message");
                            ui.add_enabled(
                                !busy,
                                TextEdit::multiline(&mut *message_str).desired_width(240.0),
                            );
                            ui.end_row();
                        });

                    ui.add_space(4.0);

                    ui.horizontal(|ui| {
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
                            let message = OutgoingMessage::PlainText(init_msg);
                            let promise = Promise::spawn_async(async move {
                                flatten_rpc(get_rpc().convo_send(convo_id, message).await)
                                    .map(|_| ())
                            });
                            add_contact.start(promise);
                        }
                        if busy {
                            ui.add(Spinner::new());
                        }
                    });

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
            *self.open = window_open;
        })
        .response
    }
}
