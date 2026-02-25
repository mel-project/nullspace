use std::time::Duration;

use eframe::egui::{Button, Grid, Response, TextEdit, Widget, Window};
use nullspace_client::internal::{ConvoId, OutgoingMessage};
use nullspace_structs::username::UserName;

use crate::NullspaceApp;
use crate::rpc::flatten_rpc;
use crate::rpc::get_rpc;
use crate::utils::hooks::CustomHooksExt;

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
            let username_str = ui.use_gbox(String::new, ());
            let message_str = ui.use_gbox(String::new, ());
            let validate_username = ui.use_async(
                async move {
                    smol::Timer::after(Duration::from_millis(100)).await;
                    anyhow::Ok(
                        get_rpc()
                            .user_details(username_str.get().parse()?)
                            .await??,
                    )
                },
                username_str.get(),
            );
            let username_valid = validate_username.map(|s| s.is_ok()).unwrap_or_default();
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
                            ui.add(
                                TextEdit::singleline(&mut *username_str.write())
                                    .desired_width(120.0),
                            );
                            ui.end_row();

                            ui.label("Message");
                            ui.add(
                                TextEdit::multiline(&mut *message_str.write()).desired_width(120.0),
                            );
                            ui.end_row();
                        });

                    ui.add_space(4.0);

                    ui.horizontal(|ui| {
                        if ui.add_enabled(username_valid, Button::new("Add")).clicked() {
                            let username = match UserName::parse(username_str.get().trim()) {
                                Ok(username) => username,
                                Err(err) => {
                                    self.app.state.error_dialog =
                                        Some(format!("invalid username: {err}"));
                                    return;
                                }
                            };
                            let convo_id = ConvoId::Direct { peer: username };
                            let message = OutgoingMessage::PlainText(message_str.get());
                            smol::spawn(async move {
                                flatten_rpc(get_rpc().convo_send(convo_id, message).await)
                                    .map(|_| ())
                            })
                            .detach();
                        }
                    });
                });
            *self.open = window_open;
        })
        .response
    }
}
