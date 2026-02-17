use eframe::egui::{Button, Response, Spinner, Widget};
use egui::{ComboBox, Modal, RichText, TextEdit};
use egui_hooks::UseHookExt;
use nullspace_client::internal::RegisterFinish;
use nullspace_structs::username::UserName;
use poll_promise::Promise;

use crate::NullspaceApp;
use crate::promises::{PromiseSlot, flatten_rpc};
use crate::rpc::get_rpc;
use crate::utils::color::username_color;

pub struct Login<'a>(pub &'a mut NullspaceApp);

#[derive(Clone, Copy)]
enum LoginStep {
    EnterUsername,
    FinishBootstrap,
    FinishAddDevice,
}

impl Widget for Login<'_> {
    fn ui(self, ui: &mut eframe::egui::Ui) -> Response {
        let step = ui.use_state(|| LoginStep::EnterUsername, ());
        let mut username_str = ui.use_state(|| "".to_string(), ()).into_var();
        let mut server_str = ui.use_state(|| "".to_string(), ()).into_var();
        let mut server_choice = ui.use_state(|| "~public_test".to_string(), ()).into_var();
        let mut custom_server_str = ui.use_state(|| "".to_string(), ()).into_var();
        let mut pairing_code = ui.use_state(String::new, ()).into_var();

        let register_start = ui.use_state(PromiseSlot::new, ());
        let register_finish = ui.use_state(PromiseSlot::new, ());
        Modal::new(ui.next_auto_id()).show(ui.ctx(), |ui| {
            ui.heading("Login or register");
            ui.separator();
            match *step {
                LoginStep::EnterUsername => {
                    ui.add(
                        TextEdit::singleline(&mut *username_str).hint_text("Enter a @username"),
                    );

                    if register_start.is_running() {
                        ui.add(Spinner::new());
                    } else if ui.add(Button::new("Next")).clicked() {
                        let username = match username_str.parse::<nullspace_structs::username::UserName>() {
                            Ok(username) => username,
                            Err(err) => {
                                self.0.state.error_dialog = Some(format!("invalid username: {err}"));
                                return;
                            }
                        };
                        let promise = Promise::spawn_async(async move {
                            flatten_rpc(get_rpc().register_start(username).await)
                        });
                        register_start.start(promise);
                    }
                    if let Some(result) = register_start.take() {
                        match result {
                            Ok(Some(info)) => {
                                *server_str = info.server_name.as_str().to_string();
                                step.set_next(LoginStep::FinishAddDevice);
                            }
                            Ok(None) => {
                                step.set_next(LoginStep::FinishBootstrap);
                            }
                            Err(err) => {
                                self.0.state.error_dialog = Some(format!("register_start: {err}"));
                            }
                        }
                    }
                }
                LoginStep::FinishBootstrap => {
                    let username: UserName = username_str.parse().unwrap();
                    ui.label("You are registering a new user:");
                    ui.colored_label(username_color(&username), username.as_str());

                    ui.horizontal(|ui| {
                        ui.label("Server");
                        ComboBox::from_id_salt("register_server_choice")
                            .selected_text(server_choice.as_str())
                            .show_ui(ui, |ui| {
                                ui.selectable_value(
                                    &mut *server_choice,
                                    "~public_test".to_string(),
                                    "~public_test",
                                );
                                ui.selectable_value(
                                    &mut *server_choice,
                                    "~public_test_cn".to_string(),
                                    "~public_test_cn",
                                );
                                ui.selectable_value(
                                    &mut *server_choice,
                                    "Custom".to_string(),
                                    "Custom",
                                );
                            });
                    });

                    if *server_choice == "Custom" {
                        ui.add(
                            TextEdit::singleline(&mut *custom_server_str)
                                .hint_text("Enter a ~server_id"),
                        );
                        *server_str = (*custom_server_str).clone();
                    } else {
                        *server_str = (*server_choice).clone();
                        ui.label(
                            RichText::new(
                                "Hint: ~public_test (hosted in the US) and ~public_test_cn (hosted in China) are test servers run by the Nullspace developers",
                            )
                            .size(10.0),
                        );
                    }

                    let register_enabled =
                        !register_start.is_running() && !register_finish.is_running();

                    ui.horizontal_centered(|ui| {
                    if ui
                        .add_enabled(register_enabled, eframe::egui::Button::new("Register"))
                        .clicked()
                    {
                        let server_name = match server_str
                            .parse::<nullspace_structs::server::ServerName>()
                        {
                            Ok(server_name) => server_name,
                            Err(err) => {
                                self.0.state.error_dialog = Some(format!("invalid server: {err}"));
                                return;
                            }
                        };
                        let request = RegisterFinish::BootstrapNewUser {
                            username,
                            server_name,
                        };
                        let promise = Promise::spawn_async(async move {
                            flatten_rpc(get_rpc().register_finish(request).await)
                        });
                        register_finish.start(promise);
                    }
                    if register_finish.is_running() {
                        ui.add(Spinner::new());
                    }
                    if let Some(result) = register_finish.take() {
                        match result {
                            Ok(()) => {
                                self.0.state.error_dialog =
                                    Some("registration submitted".to_string());
                            }
                            Err(err) => {
                                self.0.state.error_dialog = Some(format!("register_finish: {err}"));
                            }
                        }
                    }
                });
                }
                LoginStep::FinishAddDevice => {
                    ui.label(format!("The user {username_str} exists!"));
                    ui.label("Enter the pairing code from your existing device:");
                    ui.text_edit_singleline(&mut *pairing_code);
                    ui.label(
                        RichText::new("On your other device, go to [File] > [Add device]").small(),
                    );
                    let add_enabled = !register_start.is_running() && !register_finish.is_running();
                    if ui
                        .add_enabled(add_enabled, eframe::egui::Button::new("Log in"))
                        .clicked()
                    {
                        let username: UserName = match username_str.parse() {
                            Ok(username) => username,
                            Err(err) => {
                                self.0.state.error_dialog = Some(format!("invalid username: {err}"));
                                return;
                            }
                        };
                        let request = nullspace_client::internal::RegisterFinish::AddDeviceByCode {
                            username,
                            code: (*pairing_code).trim().to_string(),
                        };
                        let promise = Promise::spawn_async(async move {
                            flatten_rpc(get_rpc().register_finish(request).await)
                        });
                        register_finish.start(promise);
                    }
                    if register_finish.is_running() {
                        ui.add(Spinner::new());
                    }
                    if let Some(result) = register_finish.take() {
                        match result {
                            Ok(()) => {
                                self.0.state.error_dialog = Some("device added".to_string());
                            }
                            Err(err) => {
                                self.0.state.error_dialog = Some(format!("add device: {err}"));
                            }
                        }
                    }
                }
            }
        });

        ui.response()
    }
}
