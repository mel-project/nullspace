use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use eframe::egui::{Button, Response, Spinner, Widget};
use egui::{ComboBox, Modal, RichText, TextEdit};
use egui_hooks::UseHookExt;
use nullspace_client::internal::RegisterFinish;
use nullspace_structs::username::UserName;
use poll_promise::Promise;

use crate::NullspaceApp;
use crate::promises::{PromiseSlot, flatten_rpc};
use crate::utils::color::username_color;
use crate::utils::markdown::layout_md;

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
        let mut bundle_str = ui.use_state(String::new, ()).into_var();
        let register_info =
            ui.use_state(|| None::<nullspace_client::internal::RegisterStartInfo>, ());
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
                        let rpc = self.0.client.rpc();
                        let promise = Promise::spawn_async(async move {
                            flatten_rpc(rpc.register_start(username).await)
                        });
                        register_start.start(promise);
                    }
                    if let Some(result) = register_start.poll() {
                        match result {
                            Ok(Some(info)) => {
                                register_info.set_next(Some(info.clone()));
                                *server_str = info.server_name.as_str().to_string();
                                step.set_next(LoginStep::FinishAddDevice);
                            }
                            Ok(None) => {
                                register_info.set_next(None);
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
                    ui.label(layout_md(ui, "You are registering a **new user**:"));
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
                        let rpc = self.0.client.rpc();
                        let promise = Promise::spawn_async(async move {
                            flatten_rpc(rpc.register_finish(request).await)
                        });
                        register_finish.start(promise);
                    }
                    if register_finish.is_running() {
                        ui.add(Spinner::new());
                    }
                    if let Some(result) = register_finish.poll() {
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
                    let info = (*register_info).clone();
                    let Some(_info) = info else {
                        self.0.state.error_dialog = Some("missing register info".to_string());
                        step.set_next(LoginStep::EnterUsername);
                        return;
                    };
                    ui.label(layout_md(ui, &format!("The user **{username_str}** exists!")));
                    ui.label(layout_md(
                        ui,
                        "You need to export a **device bundle** from an existing device:",
                    ));
                    ui.text_edit_multiline(&mut *bundle_str);
                    ui.label(
                        RichText::new("On your other device, go to [File] > [Add device]").small(),
                    );
                    let add_enabled = !register_start.is_running() && !register_finish.is_running();
                    if ui
                        .add_enabled(add_enabled, eframe::egui::Button::new("Log in"))
                        .clicked()
                    {
                        let raw = match URL_SAFE_NO_PAD.decode(bundle_str.trim()) {
                            Ok(raw) => raw,
                            Err(err) => {
                                self.0.state.error_dialog = Some(format!("invalid bundle: {err}"));
                                return;
                            }
                        };
                        let bundle = nullspace_client::internal::NewDeviceBundle(raw.into());
                        let request = nullspace_client::internal::RegisterFinish::AddDevice { bundle };
                        let rpc = self.0.client.rpc();
                        let promise = Promise::spawn_async(async move {
                            flatten_rpc(rpc.register_finish(request).await)
                        });
                        register_finish.start(promise);
                    }
                    if register_finish.is_running() {
                        ui.add(Spinner::new());
                    }
                    if let Some(result) = register_finish.poll() {
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
