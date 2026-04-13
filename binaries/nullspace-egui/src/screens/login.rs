use eframe::egui::{Button, Response, Spinner, Widget};
use egui::{Color32, ComboBox, Modal, RichText, TextEdit};
use egui_hooks::UseHookExt;
use nullspace_client::RegisterFinish;
use nullspace_structs::username::UserName;

use crate::NullspaceApp;
use crate::rpc::{flatten_rpc, get_rpc};
use crate::utils::color::identity_color;
use crate::utils::hooks::CustomHooksExt;

pub struct Login<'a>(pub &'a mut NullspaceApp);

#[derive(Clone, Copy, Default)]
enum LoginStep {
    #[default]
    EnterUsername,
    FinishBootstrap,
    FinishAddDevice,
}

#[derive(Clone)]
enum LoginRpcOutcome {
    Start { user_exists: bool },
    FinishBootstrap,
    FinishAddDevice,
}

impl Widget for Login<'_> {
    fn ui(self, ui: &mut eframe::egui::Ui) -> Response {
        let mut step = ui.use_state(LoginStep::default, ()).into_var();
        let mut rpc_error = ui.use_state(|| None::<String>, ()).into_var();
        let mut rpc_notice = ui.use_state(|| None::<String>, ()).into_var();
        let rpc = ui.use_async_slot::<Result<LoginRpcOutcome, String>>(());
        let mut username_str = ui.use_state(|| "".to_string(), ()).into_var();
        let mut server_choice = ui.use_state(|| "~public_test".to_string(), ()).into_var();
        let mut custom_server_str = ui.use_state(|| "".to_string(), ()).into_var();
        let mut pairing_code = ui.use_state(String::new, ()).into_var();

        let rpc_running = rpc.is_busy();
        if let Some(result) = rpc.take() {
            match result {
                Ok(LoginRpcOutcome::Start { user_exists: true }) => {
                    *step = LoginStep::FinishAddDevice;
                }
                Ok(LoginRpcOutcome::Start { user_exists: false }) => {
                    *step = LoginStep::FinishBootstrap;
                }
                Ok(LoginRpcOutcome::FinishBootstrap) => {
                    *rpc_notice = Some("registration submitted".to_string());
                }
                Ok(LoginRpcOutcome::FinishAddDevice) => {
                    *rpc_notice = Some("device added".to_string());
                }
                Err(err) => {
                    *rpc_error = Some(err);
                }
            }
        }

        Modal::new(ui.next_auto_id()).show(ui.ctx(), |ui| {
            if let Some(err) = rpc_error.as_ref() {
                ui.colored_label(ui.visuals().error_fg_color, err);
            }
            if let Some(notice) = rpc_notice.as_ref() {
                ui.colored_label(success_fg_color(ui.visuals()), notice);
            }
            ui.heading("Login or register");
            ui.separator();
            match *step {
                LoginStep::EnterUsername => {
                    ui.add(
                        TextEdit::singleline(&mut *username_str).hint_text("Enter a @username"),
                    );

                    if rpc_running {
                        ui.add(Spinner::new());
                    } else if ui.add(Button::new("Next")).clicked() {
                        let username = match username_str.parse::<UserName>() {
                            Ok(username) => username,
                            Err(err) => {
                                self.0.state.error_dialog = Some(format!("invalid username: {err}"));
                                return;
                            }
                        };
                        *rpc_error = None;
                        *rpc_notice = None;
                        rpc.start(async move {
                            flatten_rpc(get_rpc().register_start(username).await)
                                .map(|value| LoginRpcOutcome::Start {
                                    user_exists: value.is_some(),
                                })
                                .map_err(|err| format!("register_start: {err}"))
                        });
                    }
                }
                LoginStep::FinishBootstrap => {
                    let username: UserName = username_str.parse().unwrap();
                    ui.label("You are registering a new user:");
                    ui.colored_label(identity_color(&username), username.as_str());

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

                    let server_str = if *server_choice == "Custom" {
                        ui.add(
                            TextEdit::singleline(&mut *custom_server_str)
                                .hint_text("Enter a ~server_id"),
                        );
                        (*custom_server_str).clone()
                    } else {
                        ui.label(
                            RichText::new(
                                "Hint: ~public_test (hosted in the US) and ~public_test_cn (hosted in China) are test servers run by the Nullspace developers",
                            )
                            .size(10.0),
                        );
                        (*server_choice).clone()
                    };

                    let register_enabled = !rpc_running;

                    ui.horizontal_centered(|ui| {
                        if ui
                            .add_enabled(register_enabled, eframe::egui::Button::new("Register"))
                            .clicked()
                        {
                            let server_name =
                                match server_str.parse::<nullspace_structs::server::ServerName>() {
                                    Ok(server_name) => server_name,
                                    Err(err) => {
                                        self.0.state.error_dialog =
                                            Some(format!("invalid server: {err}"));
                                        return;
                                    }
                                };
                            *rpc_error = None;
                            *rpc_notice = None;
                            let request = RegisterFinish::BootstrapNewUser {
                                username,
                                server_name,
                            };
                            rpc.start(async move {
                                flatten_rpc(get_rpc().register_finish(request).await)
                                    .map(|()| LoginRpcOutcome::FinishBootstrap)
                                    .map_err(|err| format!("register_finish: {err}"))
                            });
                        }
                        if rpc_running {
                            ui.add(Spinner::new());
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
                    let add_enabled = !rpc_running;
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
                        *rpc_error = None;
                        *rpc_notice = None;
                        let request = RegisterFinish::AddDeviceByCode {
                            username,
                            code: (*pairing_code).trim().to_string(),
                        };
                        rpc.start(async move {
                            flatten_rpc(get_rpc().register_finish(request).await)
                                .map(|()| LoginRpcOutcome::FinishAddDevice)
                                .map_err(|err| format!("register_finish: {err}"))
                        });
                    }
                    if rpc_running {
                        ui.add(Spinner::new());
                    }
                }
            }
        });

        ui.response()
    }
}

fn success_fg_color(visuals: &egui::Visuals) -> Color32 {
    if visuals.dark_mode {
        Color32::from_rgb(120, 220, 140)
    } else {
        Color32::from_rgb(0, 135, 60)
    }
}
