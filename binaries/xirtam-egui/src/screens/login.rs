use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use eframe::egui::{Button, Response, Spinner, Widget};
use egui_hooks::UseHookExt;
use poll_promise::Promise;

use crate::XirtamApp;
use crate::promises::{PromiseSlot, flatten_rpc};

pub struct Login<'a>(pub &'a mut XirtamApp);

#[derive(Clone, Copy)]
enum LoginStep {
    EnterHandle,
    FinishBootstrap,
    FinishAddDevice,
}

impl Widget for Login<'_> {
    fn ui(self, ui: &mut eframe::egui::Ui) -> Response {
        let step = ui.use_state(|| LoginStep::EnterHandle, ());
        let mut handle_str = ui.use_state(|| "@alice01".to_string(), ()).into_var();
        let mut gateway_str = ui.use_state(|| "~demo01".to_string(), ()).into_var();
        let mut bundle_str = ui.use_state(String::new, ()).into_var();
        let register_info = ui.use_state(|| None::<xirtam_client::internal::RegisterStartInfo>, ());
        let register_start = ui.use_state(PromiseSlot::new, ());
        let register_finish = ui.use_state(PromiseSlot::new, ());

        ui.heading("Login");

        match *step {
            LoginStep::EnterHandle => {
                ui.text_edit_singleline(&mut *handle_str);
                let busy = register_start.is_running() || register_finish.is_running();
                if ui.add_enabled(!busy, Button::new("Check")).clicked() {
                    let handle = match handle_str.parse::<xirtam_structs::handle::Handle>() {
                        Ok(handle) => handle,
                        Err(err) => {
                            self.0.state.error_dialog = Some(format!("invalid handle: {err}"));
                            return ui.response();
                        }
                    };
                    let rpc = self.0.client.rpc();
                    let promise = Promise::spawn_async(async move {
                        flatten_rpc(rpc.register_start(handle).await)
                    });
                    register_start.start(promise);
                }
                if register_start.is_running() {
                    ui.add(Spinner::new());
                }
                if let Some(result) = register_start.poll() {
                    match result {
                        Ok(Some(info)) => {
                            register_info.set_next(Some(info.clone()));
                            *gateway_str = info.gateway_name.as_str().to_string();
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
                ui.horizontal(|ui| {
                    ui.label("Handle");
                    ui.text_edit_singleline(&mut *handle_str);
                });
                ui.horizontal(|ui| {
                    ui.label("Gateway");
                    ui.text_edit_singleline(&mut *gateway_str);
                });
                let register_enabled =
                    !register_start.is_running() && !register_finish.is_running();
                if ui
                    .add_enabled(register_enabled, eframe::egui::Button::new("Register"))
                    .clicked()
                {
                    let handle = match handle_str.parse::<xirtam_structs::handle::Handle>() {
                        Ok(handle) => handle,
                        Err(err) => {
                            self.0.state.error_dialog = Some(format!("invalid handle: {err}"));
                            return ui.response();
                        }
                    };
                    let gateway_name =
                        match gateway_str.parse::<xirtam_structs::gateway::GatewayName>() {
                            Ok(gateway_name) => gateway_name,
                            Err(err) => {
                                self.0.state.error_dialog = Some(format!("invalid gateway: {err}"));
                                return ui.response();
                            }
                        };
                    let request = xirtam_client::internal::RegisterFinish::BootstrapNewHandle {
                        handle,
                        gateway_name,
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
                            self.0.state.error_dialog = Some("registration submitted".to_string());
                        }
                        Err(err) => {
                            self.0.state.error_dialog = Some(format!("register_finish: {err}"));
                        }
                    }
                }
            }
            LoginStep::FinishAddDevice => {
                let info = (*register_info).clone();
                let Some(info) = info else {
                    self.0.state.error_dialog = Some("missing register info".to_string());
                    step.set_next(LoginStep::EnterHandle);
                    return ui.response();
                };
                ui.label(format!("Handle: {}", info.handle.as_str()));
                ui.label(format!("Gateway: {}", info.gateway_name.as_str()));
                ui.add_space(8.0);
                ui.label("Bundle");
                ui.text_edit_multiline(&mut *bundle_str);
                ui.add_space(8.0);
                let add_enabled = !register_start.is_running() && !register_finish.is_running();
                if ui
                    .add_enabled(add_enabled, eframe::egui::Button::new("Add device"))
                    .clicked()
                {
                    let raw = match URL_SAFE_NO_PAD.decode(bundle_str.trim()) {
                        Ok(raw) => raw,
                        Err(err) => {
                            self.0.state.error_dialog = Some(format!("invalid bundle: {err}"));
                            return ui.response();
                        }
                    };
                    let bundle = xirtam_client::internal::NewDeviceBundle(raw.into());
                    let request = xirtam_client::internal::RegisterFinish::AddDevice { bundle };
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
        ui.response()
    }
}
