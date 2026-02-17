use eframe::egui::{Response, TextEdit, Widget, Window};
use egui_hooks::UseHookExt;
use egui_hooks::hook::state::Var;
use nullspace_client::internal::{ProvisionHostPhase, ProvisionHostStart, ProvisionHostStatus};
use poll_promise::Promise;
use pollster::block_on;

use crate::NullspaceApp;
use crate::promises::{PromiseSlot, flatten_rpc};
use crate::rpc::get_rpc;

pub struct AddDevice<'a> {
    pub app: &'a mut NullspaceApp,
    pub open: &'a mut bool,
}

impl Widget for AddDevice<'_> {
    fn ui(self, ui: &mut eframe::egui::Ui) -> Response {
        let mut session_id: Var<Option<u64>> = ui.use_state(|| None, ()).into_var();
        let mut display_code: Var<String> = ui.use_state(String::new, ()).into_var();
        let mut phase: Var<ProvisionHostPhase> =
            ui.use_state(|| ProvisionHostPhase::Pending, ()).into_var();
        let mut phase_error: Var<Option<String>> = ui.use_state(|| None::<String>, ()).into_var();

        let start_req = ui.use_state(PromiseSlot::<Result<ProvisionHostStart, String>>::new, ());
        if let Some(result) = start_req.take() {
            match result {
                Ok(start) => {
                    *session_id = Some(start.session_id);
                    *display_code = start.display_code;
                    *phase = ProvisionHostPhase::Pending;
                    *phase_error = None;
                }
                Err(err) => {
                    self.app.state.error_dialog = Some(err);
                }
            }
        }

        if *self.open {
            if let Some(current) = *session_id {
                match flatten_rpc(block_on(get_rpc().provision_host_status(current))) {
                    Ok(ProvisionHostStatus {
                        phase: current_phase,
                        display_code: current_code,
                        error: current_error,
                    }) => {
                        *display_code = current_code;
                        *phase = current_phase;
                        *phase_error = current_error;
                    }
                    Err(err) => {
                        tracing::warn!(
                            session_id = current,
                            error = %err,
                            "provision_host_status failed; restarting session",
                        );
                        if let Err(stop_err) = flatten_rpc(block_on(get_rpc().provision_host_stop(current)))
                        {
                            tracing::warn!(
                                session_id = current,
                                error = %stop_err,
                                "provision_host_stop failed during status-error restart",
                            );
                        }
                        reset_pairing_state(
                            &mut session_id,
                            &mut display_code,
                            &mut phase,
                            &mut phase_error,
                        );
                        if start_req.is_idle() {
                            let promise = Promise::spawn_async(async move {
                                flatten_rpc(get_rpc().provision_host_start().await)
                            });
                            start_req.start(promise);
                        }
                    }
                }
            }
            if session_id.is_some() || start_req.is_running() {
                ui.ctx().request_repaint();
            }

            let mut window_open = *self.open;
            let center = ui.ctx().content_rect().center();
            Window::new("Add device")
                .collapsible(false)
                .default_pos(center)
                .open(&mut window_open)
                .show(ui.ctx(), |ui| {
                    ui.label("Start pairing and enter the code on the new device.");

                    let can_start = !start_req.is_running();
                    let button_label = if session_id.is_some() {
                        "Restart pairing"
                    } else {
                        "Start pairing"
                    };
                    if ui
                        .add_enabled(can_start, eframe::egui::Button::new(button_label))
                        .clicked()
                    {
                        if let Some(existing) = *session_id {
                            if let Err(err) =
                                flatten_rpc(block_on(get_rpc().provision_host_stop(existing)))
                            {
                                tracing::warn!(
                                    session_id = existing,
                                    error = %err,
                                    "provision_host_stop failed on restart",
                                );
                            }
                        }
                        reset_pairing_state(
                            &mut session_id,
                            &mut display_code,
                            &mut phase,
                            &mut phase_error,
                        );

                        let promise = Promise::spawn_async(async move {
                            flatten_rpc(get_rpc().provision_host_start().await)
                        });
                        start_req.start(promise);
                    }

                    if start_req.is_running() {
                        ui.label("Starting pairing...");
                    }

                    if !display_code.is_empty() {
                        ui.label("Pairing code");
                        let mut copy_code = (*display_code).clone();
                        ui.add(
                            TextEdit::singleline(&mut copy_code)
                                .interactive(false)
                                .desired_width(220.0),
                        );
                        ui.label("Use the latest code shown above.");
                    }

                    match *phase {
                        ProvisionHostPhase::Pending => {
                            if session_id.is_some() {
                                ui.label("Waiting for the new device to connect...");
                            }
                        }
                        ProvisionHostPhase::Completed => {
                            ui.label("Pairing completed.");
                        }
                        ProvisionHostPhase::Failed => {
                            let message = (*phase_error)
                                .clone()
                                .unwrap_or_else(|| "Pairing failed".to_string());
                            ui.label(message);
                        }
                    }
                });
            *self.open = window_open;
        } else if let Some(existing) = *session_id {
            if let Err(err) = flatten_rpc(block_on(get_rpc().provision_host_stop(existing))) {
                tracing::warn!(
                    session_id = existing,
                    error = %err,
                    "provision_host_stop failed on close",
                );
            }
            reset_pairing_state(
                &mut session_id,
                &mut display_code,
                &mut phase,
                &mut phase_error,
            );
        }
        ui.response()
    }
}

fn reset_pairing_state(
    session_id: &mut Var<Option<u64>>,
    display_code: &mut Var<String>,
    phase: &mut Var<ProvisionHostPhase>,
    phase_error: &mut Var<Option<String>>,
) {
    **session_id = None;
    **display_code = String::new();
    **phase = ProvisionHostPhase::Pending;
    **phase_error = None;
}
