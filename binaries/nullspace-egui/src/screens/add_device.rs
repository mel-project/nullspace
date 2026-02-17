use std::time::Duration;

use eframe::egui::{DragValue, Response, TextEdit, Widget, Window};
use egui_hooks::UseHookExt;
use egui_hooks::hook::state::Var;
use nullspace_client::internal::{ProvisionHostPhase, ProvisionHostStart, ProvisionHostStatus};
use nullspace_structs::timestamp::Timestamp;
use poll_promise::Promise;

use crate::NullspaceApp;
use crate::promises::{PromiseSlot, flatten_rpc};
use crate::rpc::get_rpc;

pub struct AddDevice<'a> {
    pub app: &'a mut NullspaceApp,
    pub open: &'a mut bool,
}

impl Widget for AddDevice<'_> {
    fn ui(self, ui: &mut eframe::egui::Ui) -> Response {
        let mut can_issue: Var<bool> = ui.use_state(|| true, ()).into_var();
        let mut never_expires: Var<bool> = ui.use_state(|| true, ()).into_var();
        let mut expiry_days: Var<u32> = ui.use_state(|| 365, ()).into_var();
        let mut session_id: Var<Option<u64>> = ui.use_state(|| None, ()).into_var();
        let mut display_code: Var<String> = ui.use_state(String::new, ()).into_var();
        let mut phase: Var<ProvisionHostPhase> =
            ui.use_state(|| ProvisionHostPhase::Pending, ()).into_var();
        let mut phase_error: Var<Option<String>> = ui.use_state(|| None::<String>, ()).into_var();

        let start_req = ui.use_state(PromiseSlot::<Result<ProvisionHostStart, String>>::new, ());
        let status_req = ui.use_state(PromiseSlot::<Result<ProvisionHostStatus, String>>::new, ());
        let stop_req = ui.use_state(PromiseSlot::<Result<(), String>>::new, ());

        if let Some(result) = stop_req.take()
            && let Err(err) = result
        {
            self.app.state.error_dialog = Some(err);
        }
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
        if let Some(result) = status_req.take() {
            match result {
                Ok(status) => {
                    *display_code = status.display_code;
                    *phase = status.phase;
                    *phase_error = status.error;
                }
                Err(err) => {
                    self.app.state.error_dialog = Some(err);
                }
            }
        }

        if *self.open {
            if let Some(current) = *session_id
                && status_req.is_idle()
            {
                let promise = Promise::spawn_async(async move {
                    flatten_rpc(get_rpc().provision_host_status(current).await)
                });
                status_req.start(promise);
                ui.ctx()
                    .request_repaint_after(Duration::from_millis(250));
            }

            let mut window_open = *self.open;
            let center = ui.ctx().content_rect().center();
            Window::new("Add device")
                .collapsible(false)
                .default_pos(center)
                .open(&mut window_open)
                .show(ui.ctx(), |ui| {
                    ui.label("Start pairing and enter the code on the new device.");
                    ui.label("If pairing does not complete, this code auto-refreshes every 15 seconds.");

                    let can_start = !start_req.is_running();
                    ui.checkbox(&mut can_issue, "Allow this device to issue new devices");
                    ui.checkbox(&mut never_expires, "Never expires");
                    ui.add_enabled_ui(!*never_expires, |ui| {
                        ui.horizontal(|ui| {
                            ui.label("Expires in days");
                            ui.add(DragValue::new(&mut *expiry_days).speed(1));
                        });
                    });

                    let button_label = if session_id.is_some() {
                        "Restart pairing"
                    } else {
                        "Start pairing"
                    };
                    if ui
                        .add_enabled(can_start, eframe::egui::Button::new(button_label))
                        .clicked()
                    {
                        if let Some(existing) = *session_id
                            && stop_req.is_idle()
                        {
                            let promise = Promise::spawn_async(async move {
                                flatten_rpc(get_rpc().provision_host_stop(existing).await)
                            });
                            stop_req.start(promise);
                        }
                        *session_id = None;
                        *display_code = String::new();
                        *phase = ProvisionHostPhase::Pending;
                        *phase_error = None;

                        let expiry = if *never_expires {
                            Timestamp(u64::MAX)
                        } else {
                            let secs = u64::from(*expiry_days)
                                .saturating_mul(86_400)
                                .saturating_add(Timestamp::now().0);
                            Timestamp(secs)
                        };
                        let can_issue = *can_issue;
                        let promise = Promise::spawn_async(async move {
                            flatten_rpc(get_rpc().provision_host_start(can_issue, expiry).await)
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
        } else if let Some(existing) = *session_id
            && stop_req.is_idle()
        {
            let promise = Promise::spawn_async(async move {
                flatten_rpc(get_rpc().provision_host_stop(existing).await)
            });
            stop_req.start(promise);
            *session_id = None;
            *display_code = String::new();
            *phase = ProvisionHostPhase::Pending;
            *phase_error = None;
        }
        ui.response()
    }
}
