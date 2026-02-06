use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use eframe::egui::{DragValue, Response, TextEdit, Widget, Window};
use egui_hooks::UseHookExt;
use egui_hooks::hook::state::Var;
use poll_promise::Promise;
use nullspace_structs::timestamp::Timestamp;

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
        let mut bundle_str: Var<String> = ui.use_state(String::new, ()).into_var();
        let bundle_req = ui.use_state(
            PromiseSlot::<Result<nullspace_client::internal::NewDeviceBundle, String>>::new,
            (),
        );

        if *self.open {
            let mut window_open = *self.open;
            let center = ui.ctx().content_rect().center();
            Window::new("Add device")
                .collapsible(false)
                .default_pos(center)
                .open(&mut window_open)
                .show(ui.ctx(), |ui| {
                    ui.label("Generate a device bundle here, then paste it into the new device");
                    let busy = bundle_req.is_running();
                    ui.checkbox(&mut can_issue, "Allow this device to issue new devices");
                    ui.checkbox(&mut never_expires, "Never expires");
                    ui.add_enabled_ui(!*never_expires, |ui| {
                        ui.horizontal(|ui| {
                            ui.label("Expires in days");
                            ui.add(DragValue::new(&mut *expiry_days).speed(1));
                        });
                    });
                    if ui
                        .add_enabled(!busy, eframe::egui::Button::new("Generate bundle"))
                        .clicked()
                    {
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
                            flatten_rpc(get_rpc().new_device_bundle(can_issue, expiry).await)
                        });
                    bundle_req.start(promise);
                }

                    if let Some(result) = bundle_req.take() {
                        match result {
                            Ok(bundle) => {
                                let encoded = URL_SAFE_NO_PAD.encode(bundle.0);
                                *bundle_str = encoded;
                            }
                            Err(err) => {
                                self.app.state.error_dialog = Some(err);
                            }
                        }
                    }

                    ui.label("Device bundle");
                    ui.add(
                        TextEdit::multiline(&mut *bundle_str)
                            .desired_rows(6)
                            .desired_width(360.0),
                    );
                });
            *self.open = window_open;
        }
        ui.response()
    }
}
