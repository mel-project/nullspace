use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use eframe::egui::{DragValue, Modal, Response, TextEdit, Widget};
use egui_hooks::UseHookExt;
use egui_hooks::hook::state::Var;
use poll_promise::Promise;
use xirtam_structs::timestamp::Timestamp;

use crate::XirtamApp;
use crate::promises::{PromiseSlot, flatten_rpc};

pub struct AddDevice<'a> {
    pub app: &'a mut XirtamApp,
    pub open: &'a mut bool,
}

impl Widget for AddDevice<'_> {
    fn ui(self, ui: &mut eframe::egui::Ui) -> Response {
        let mut can_issue: Var<bool> = ui.use_state(|| true, ()).into_var();
        let mut never_expires: Var<bool> = ui.use_state(|| true, ()).into_var();
        let mut expiry_days: Var<u32> = ui.use_state(|| 365, ()).into_var();
        let mut bundle_str: Var<String> = ui.use_state(String::new, ()).into_var();
        let bundle_req = ui.use_state(PromiseSlot::new, ());

        if *self.open {
            let modal = Modal::new("add_device_modal".into()).show(ui.ctx(), |ui| {
                ui.heading("Add device");
                ui.separator();
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
                    let rpc = self.app.client.rpc();
                    let can_issue = *can_issue;
                    let promise = Promise::spawn_async(async move {
                        flatten_rpc(rpc.new_device_bundle(can_issue, expiry).await)
                    });
                    bundle_req.start(promise);
                }

                if let Some(result) = bundle_req.poll() {
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
                if ui.button("Close").clicked() {
                    *self.open = false;
                }
            });
            if modal.should_close() {
                *self.open = false;
            }
        }
        ui.response()
    }
}
