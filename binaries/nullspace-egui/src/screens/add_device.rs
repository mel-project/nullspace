use std::time::Duration;

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
        let center = ui.ctx().content_rect().center();
        Window::new("Add device")
            .collapsible(false)
            .default_pos(center)
            .open(&mut *self.open)
            .show(ui.ctx(), |ui| {
                let status = ui.use_state(|| 0, ());
                let s = status.clone();
                ui.use_effect(
                    || {
                        tokio::task::spawn(async move {
                            tokio::time::sleep(Duration::from_secs(1)).await;
                            s.set_next(1);
                        });
                    },
                    (),
                );
                ui.label(status.to_string());
            });
        ui.response()
    }
}
