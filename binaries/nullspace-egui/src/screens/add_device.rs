use std::{ops::Deref, time::Duration};

use crate::{NullspaceApp, rpc::get_rpc};
use eframe::egui::{Response, Widget, Window};
use egui::{Color32, RichText};
use egui_hooks::{UseHookExt, hook::state::State};
use futures_util::TryFutureExt;
use nullspace_client::internal::ProvisionHostPhase;

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
                let pairing_code: State<Option<String>> = ui.use_state(|| None, ());
                let pairing_done: State<bool> = ui.use_state(|| false, ());
                let fatal_error: State<Option<String>> = ui.use_state(|| None, ());
                let mut refreshes = ui.use_state(|| 0, ()).into_var();
                ui.use_effect(
                    || {
                        let pairing_code = pairing_code.clone();
                        let pairing_done = pairing_done.clone();
                        let fatal_error = fatal_error.clone();
                        tokio::task::spawn(
                            async move {
                                let rpc = get_rpc();
                                let started = rpc.provision_host_start().await??;
                                pairing_code.set_next(started.display_code.into());
                                loop {
                                    let status =
                                        rpc.provision_host_status(started.session_id).await??;
                                    match status.phase {
                                        ProvisionHostPhase::Pending => {}
                                        ProvisionHostPhase::Completed => break,
                                        ProvisionHostPhase::Failed => {
                                            anyhow::bail!("failed to provision host at the end")
                                        }
                                    }
                                    tokio::time::sleep(Duration::from_secs(1)).await;
                                }
                                pairing_done.set_next(true);
                                anyhow::Ok(())
                            }
                            .inspect_err(move |err| {
                                fatal_error.set_next(Some(err.to_string()));
                            }),
                        );
                    },
                    *refreshes,
                );
                ui.label("Pair a new device with this code:");
                ui.vertical_centered(|ui| {
                    if let Some(fatal_error) = fatal_error.deref() {
                        ui.colored_label(Color32::RED, fatal_error);
                    }
                    if let Some(pairing_code) = pairing_code.deref() {
                        ui.label(RichText::new(pairing_code).size(20.0));
                    } else {
                        ui.spinner();
                    }
                    if ui.button("Refresh code").clicked() {
                        *refreshes += 1;
                    }
                });
            });
        ui.response()
    }
}
