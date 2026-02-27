use std::{ops::Deref, time::Duration};

use eframe::egui::Ui;
use egui::{Color32, RichText};
use egui_hooks::{UseHookExt, hook::state::State};
use nullspace_client::internal::ProvisionHostPhase;

use crate::rpc::get_rpc;
use crate::utils::generational::GBox;
use crate::utils::hooks::CustomHooksExt;

pub(super) fn render(ui: &mut Ui) {
    let pairing_code: State<Option<String>> = ui.use_state(|| None, ());
    let pairing_done: State<bool> = ui.use_state(|| false, ());
    let fatal_error: State<Option<String>> = ui.use_state(|| None, ());
    let session_id: GBox<Option<u64>> = ui.use_gbox(|| None, ());
    let task: GBox<Option<smol::Task<()>>> = ui.use_gbox(|| None, ());
    let mut refreshes = ui.use_state(|| 0, ()).into_var();

    ui.use_cleanup(
        move || {
            task.set(None);
            if let Some(id) = session_id.get() {
                smol::spawn(async move {
                    let _ = get_rpc().provision_host_stop(id).await;
                })
                .detach();
            }
        },
        (),
    );
    ui.use_effect(
        || {
            let pairing_code = pairing_code.clone();
            let pairing_done = pairing_done.clone();
            let fatal_error = fatal_error.clone();
            task.set(None);
            let old_session_id = session_id.get();
            task.set(Some(smol::spawn(async move {
                if let Some(old_id) = old_session_id {
                    let _ = get_rpc().provision_host_stop(old_id).await;
                }
                let result: anyhow::Result<()> = async {
                    let rpc = get_rpc();
                    let started = rpc.provision_host_start().await??;
                    session_id.set(Some(started.session_id));
                    pairing_code.set_next(started.display_code.into());
                    pairing_done.set_next(false);
                    loop {
                        let status = rpc.provision_host_status(started.session_id).await??;
                        match status.phase {
                            ProvisionHostPhase::Pending => {}
                            ProvisionHostPhase::Completed => break,
                            ProvisionHostPhase::Failed => {
                                anyhow::bail!("failed to provision host at the end")
                            }
                        }
                        smol::Timer::after(Duration::from_secs(1)).await;
                    }
                    pairing_done.set_next(true);
                    anyhow::Ok(())
                }
                .await;
                if let Err(err) = result {
                    fatal_error.set_next(Some(err.to_string()));
                }
            })));
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
        if *pairing_done {
            ui.colored_label(Color32::DARK_GREEN, "Device added.");
        }
        if ui.button("Refresh code").clicked() {
            fatal_error.set_next(None);
            *refreshes += 1;
        }
    });
}
