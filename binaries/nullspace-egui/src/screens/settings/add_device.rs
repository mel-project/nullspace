use std::{ops::Deref, time::Duration};

use eframe::egui::Ui;
use egui::{Color32, FontFamily, FontId, RichText, Spinner};
use egui_hooks::{UseHookExt, hook::state::State};
use nullspace_client::ProvisionHostState;

use crate::rpc::get_rpc;
use crate::utils::generational::GBox;
use crate::utils::hooks::CustomHooksExt;

pub(super) fn render(ui: &mut Ui) {
    let pairing_code: State<Option<String>> = ui.use_state(|| None, ());
    let pairing_done: State<bool> = ui.use_state(|| false, ());
    let fatal_error: State<Option<String>> = ui.use_state(|| None, ());
    let task: GBox<Option<smol::Task<()>>> = ui.use_gbox(|| None, ());
    let mut refreshes = ui.use_state(|| 0, ()).into_var();

    ui.use_cleanup(
        move || {
            task.set(None);
            smol::spawn(async move {
                let _ = get_rpc().provision_host_stop().await;
            })
            .detach();
        },
        (),
    );
    ui.use_effect(
        || {
            let pairing_code = pairing_code.clone();
            let pairing_done = pairing_done.clone();
            let fatal_error = fatal_error.clone();
            task.set(None);
            task.set(Some(smol::spawn(async move {
                let result: anyhow::Result<()> = async {
                    let rpc = get_rpc();
                    let display_code = rpc.provision_host_start().await??;
                    pairing_code.set_next(Some(display_code));
                    pairing_done.set_next(false);
                    loop {
                        match rpc.provision_host_status().await?? {
                            ProvisionHostState::Idle => {
                                anyhow::bail!("host provisioning stopped unexpectedly")
                            }
                            ProvisionHostState::Pending { display_code } => {
                                pairing_code.set_next(Some(display_code));
                            }
                            ProvisionHostState::Completed => break,
                            ProvisionHostState::Failed { error } => anyhow::bail!(error),
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

    ui.vertical_centered(|ui| {
        let code_font = FontId::new(20.0, FontFamily::Proportional);
        let code_height = ui.fonts_mut(|fonts| fonts.row_height(&code_font));

        ui.label("Pair a new device with this code:");
        if let Some(fatal_error) = fatal_error.deref() {
            ui.colored_label(ui.visuals().error_fg_color, fatal_error);
        }
        if let Some(pairing_code) = pairing_code.deref() {
            let mut text = RichText::new(pairing_code.as_str()).size(20.0);
            if *pairing_done {
                text = text.strikethrough();
            }
            ui.label(text);
        } else {
            ui.add(Spinner::new().size(code_height));
        }
        if *pairing_done {
            ui.colored_label(success_fg_color(ui.visuals()), "Device added.");
        }
        if ui.button("Refresh code").clicked() {
            fatal_error.set_next(None);
            *refreshes += 1;
        }
    });
}

fn success_fg_color(visuals: &egui::Visuals) -> Color32 {
    if visuals.dark_mode {
        Color32::from_rgb(120, 220, 140)
    } else {
        Color32::from_rgb(0, 135, 60)
    }
}
