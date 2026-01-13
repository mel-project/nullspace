use eframe::egui::{Response, ViewportCommand, Widget};
use egui::{Align, Button, Layout};
use egui_hooks::UseHookExt;
use egui_hooks::hook::state::Var;
use xirtam_structs::handle::Handle;

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::XirtamApp;
use crate::promises::flatten_rpc;
use crate::widgets::add_contact::AddContact;
use crate::widgets::add_device::AddDevice;
use crate::widgets::convo::Convo;
use crate::widgets::preferences::Preferences;

pub struct SteadyState<'a>(pub &'a mut XirtamApp);

impl Widget for SteadyState<'_> {
    fn ui(mut self, ui: &mut eframe::egui::Ui) -> Response {
        let rpc = Arc::new(self.0.client.rpc());
        let mut selected_chat: Var<Option<Handle>> = ui.use_state(|| None, ()).into_var();
        let mut show_add_contact: Var<bool> = ui.use_state(|| false, ()).into_var();
        let mut show_add_device: Var<bool> = ui.use_state(|| false, ()).into_var();
        let mut show_preferences: Var<bool> = ui.use_state(|| false, ()).into_var();
        let all_chats = ui.use_memo(
            || {
                let result = pollster::block_on(rpc.all_peers());
                flatten_rpc(result)
            },
            self.0.state.update_count,
        );

        let frame = eframe::egui::Frame::default().inner_margin(eframe::egui::Margin::same(8));
        eframe::egui::TopBottomPanel::top("steady_menu").show_inside(ui, |ui| {
            ui.horizontal(|ui| {
                ui.menu_button("File", |ui| {
                    if ui.button("Preferences").clicked() {
                        *show_preferences = true;
                        ui.close_menu();
                    }
                    if ui.button("Add device").clicked() {
                        *show_add_device = true;
                        ui.close_menu();
                    }
                    if ui.button("Exit").clicked() {
                        ui.ctx().send_viewport_cmd(ViewportCommand::Close);
                        ui.close_menu();
                    }
                });
            });
            ui.add_space(4.0);
        });
        eframe::egui::SidePanel::left("steady_left")
            .resizable(false)
            .exact_width(200.0)
            .frame(frame)
            .show_inside(ui, |ui| {
                self.render_left(ui, &all_chats, &mut *selected_chat, &mut *show_add_contact)
            });
        eframe::egui::CentralPanel::default()
            .frame(frame)
            .show_inside(ui, |ui| {
                self.render_right(ui, &*selected_chat);
            });
        ui.add(AddContact {
            app: self.0,
            open: &mut *show_add_contact,
        });
        ui.add(AddDevice {
            app: self.0,
            open: &mut *show_add_device,
        });
        ui.add(Preferences {
            app: self.0,
            open: &mut *show_preferences,
        });
        ui.response()
    }
}

impl<'a> SteadyState<'a> {
    fn render_left(
        &mut self,
        ui: &mut eframe::egui::Ui,
        all_chats: &Result<BTreeMap<Handle, xirtam_client::internal::DmMessage>, String>,
        selected_chat: &mut Option<Handle>,
        show_add_contact: &mut bool,
    ) {
        if ui.add(Button::new("Add contact")).clicked() {
            *show_add_contact = true;
        }
        ui.separator();
        match all_chats {
            Ok(lst) => {
                ui.with_layout(Layout::top_down_justified(Align::Min), |ui| {
                    for (handle, _last_msg) in lst {
                        if ui
                            .selectable_label(
                                *selected_chat == Some(handle.clone()),
                                handle.to_string(),
                            )
                            .clicked()
                        {
                            selected_chat.replace(handle.clone());
                        }
                    }
                });
            }
            Err(err) => {
                self.0.state.error_dialog.replace(err.to_string());
            }
        }
    }

    fn render_right(&mut self, ui: &mut eframe::egui::Ui, selected_chat: &Option<Handle>) {
        if let Some(handle) = selected_chat {
            ui.add(Convo(self.0, handle.clone()));
        }
    }
}
