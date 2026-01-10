use eframe::egui::{Response, Widget};
use egui_hooks::UseHookExt;
use egui_hooks::hook::state::Var;
use xirtam_structs::handle::Handle;

use std::collections::BTreeSet;
use std::sync::Arc;

use crate::XirtamApp;
use crate::promises::{AsyncMemo, flatten_rpc};

pub struct SteadyState<'a>(pub &'a mut XirtamApp);

impl Widget for SteadyState<'_> {
    fn ui(mut self, ui: &mut eframe::egui::Ui) -> Response {
        let rpc = Arc::new(self.0.client.rpc());
        let mut selected_chat: Var<Option<Handle>> = ui.use_state(|| None, ()).into_var();
        let all_chats = ui.use_memo(
            || {
                AsyncMemo::spawn_async_with(rpc.clone(), |rpc| async move {
                    flatten_rpc(rpc.all_peers().await)
                })
            },
            self.0.state.update_count,
        );

        let frame = eframe::egui::Frame::default().inner_margin(eframe::egui::Margin::same(8));
        eframe::egui::TopBottomPanel::top("steady_menu").show_inside(ui, |ui| {
            ui.horizontal(|ui| ui.menu_button("File", |ui| ui.button("Preferences")));
            ui.add_space(4.0);
        });
        eframe::egui::SidePanel::left("steady_left")
            .resizable(false)
            .exact_width(200.0)
            .frame(frame)
            .show_inside(ui, |ui| {
                self.render_left(ui, &all_chats, &mut *selected_chat)
            });
        eframe::egui::CentralPanel::default()
            .frame(frame)
            .show_inside(ui, |ui| {
                self.render_right(ui, &*selected_chat);
            });
        ui.response()
    }
}

impl<'a> SteadyState<'a> {
    fn render_left(
        &mut self,
        ui: &mut eframe::egui::Ui,
        all_chats: &AsyncMemo<Result<BTreeSet<Handle>, String>>,
        selected_chat: &mut Option<Handle>,
    ) {
        // render all the chats
        match all_chats.poll() {
            std::task::Poll::Ready(lst) => match &*lst {
                Ok(lst) => {
                    for handle in lst {
                        if ui.button(handle.to_string()).clicked() {
                            selected_chat.replace(handle.clone());
                        }
                    }
                }
                Err(err) => {
                    self.0.state.error_dialog.replace(err.to_string());
                }
            },
            std::task::Poll::Pending => {
                ui.spinner();
            }
        }
        // render a button
    }

    fn render_right(&mut self, ui: &mut eframe::egui::Ui, selected_chat: &Option<Handle>) {
        if let Some(handle) = selected_chat {
            ui.heading(handle.to_string());
            ui.add(Convo(self.0, handle.clone()));
        }
    }
}

struct Convo<'a>(&'a mut XirtamApp, Handle);

impl Widget for Convo<'_> {
    fn ui(self, ui: &mut eframe::egui::Ui) -> Response {
        ui.response()
    }
}
