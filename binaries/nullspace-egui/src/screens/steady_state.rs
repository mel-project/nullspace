use eframe::egui::{Response, ViewportCommand, Widget};
use egui::{Align, Button, Layout, Sense, vec2};
use egui_hooks::UseHookExt;
use egui_hooks::hook::state::Var;
use nullspace_client::{ConvoId, ConvoSummary};

use crate::NullspaceApp;
use crate::rpc::flatten_rpc;
use crate::rpc::get_rpc;
use crate::screens::new_chat::NewChat;
use crate::screens::new_group::NewGroup;
use crate::screens::settings::Settings;
use crate::widgets::avatar::Avatar;
use crate::widgets::convo::Convo;
use crate::widgets::convo_select::ConvoSelect;

pub struct SteadyState<'a>(pub &'a mut NullspaceApp);

#[derive(Clone, Default)]
struct SsState {
    selected_chat: Option<ConvoId>,
    show_new_chat: bool,
    show_new_group: bool,
    show_settings: bool,
}

impl Widget for SteadyState<'_> {
    fn ui(mut self, ui: &mut eframe::egui::Ui) -> Response {
        let mut state: Var<SsState> = ui.use_state(SsState::default, ()).into_var();
        let convos = ui.use_memo(
            || flatten_rpc(pollster::block_on(get_rpc().convo_list())),
            self.0.state.msg_updates,
        );
        let convos = ui_unwrap!(ui, convos);
        let Some(own_username) = self.0.state.own_username.clone() else {
            return ui.response();
        };

        let frame = eframe::egui::Frame::default()
            .inner_margin(eframe::egui::Margin::same(8))
            .outer_margin(0.0);
        eframe::egui::Panel::top("steady_menu")
            .exact_size(30.0)
            .show_inside(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.menu_button("File", |ui| {
                        if ui.button("Settings").clicked() {
                            state.show_settings = true;
                            ui.close();
                        }
                        if ui.button("Exit").clicked() {
                            ui.ctx().send_viewport_cmd(ViewportCommand::Close);
                            ui.close();
                        }
                    });
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        let size = 20.0;

                        let profile_view = self.0.state.profile_loader.view(&own_username);
                        let display = self.0.state.profile_loader.label_for(&own_username);
                        if ui.button(display).clicked()
                            | ui.add_sized(
                                vec2(size, size),
                                Avatar {
                                    sender: own_username.clone(),
                                    attachment: profile_view.and_then(|details| details.avatar),
                                    size,
                                },
                            )
                            .clicked()
                        {
                            state.show_settings = true;
                        }
                    });
                });
                ui.add_space(4.0);
            });
        eframe::egui::Panel::left("steady_left")
            .resizable(true)
            .min_size(200.0)
            .default_size(200.0)
            .frame(frame)
            .show_inside(ui, |ui| self.render_left(ui, &convos, &mut state));
        eframe::egui::CentralPanel::default().show_inside(ui, |ui| {
            self.render_right(ui, &state);
        });
        {
            let state = &mut *state;
            ui.add(NewChat {
                app: self.0,
                open: &mut state.show_new_chat,
                selected_chat: &mut state.selected_chat,
                convos: &convos,
            });
        }
        {
            let state = &mut *state;
            ui.add(NewGroup {
                app: self.0,
                open: &mut state.show_new_group,
                selected_chat: &mut state.selected_chat,
                convos: &convos,
            });
        }
        {
            let state = &mut *state;
            ui.add(Settings {
                app: self.0,
                open: &mut state.show_settings,
            });
        }
        ui.response()
    }
}

impl<'a> SteadyState<'a> {
    fn render_left(
        &mut self,
        ui: &mut eframe::egui::Ui,
        convos: &[ConvoSummary],
        state: &mut SsState,
    ) {
        ui.horizontal(|ui| {
            if ui.add(Button::new("New chat")).clicked() {
                state.show_new_chat = true;
            }
            if ui.add(Button::new("New group")).clicked() {
                state.show_new_group = true;
            }
        });
        ui.separator();

        ui.with_layout(Layout::top_down_justified(Align::Min), |ui| {
            for convo in convos {
                let selection = convo.convo_id.clone();

                if ui
                    .add(ConvoSelect {
                        selected: state.selected_chat == Some(selection.clone()),
                        convo: convo.clone(),
                        app: self.0,
                    })
                    .interact(Sense::all())
                    .clicked()
                {
                    state.selected_chat.replace(selection);
                }
            }
        });
    }

    fn render_right(&mut self, ui: &mut eframe::egui::Ui, state: &SsState) {
        if let Some(selection) = &state.selected_chat {
            ui.add(Convo(self.0, selection.clone()));
        }
    }
}
