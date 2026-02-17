use eframe::egui::{Response, ViewportCommand, Widget};
use egui::{Align, Button, Layout, Sense, vec2};
use egui_hooks::UseHookExt;
use egui_hooks::hook::state::Var;
use nullspace_client::internal::{ConvoId, ConvoSummary};

use crate::NullspaceApp;
use crate::promises::flatten_rpc;
use crate::rpc::get_rpc;
use crate::screens::add_contact::AddContact;
use crate::screens::add_device::AddDevice;
use crate::screens::add_group::AddGroup;
use crate::screens::preferences::Preferences;
use crate::screens::profile::Profile;
use crate::widgets::avatar::Avatar;
use crate::widgets::convo::Convo;
use crate::widgets::convo_select::ConvoSelect;

pub struct SteadyState<'a>(pub &'a mut NullspaceApp);

#[derive(Clone, Default)]
struct SsState {
    selected_chat: Option<ConvoId>,
    show_add_contact: bool,
    show_add_group: bool,
    show_add_device: bool,
    show_preferences: bool,
    show_profile: bool,
}

impl Widget for SteadyState<'_> {
    fn ui(mut self, ui: &mut eframe::egui::Ui) -> Response {
        let mut state: Var<SsState> = ui.use_state(SsState::default, ()).into_var();
        let convos = ui.use_memo(
            || flatten_rpc(pollster::block_on(get_rpc().convo_list())),
            self.0.state.msg_updates,
        );
        let convos = ui_unwrap!(ui, convos);
        let own_username = ui.use_memo(
            || flatten_rpc(pollster::block_on(get_rpc().own_username())),
            (),
        );
        let own_username = ui_unwrap!(ui, own_username);

        let frame = eframe::egui::Frame::default().inner_margin(eframe::egui::Margin::same(8));
        eframe::egui::TopBottomPanel::top("steady_menu")
            .exact_height(26.0)
            .show_inside(ui, |ui| {
                ui.horizontal_centered(|ui| {
                    ui.menu_button("File", |ui| {
                        if ui.button("Preferences").clicked() {
                            state.show_preferences = true;
                            ui.close();
                        }
                        if ui.button("Add device").clicked() {
                            state.show_add_device = true;
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
                            state.show_profile = true;
                        }
                    });
                });
                ui.add_space(4.0);
            });
        eframe::egui::SidePanel::left("steady_left")
            .resizable(true)
            .min_width(200.0)
            .default_width(200.0)
            .frame(frame)
            .show_inside(ui, |ui| self.render_left(ui, &convos, &mut state));
        eframe::egui::CentralPanel::default()
            .frame(frame)
            .show_inside(ui, |ui| {
                self.render_right(ui, &state);
            });
        ui.add(AddContact {
            app: self.0,
            open: &mut state.show_add_contact,
        });
        ui.add(AddGroup {
            app: self.0,
            open: &mut state.show_add_group,
        });
        ui.add(AddDevice {
            app: self.0,
            open: &mut state.show_add_device,
        });
        ui.add(Preferences {
            app: self.0,
            open: &mut state.show_preferences,
        });
        ui.add(Profile {
            app: self.0,
            open: &mut state.show_profile,
        });
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
            if ui.add(Button::new("Add contact")).clicked() {
                state.show_add_contact = true;
            }
            if ui.add(Button::new("New group")).clicked() {
                state.show_add_group = true;
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
