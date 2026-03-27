use eframe::egui::{Response, Ui, Widget, Window};
use egui_hooks::UseHookExt;
use egui_hooks::hook::state::Var;

use crate::NullspaceApp;

mod add_device;
mod debug;
mod preferences;
mod profile;

#[derive(Clone, Copy, PartialEq, Eq)]
enum SettingsTab {
    Profile,
    AddDevice,
    Preferences,
    Debug,
}

pub struct Settings<'a> {
    pub app: &'a mut NullspaceApp,
    pub open: &'a mut bool,
}

impl Widget for Settings<'_> {
    fn ui(self, ui: &mut Ui) -> Response {
        if *self.open {
            let mut window_open = *self.open;
            let center = ui.ctx().content_rect().center();
            Window::new("Settings")
                .collapsible(false)
                .default_pos(center)
                .max_size([500.0, 500.0])
                .open(&mut window_open)
                .show(ui.ctx(), |ui| {
                    let mut selected_tab: Var<SettingsTab> =
                        ui.use_state(|| SettingsTab::Profile, ()).into_var();

                    ui.horizontal(|ui| {
                        ui.vertical(|ui| {
                            ui.selectable_value(
                                &mut *selected_tab,
                                SettingsTab::Profile,
                                "Profile",
                            );
                            ui.selectable_value(
                                &mut *selected_tab,
                                SettingsTab::AddDevice,
                                "Add device",
                            );
                            ui.selectable_value(
                                &mut *selected_tab,
                                SettingsTab::Preferences,
                                "Preferences",
                            );
                            ui.selectable_value(&mut *selected_tab, SettingsTab::Debug, "Debug");
                        });
                        ui.separator();
                        ui.vertical(|ui| match *selected_tab {
                            SettingsTab::Profile => {
                                ui.push_id("settings_profile", |ui| {
                                    profile::render(ui, self.app);
                                });
                            }
                            SettingsTab::AddDevice => {
                                ui.push_id("settings_add_device", |ui| {
                                    add_device::render(ui);
                                });
                            }
                            SettingsTab::Preferences => {
                                ui.push_id("settings_preferences", |ui| {
                                    preferences::render(ui, self.app);
                                });
                            }
                            SettingsTab::Debug => {
                                ui.push_id("settings_debug", |ui| {
                                    debug::render(ui, self.app);
                                });
                            }
                        });
                    });
                });
            *self.open = window_open;
        }
        ui.response()
    }
}
