use eframe::egui::{Response, Ui, Widget, Window};

use crate::NullspaceApp;
use crate::widgets::tabbed_pane::TabbedPane;

mod add_device;
mod debug;
mod form;
mod preferences;
mod profile;

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
                .resizable(false)
                .open(&mut window_open)
                .show(ui.ctx(), |ui| {
                    TabbedPane::new("settings_tabs")
                        .rail_width(130.0)
                        .show(ui, |tabs| {
                            tabs.tab("Profile", |ui| profile::render(ui, self.app));
                            tabs.tab("Add device", |ui| add_device::render(ui, self.app));
                            tabs.tab("Preferences", |ui| preferences::render(ui, self.app));
                            tabs.tab("Debug", |ui| debug::render(ui, self.app));
                        });
                });
            *self.open = window_open;
        }
        ui.response()
    }
}
