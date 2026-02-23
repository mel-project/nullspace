use eframe::egui::{ComboBox, Grid, Response, Widget, Window};

use crate::{
    NullspaceApp,
    utils::prefs::ConvoRowStyle,
};

pub struct Preferences<'a> {
    pub app: &'a mut NullspaceApp,
    pub open: &'a mut bool,
}

impl Widget for Preferences<'_> {
    fn ui(self, ui: &mut eframe::egui::Ui) -> Response {
        const ZOOM_OPTIONS: &[u16] = &[75, 100, 125, 150, 175, 200];

        if *self.open {
            let mut window_open = *self.open;
            let center = ui.ctx().content_rect().center();
            Window::new("Preferences")
                .collapsible(false)
                .default_pos(center)
                .open(&mut window_open)
                .show(ui.ctx(), |ui| {
                    Grid::new("preferences_grid")
                        .num_columns(2)
                        .spacing([16.0, 8.0])
                        .show(ui, |ui| {
                            ui.label("Zoom");
                            ComboBox::from_id_salt("zoom_percent")
                                .selected_text(format!(
                                    "{}%",
                                    self.app.state.prefs.zoom_percent
                                ))
                                .show_ui(ui, |ui| {
                                    for &pct in ZOOM_OPTIONS {
                                        ui.selectable_value(
                                            &mut self.app.state.prefs.zoom_percent,
                                            pct,
                                            format!("{pct}%"),
                                        );
                                    }
                                });
                            ui.end_row();

                            ui.label("Auto-download images");
                            let mut enabled =
                                self.app.state.prefs.max_auto_image_download_bytes.is_some();
                            ui.checkbox(&mut enabled, "");
                            self.app.state.prefs.max_auto_image_download_bytes =
                                enabled.then_some(1_000_000);
                            ui.end_row();

                            ui.label("Message style");
                            ComboBox::from_id_salt("message_style")
                                .selected_text(self.app.state.prefs.convo_row_style.label())
                                .show_ui(ui, |ui| {
                                    ui.selectable_value(
                                        &mut self.app.state.prefs.convo_row_style,
                                        ConvoRowStyle::Text,
                                        ConvoRowStyle::Text.label(),
                                    );
                                    ui.selectable_value(
                                        &mut self.app.state.prefs.convo_row_style,
                                        ConvoRowStyle::Friendly,
                                        ConvoRowStyle::Friendly.label(),
                                    );
                                });
                            ui.end_row();
                        });
                });
            *self.open = window_open;
        }
        ui.response()
    }
}
