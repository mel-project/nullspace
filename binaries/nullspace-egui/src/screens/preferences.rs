use eframe::egui::{Button, ComboBox, Grid, Response, Widget, Window};

use crate::{
    NullspaceApp,
    utils::prefs::{ConvoRowStyle, IMAGE_AUTO_DOWNLOAD_OPTIONS, label_for_auto_image_limit},
};

pub struct Preferences<'a> {
    pub app: &'a mut NullspaceApp,
    pub open: &'a mut bool,
}

impl Widget for Preferences<'_> {
    fn ui(self, ui: &mut eframe::egui::Ui) -> Response {
        const MIN_ZOOM_PERCENT: u16 = 70;
        const MAX_ZOOM_PERCENT: u16 = 200;
        const ZOOM_STEP_PERCENT: u16 = 10;

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
                            ui.horizontal(|ui| {
                                let can_decrease =
                                    self.app.state.prefs.zoom_percent > MIN_ZOOM_PERCENT;
                                if ui.add_enabled(can_decrease, Button::new("-")).clicked() {
                                    self.app.state.prefs.zoom_percent =
                                        self.app.state.prefs.zoom_percent
                                            .saturating_sub(ZOOM_STEP_PERCENT)
                                            .max(MIN_ZOOM_PERCENT);
                                }
                                ui.label(format!("{}%", self.app.state.prefs.zoom_percent));
                                let can_increase =
                                    self.app.state.prefs.zoom_percent < MAX_ZOOM_PERCENT;
                                if ui.add_enabled(can_increase, Button::new("+")).clicked() {
                                    self.app.state.prefs.zoom_percent =
                                        self.app.state.prefs.zoom_percent
                                            .saturating_add(ZOOM_STEP_PERCENT)
                                            .min(MAX_ZOOM_PERCENT);
                                }
                            });
                            ui.end_row();

                            ui.label("Auto-download images");
                            ComboBox::from_id_salt("auto_download_images_max")
                                .selected_text(label_for_auto_image_limit(
                                    self.app.state.prefs.max_auto_image_download_bytes,
                                ))
                                .show_ui(ui, |ui| {
                                    for (bytes, label) in IMAGE_AUTO_DOWNLOAD_OPTIONS {
                                        ui.selectable_value(
                                            &mut self.app.state.prefs.max_auto_image_download_bytes,
                                            *bytes,
                                            *label,
                                        );
                                    }
                                });
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
