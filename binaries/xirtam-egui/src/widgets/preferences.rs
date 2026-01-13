use eframe::egui::{Modal, Response, Slider, Widget};

use crate::XirtamApp;

pub struct Preferences<'a> {
    pub app: &'a mut XirtamApp,
    pub open: &'a mut bool,
}

impl Widget for Preferences<'_> {
    fn ui(self, ui: &mut eframe::egui::Ui) -> Response {
        if *self.open {
            let modal = Modal::new("preferences_modal".into()).show(ui.ctx(), |ui| {
                ui.heading("Preferences");
                ui.separator();
                ui.horizontal(|ui| {
                    ui.label("Zoom");
                    ui.add(
                        Slider::new(&mut self.app.state.prefs.zoom_percent, 80..=160)
                            .suffix("%")
                            .clamping(egui::SliderClamping::Always),
                    );
                });
                if ui.button("Close").clicked() {
                    *self.open = false;
                }
            });
            if modal.should_close() {
                *self.open = false;
            }
        }
        ui.response()
    }
}
