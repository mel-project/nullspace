use std::path::PathBuf;

use eframe::egui::{Response, Widget, Window};

use crate::widgets::smooth::SmoothImage;

pub struct ImageViewer<'a>(pub &'a mut Option<PathBuf>);

impl Widget for ImageViewer<'_> {
    fn ui(self, ui: &mut eframe::egui::Ui) -> Response {
        let Some(path) = self.0.as_ref().cloned() else {
            return ui.response();
        };

        let mut open = true;
        let center = ui.ctx().content_rect().center();
        Window::new("Image Viewer")
            .collapsible(false)
            .open(&mut open)
            .default_pos(center)
            .default_size([600.0, 500.0])
            .show(ui.ctx(), |ui| {
                // Layout bottom-up so the button claims space at the bottom
                // and the image gets exactly the remainder — no margin
                // guesswork, no feedback loop.
                ui.with_layout(egui::Layout::bottom_up(egui::Align::Center), |ui| {
                    if ui.button("Open in external viewer").clicked() {
                        let _ = open::that_detached(&path);
                    }

                    // Everything above the button is the image area.
                    let image_area = ui.available_size();
                    let (full_rect, _) = ui.allocate_exact_size(image_area, egui::Sense::empty());

                    // Center the image within the fixed area using an
                    // independent child UI so layout doesn't feed back.
                    let mut image_ui =
                        ui.new_child(egui::UiBuilder::new().max_rect(full_rect).layout(
                            egui::Layout::centered_and_justified(egui::Direction::TopDown),
                        ));
                    image_ui.add(
                        SmoothImage::new(path.as_path())
                            .fit_to_size(image_area)
                            .preserve_aspect_ratio(true),
                    );
                });
            });

        if !open {
            *self.0 = None;
        }

        ui.response()
    }
}
