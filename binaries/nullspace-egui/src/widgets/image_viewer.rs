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
        Window::new("Image Viewer")
            .collapsible(false)
            .open(&mut open)
            .default_size([600.0, 500.0])
            .show(ui.ctx(), |ui| {
                let available = ui.available_size();
                let max_image = egui::vec2(
                    available.x,
                    (available.y - 32.0).max(100.0),
                );
                ui.add(
                    SmoothImage::new(path.as_path())
                        .fit_to_size(max_image)
                        .corner_radius(egui::CornerRadius::same(4))
                        .preserve_aspect_ratio(true),
                );
                ui.add_space(4.0);
                if ui.button("Open in external viewer").clicked() {
                    let _ = open::that_detached(&path);
                }
            });

        if !open {
            *self.0 = None;
        }

        ui.response()
    }
}
