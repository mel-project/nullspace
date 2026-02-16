use eframe::egui::{Response, Widget};

pub struct ConvoSelect {
    pub selected: bool,
    pub label: String,
}

impl Widget for ConvoSelect {
    fn ui(self, ui: &mut eframe::egui::Ui) -> Response {
        ui.selectable_label(self.selected, self.label)
    }
}
