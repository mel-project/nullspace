use std::hash::Hash;

use eframe::egui::{Align, Grid, Layout, Ui, WidgetText};

pub(super) const LABEL_WIDTH: f32 = 170.0;
const ROW_GAP_X: f32 = 16.0;
const ROW_GAP_Y: f32 = 10.0;

pub(super) fn show<R>(
    ui: &mut Ui,
    id_source: impl Hash,
    add_rows: impl FnOnce(&mut SettingsForm<'_>) -> R,
) -> R {
    Grid::new(ui.id().with(id_source))
        .num_columns(2)
        .min_col_width(LABEL_WIDTH)
        .spacing([ROW_GAP_X, ROW_GAP_Y])
        .show(ui, |ui| {
            let mut form = SettingsForm { ui };
            add_rows(&mut form)
        })
        .inner
}

pub(super) struct SettingsForm<'a> {
    ui: &'a mut Ui,
}

impl SettingsForm<'_> {
    pub(super) fn row(&mut self, label: impl Into<WidgetText>, add_field: impl FnOnce(&mut Ui)) {
        let row_height = self.ui.spacing().interact_size.y.max(
            self.ui.text_style_height(&eframe::egui::TextStyle::Button)
                + 2.0 * self.ui.spacing().button_padding.y,
        );

        self.ui.with_layout(Layout::left_to_right(Align::Center), |ui| {
            ui.set_min_height(row_height);
            ui.label(label);
        });
        self.ui.with_layout(Layout::left_to_right(Align::Center), |ui| {
            ui.set_min_height(row_height);
            add_field(ui);
        });
        self.ui.end_row();
    }
}
