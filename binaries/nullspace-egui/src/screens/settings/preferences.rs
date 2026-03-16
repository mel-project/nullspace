use eframe::egui::{ComboBox, Grid, Ui};

use crate::{
    NullspaceApp,
    utils::prefs::{AppTheme, ConvoRowStyle},
};

pub(super) fn render(ui: &mut Ui, app: &mut NullspaceApp) {
    const ZOOM_OPTIONS: &[u16] = &[75, 100, 125, 150, 175, 200];

    Grid::new("preferences_grid")
        .num_columns(2)
        .spacing([16.0, 8.0])
        .show(ui, |ui| {
            ui.label("Theme");
            ComboBox::from_id_salt("theme_preference")
                .selected_text(app.state.prefs.theme.label())
                .show_ui(ui, |ui| {
                    ui.selectable_value(
                        &mut app.state.prefs.theme,
                        AppTheme::Auto,
                        AppTheme::Auto.label(),
                    );
                    ui.selectable_value(
                        &mut app.state.prefs.theme,
                        AppTheme::Light,
                        AppTheme::Light.label(),
                    );
                    ui.selectable_value(
                        &mut app.state.prefs.theme,
                        AppTheme::Dark,
                        AppTheme::Dark.label(),
                    );
                });
            ui.end_row();

            ui.label("Zoom");
            ComboBox::from_id_salt("zoom_percent")
                .selected_text(format!("{}%", app.state.prefs.zoom_percent))
                .show_ui(ui, |ui| {
                    for &pct in ZOOM_OPTIONS {
                        ui.selectable_value(
                            &mut app.state.prefs.zoom_percent,
                            pct,
                            format!("{pct}%"),
                        );
                    }
                });
            ui.end_row();

            ui.label("Auto-download images");
            let mut enabled = app.state.prefs.max_auto_image_download_bytes.is_some();
            ui.checkbox(&mut enabled, "");
            app.state.prefs.max_auto_image_download_bytes = enabled.then_some(1_000_000);
            ui.end_row();

            ui.label("Message style");
            ComboBox::from_id_salt("message_style")
                .selected_text(app.state.prefs.convo_row_style.label())
                .show_ui(ui, |ui| {
                    ui.selectable_value(
                        &mut app.state.prefs.convo_row_style,
                        ConvoRowStyle::Text,
                        ConvoRowStyle::Text.label(),
                    );
                    ui.selectable_value(
                        &mut app.state.prefs.convo_row_style,
                        ConvoRowStyle::Friendly,
                        ConvoRowStyle::Friendly.label(),
                    );
                });
            ui.end_row();
        });
}
