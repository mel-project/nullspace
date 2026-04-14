use eframe::egui::{ComboBox, Ui};

use crate::{
    NullspaceApp,
    screens::settings::form,
    utils::prefs::{AppTheme, ConvoRowStyle},
    widgets::pretty::PrettyToggle,
};

pub(super) fn render(ui: &mut Ui, app: &mut NullspaceApp) {
    const ZOOM_OPTIONS: &[u16] = &[75, 100, 125, 150, 175, 200];

    form::show(ui, "preferences_grid", |form| {
        form.row("Theme", |ui| {
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
        });

        form.row("Zoom", |ui| {
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
        });

        form.row("Auto-download images", |ui| {
            let mut enabled = app.state.prefs.max_auto_image_download_bytes.is_some();
            ui.add(PrettyToggle::new(&mut enabled));
            app.state.prefs.max_auto_image_download_bytes = enabled.then_some(1_000_000);
        });

        form.row("Message style", |ui| {
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
        });
    });
}
