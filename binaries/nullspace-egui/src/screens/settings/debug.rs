use eframe::egui::Ui;

use crate::{NullspaceApp, screens::settings::form, widgets::pretty::PrettyToggle};

pub(super) fn render(ui: &mut Ui, app: &mut NullspaceApp) {
    form::show(ui, "debug_form", |form| {
        form.row("Debug mode", |ui| {
            ui.add(PrettyToggle::new(&mut app.state.prefs.debug_mode));
        });
    });
}
