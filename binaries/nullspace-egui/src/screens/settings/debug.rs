use eframe::egui::Ui;

use crate::NullspaceApp;

pub(super) fn render(ui: &mut Ui, app: &mut NullspaceApp) {
    ui.checkbox(&mut app.state.prefs.debug_mode, "Debug mode");
}
