use egui::Modal;

pub trait Component {
    fn render(&mut self, ctx: &egui::Context, ui: &mut egui::Ui) -> anyhow::Result<()>;
    fn render_or_error(&mut self, ctx: &egui::Context, ui: &mut egui::Ui) {
        if let Err(err) = self.render(ctx, ui) {
            Modal::new("fatal".into()).show(ctx, |ui| {
                ui.heading("Fatal error");
                ui.label(format!("{:?}", err));
            });
        }
    }
}
