use eframe::egui::{Response, Widget};
use egui::{Align, Color32, Frame, Label, Layout, RichText, Sense};
use nullspace_client::internal::{ConvoId, ConvoSummary};

use crate::{NullspaceApp, widgets::avatar::Avatar};

pub struct ConvoSelect<'a> {
    pub app: &'a mut NullspaceApp,
    pub selected: bool,
    pub convo: ConvoSummary,
}

impl Widget for ConvoSelect<'_> {
    fn ui(self, ui: &mut eframe::egui::Ui) -> Response {
        let (fill_color, text_color) = if self.selected {
            (ui.visuals().code_bg_color, ui.visuals().text_color())
        } else {
            (ui.visuals().window_fill, ui.visuals().text_color())
        };

        let label = match &self.convo.convo_id {
            ConvoId::Direct { peer } => self.app.state.profile_loader.label_for(peer),
            ConvoId::Group { group_id } => {
                format!("Group {}", group_id.short_id())
            }
        };

        let frame_response = Frame::new()
            .corner_radius(8.0)
            .inner_margin(8.0)
            .fill(fill_color)
            .show(ui, |ui| {
                ui.set_min_height(34.0);
                ui.set_max_height(34.0);
                ui.set_width(ui.available_width());
                ui.with_layout(Layout::left_to_right(Align::Center), |ui| {
                    if let ConvoId::Direct { peer } = &self.convo.convo_id {
                        let user_details = self.app.state.profile_loader.view(peer);
                        ui.add(Avatar {
                            sender: peer.clone(),
                            attachment: user_details.and_then(|ud| ud.avatar),
                            size: 28.0,
                        });
                    } else {
                        ui.add_space(28.0 + ui.ctx().style().spacing.item_spacing.x);
                    }

                    ui.add_space(4.0);

                    ui.add(Label::new(
                        RichText::new(label)
                            .family(egui::FontFamily::Name("main_bold".into()))
                            .color(text_color),
                    ));
                    if self.convo.unread_count > 0 {
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            ui.add_space(8.0);
                            ui.add(Label::new(
                                RichText::new(format!(" {} ", self.convo.unread_count))
                                    .background_color(Color32::LIGHT_BLUE),
                            ));
                        });
                    }
                });
            });

        frame_response.response.interact(Sense::click())
    }
}
