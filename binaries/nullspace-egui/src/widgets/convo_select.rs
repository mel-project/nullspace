use eframe::egui::{Response, Widget};
use egui::{Align, Frame, Label, Layout, RichText, Sense};
use nullspace_client::{ConvoId, ConvoSummary};

use crate::{NullspaceApp, fonts::FontVariant, widgets::avatar::Avatar};

pub struct ConvoSelect<'a> {
    pub app: &'a mut NullspaceApp,
    pub selected: bool,
    pub convo: ConvoSummary,
}

impl Widget for ConvoSelect<'_> {
    fn ui(self, ui: &mut eframe::egui::Ui) -> Response {
        let (fill_color, text_color) = if self.selected {
            (ui.visuals().selection.bg_fill, ui.visuals().text_color())
        } else {
            (ui.visuals().window_fill, ui.visuals().text_color())
        };

        let label = match &self.convo.convo_id {
            ConvoId::Direct { peer } => self.app.state.profile_loader.label_for(peer),
            ConvoId::Group { .. } => self.convo.display_title.clone(),
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
                    match &self.convo.convo_id {
                        ConvoId::Direct { peer } => {
                            let user_details = self.app.state.profile_loader.view(peer);
                            ui.add(Avatar::for_user(
                                peer,
                                user_details.and_then(|ud| ud.avatar),
                                28.0,
                            ));
                        }
                        ConvoId::Group { group_id } => {
                            ui.add(Avatar::for_group(*group_id, None, 28.0));
                        }
                    }

                    ui.add_space(4.0);

                    ui.add(
                        Label::new(
                            RichText::new(label)
                                .family(FontVariant::Bold.family())
                                .color(text_color),
                        )
                        .truncate(),
                    );
                    if self.convo.unread_count > 0 {
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            ui.add_space(8.0);
                            let selection = ui.visuals().selection;
                            ui.add(Label::new(
                                RichText::new(format!(" {} ", self.convo.unread_count))
                                    .background_color(selection.bg_fill)
                                    .color(selection.stroke.color),
                            ));
                        });
                    }
                });
            });

        frame_response.response.interact(Sense::click())
    }
}
