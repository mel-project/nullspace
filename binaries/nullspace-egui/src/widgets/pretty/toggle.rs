use eframe::egui::{
    self, CornerRadius, Response, Rgba, Sense, Stroke, StrokeKind, Ui, Widget, WidgetInfo,
    WidgetType, vec2,
};

use crate::utils::color;

#[must_use = "You should put this widget in a ui with `ui.add(widget);`"]
pub struct PrettyToggle<'a> {
    on: &'a mut bool,
}

impl<'a> PrettyToggle<'a> {
    pub fn new(on: &'a mut bool) -> Self {
        Self { on }
    }
}

impl Widget for PrettyToggle<'_> {
    fn ui(self, ui: &mut Ui) -> Response {
        let Self { on } = self;
        let button_height = ui.spacing().interact_size.y.max(
            ui.text_style_height(&egui::TextStyle::Button) + 2.0 * ui.spacing().button_padding.y,
        );
        let desired_size = vec2((button_height * 1.6).max(44.0), button_height);
        let (rect, mut response) = ui.allocate_exact_size(desired_size, Sense::click());

        if response.clicked() {
            *on = !*on;
            response.mark_changed();
        }

        response
            .widget_info(|| WidgetInfo::selected(WidgetType::Checkbox, ui.is_enabled(), *on, ""));

        if !ui.is_rect_visible(rect) {
            return response;
        }

        let on_t = ui.ctx().animate_bool_responsive(response.id, *on);
        let track_rect = rect.shrink2(vec2(2.0, 2.0));
        let track_radius = track_rect.height() / 2.0;
        let track_corner =
            CornerRadius::same(track_radius.round().clamp(1.0, u8::MAX as f32) as u8);

        let (off_fill, off_stroke, on_fill, on_stroke, thumb_fill, thumb_stroke) =
            if ui.visuals().dark_mode {
                (
                    color::neutral(900),
                    color::neutral(500),
                    color::success(500),
                    color::success(100),
                    color::neutral(100),
                    color::neutral(500),
                )
            } else {
                (
                    color::neutral(100),
                    color::neutral(500),
                    color::success(500),
                    color::success(900),
                    color::neutral(100),
                    color::neutral(500),
                )
            };

        let (off_fill, off_stroke, on_fill, on_stroke, thumb_fill, thumb_stroke) =
            if ui.is_enabled() {
                (
                    off_fill,
                    off_stroke,
                    on_fill,
                    on_stroke,
                    thumb_fill,
                    thumb_stroke,
                )
            } else if ui.visuals().dark_mode {
                (
                    color::neutral(900),
                    color::neutral(500),
                    color::neutral(900),
                    color::neutral(500),
                    color::neutral(500),
                    color::neutral(500),
                )
            } else {
                (
                    color::neutral(100),
                    color::neutral(500),
                    color::neutral(100),
                    color::neutral(500),
                    color::neutral(500),
                    color::neutral(500),
                )
            };

        let track_fill: egui::Color32 =
            egui::lerp(Rgba::from(off_fill)..=Rgba::from(on_fill), on_t).into();
        let track_stroke_color: egui::Color32 =
            egui::lerp(Rgba::from(off_stroke)..=Rgba::from(on_stroke), on_t).into();
        ui.painter()
            .rect_filled(track_rect, track_corner, track_fill);
        ui.painter().rect_stroke(
            track_rect,
            track_corner,
            Stroke::new(1.0, track_stroke_color),
            StrokeKind::Inside,
        );

        let thumb_radius = track_radius - 1.5;
        let thumb_x = egui::lerp(
            (track_rect.left() + track_radius)..=(track_rect.right() - track_radius),
            on_t,
        );
        ui.painter().circle_filled(
            egui::pos2(thumb_x, track_rect.center().y),
            thumb_radius,
            thumb_fill,
        );
        ui.painter().circle_stroke(
            egui::pos2(thumb_x, track_rect.center().y),
            thumb_radius,
            Stroke::new(1.0, thumb_stroke),
        );
        response
    }
}
