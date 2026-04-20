use eframe::egui::{Button, Response, ScrollArea, Sense, Ui, WidgetText};
use egui_hooks::UseHookExt;
use egui_hooks::hook::state::Var;

pub struct TabbedPane<'a> {
    id_source: &'a str,
    rail_width: f32,
}

impl<'a> TabbedPane<'a> {
    pub fn new(id_source: &'a str) -> Self {
        Self {
            id_source,
            rail_width: 120.0,
        }
    }

    pub fn rail_width(mut self, rail_width: f32) -> Self {
        self.rail_width = rail_width;
        self
    }

    pub fn show(self, ui: &mut Ui, add_tabs: impl FnOnce(&mut TabbedPaneUi<'_>)) -> Response {
        ui.push_id(self.id_source, |ui| {
            let mut selected_tab: Var<usize> = ui.use_state(|| 0usize, ()).into_var();

            let full_rect = ui.available_rect_before_wrap();
            ui.allocate_rect(full_rect, Sense::hover());
            let rail_width = self.rail_width.min(full_rect.width().max(0.0));
            let gap = ui.spacing().item_spacing.x;
            let rail_rect = egui::Rect::from_min_max(
                full_rect.min,
                egui::pos2(full_rect.min.x + rail_width, full_rect.max.y),
            )
            .shrink(8.0);
            let body_rect = egui::Rect::from_min_max(
                egui::pos2(
                    (rail_rect.max.x + gap).min(full_rect.max.x),
                    full_rect.min.y,
                ),
                full_rect.max,
            )
            .shrink(8.0);

            let mut rail_ui =
                ui.new_child(egui::UiBuilder::new().max_rect(rail_rect).id_salt("rail"));
            rail_ui.set_clip_rect(rail_rect);
            rail_ui.set_width(rail_rect.width());
            rail_ui.set_max_width(rail_rect.width());
            rail_ui.set_min_width(rail_rect.width());

            let mut body_host_ui = ui.new_child(
                egui::UiBuilder::new()
                    .max_rect(body_rect)
                    .id_salt("body_host"),
            );
            body_host_ui.set_clip_rect(body_rect);

            ScrollArea::vertical()
                .id_salt("tabbed_pane_body")
                .auto_shrink([false, false])
                .max_width(body_rect.width())
                .max_height(body_rect.height())
                .show(&mut body_host_ui, |body_ui| {
                    body_ui.set_width(body_rect.width());
                    body_ui.set_max_width(body_rect.width());

                    let mut tabs = TabbedPaneUi {
                        rail_ui: &mut rail_ui,
                        body_ui,
                        selected_tab: &mut *selected_tab,
                        tab_count: 0,
                    };
                    add_tabs(&mut tabs);

                    if tabs.tab_count == 0 {
                        *tabs.selected_tab = 0;
                    } else if *tabs.selected_tab >= tabs.tab_count {
                        *tabs.selected_tab = tabs.tab_count - 1;
                    }
                });

            ui.response()
        })
        .inner
    }
}

pub struct TabbedPaneUi<'a> {
    rail_ui: &'a mut Ui,
    body_ui: &'a mut Ui,
    selected_tab: &'a mut usize,
    tab_count: usize,
}

impl TabbedPaneUi<'_> {
    pub fn tab(&mut self, label: impl Into<WidgetText>, body: impl FnOnce(&mut Ui)) {
        let index = self.tab_count;
        self.tab_count += 1;

        let selected = *self.selected_tab == index;
        let rail_width = self.rail_ui.available_width();
        let response = self.rail_ui.add_sized(
            [rail_width, 24.0],
            Button::new(label.into()).selected(selected),
        );
        if response.clicked() {
            *self.selected_tab = index;
        }

        if *self.selected_tab == index {
            self.body_ui.push_id(index, |ui| body(ui));
        }
    }
}
