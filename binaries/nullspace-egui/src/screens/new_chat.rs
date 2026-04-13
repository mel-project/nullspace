use eframe::egui::{Button, Response, RichText, Widget, Window};
use egui_hooks::UseHookExt;
use egui_hooks::hook::state::Var;
use nullspace_client::ConvoId;
use nullspace_structs::username::UserName;

use crate::NullspaceApp;
use crate::screens::user_info::UserInfo;
use crate::widgets::user_search::{UserSearch, UserSearchSelection, known_dm_peers};

pub struct NewChat<'a> {
    pub app: &'a mut NullspaceApp,
    pub open: &'a mut bool,
    pub selected_chat: &'a mut Option<ConvoId>,
    pub convos: &'a [nullspace_client::ConvoSummary],
}

impl Widget for NewChat<'_> {
    fn ui(self, ui: &mut eframe::egui::Ui) -> Response {
        if !*self.open {
            return ui.response();
        }

        let mut window_open = *self.open;
        let mut close_requested = false;
        Window::new("New chat")
            .collapsible(false)
            .default_width(420.0)
            .vscroll(true)
            .open(&mut window_open)
            .show(ui.ctx(), |ui| {
                let mut selected_user: Var<Option<UserName>> =
                    ui.use_state(|| None::<UserName>, ()).into_var();
                let mut user_info_target: Var<Option<UserName>> =
                    ui.use_state(|| None::<UserName>, ()).into_var();
                let known_users = known_dm_peers(self.convos);

                ui.label(
                    RichText::new(
                        "Search known people, or enter an exact @username to start a conversation.",
                    )
                    .color(ui.visuals().weak_text_color()),
                );
                ui.add_space(8.0);

                ui.add(UserSearch {
                    app: self.app,
                    id_source: "new_chat_search",
                    known_users: &known_users,
                    selection: UserSearchSelection::Single(&mut *selected_user),
                    user_info_target: &mut *user_info_target,
                    disabled_reasons: &Default::default(),
                    placeholder: "Search people or enter exact @username",
                    empty_text: "No local matches. Enter an exact @username to look someone up.",
                });

                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if ui.button("Cancel").clicked() {
                        close_requested = true;
                    }
                    let enabled = selected_user.is_some();
                    if ui.add_enabled(enabled, Button::new("Open chat")).clicked() {
                        if let Some(username) = (*selected_user).clone() {
                            *self.selected_chat = Some(ConvoId::Direct { peer: username });
                            close_requested = true;
                        }
                    }
                });

                ui.add(UserInfo {
                    app: self.app,
                    target: user_info_target.take(),
                });
            });
        if close_requested {
            window_open = false;
        }
        *self.open = window_open;
        ui.response()
    }
}
