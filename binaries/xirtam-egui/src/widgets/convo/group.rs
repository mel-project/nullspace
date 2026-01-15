use bytes::Bytes;
use eframe::egui::Ui;
use egui_hooks::UseHookExt;
use egui_hooks::hook::state::Var;
use pollster::FutureExt;
use smol_str::SmolStr;
use xirtam_client::internal::GroupMessage;
use xirtam_structs::group::GroupId;

use crate::XirtamApp;
use crate::promises::flatten_rpc;
use crate::widgets::group_roster::GroupRoster;

use super::{ConvoKind, ConvoStateKey, render_row, short_group_id};

pub struct GroupConvo {
    pub group: GroupId,
}

impl ConvoKind for GroupConvo {
    type Message = GroupMessage;

    fn state_key(&self) -> ConvoStateKey {
        ConvoStateKey::Group(self.group)
    }

    fn header_ui(&self, ui: &mut Ui, _app: &mut XirtamApp, show_roster: &mut Option<Var<bool>>) {
        ui.horizontal(|ui| {
            ui.heading(format!("Group {}", short_group_id(&self.group)));
            if let Some(show_roster) = show_roster.as_mut() {
                if ui.button("Members").clicked() {
                    **show_roster = true;
                }
            }
        });
    }

    fn roster_var(&self, ui: &mut Ui, key: &ConvoStateKey) -> Option<Var<bool>> {
        Some(ui.use_state(|| false, (key.clone(), "roster")).into_var())
    }

    fn roster_ui(&self, ui: &mut Ui, app: &mut XirtamApp, show_roster: &mut Option<Var<bool>>) {
        if let Some(show_roster) = show_roster.as_mut() {
            ui.add(GroupRoster {
                app,
                open: show_roster,
                group: self.group,
            });
        }
    }

    fn history(
        &self,
        app: &mut XirtamApp,
        before: Option<i64>,
        after: Option<i64>,
        limit: u16,
    ) -> Result<Vec<Self::Message>, String> {
        let rpc = app.client.rpc();
        let result = rpc.group_history(self.group, before, after, limit).block_on();
        flatten_rpc(result)
    }

    fn send(&self, ui: &mut Ui, app: &mut XirtamApp, body: Bytes) {
        let rpc = app.client.rpc();
        let group = self.group;
        tokio::spawn(async move {
            let _ =
                flatten_rpc(rpc.group_send(group, SmolStr::new("text/markdown"), body).await);
        });
        ui.ctx().request_discard("msg sent");
    }

    fn render_item(&self, ui: &mut Ui, item: &Self::Message, _app: &mut XirtamApp) {
        render_row(ui, item, None);
    }
}
