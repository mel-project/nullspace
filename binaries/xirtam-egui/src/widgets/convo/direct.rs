use bytes::Bytes;
use eframe::egui::Ui;
use egui_hooks::hook::state::Var;
use pollster::FutureExt;
use smol_str::SmolStr;
use xirtam_client::internal::DmMessage;
use xirtam_structs::handle::Handle;

use crate::XirtamApp;
use crate::promises::flatten_rpc;

use super::{ConvoKind, ConvoStateKey, render_row};

pub struct DirectConvo {
    pub peer: Handle,
}

impl ConvoKind for DirectConvo {
    type Message = DmMessage;

    fn state_key(&self) -> ConvoStateKey {
        ConvoStateKey::Dm(self.peer.clone())
    }

    fn header_ui(&self, ui: &mut Ui, _app: &mut XirtamApp, _show_roster: &mut Option<Var<bool>>) {
        ui.heading(self.peer.to_string());
    }

    fn roster_var(&self, _ui: &mut Ui, _key: &ConvoStateKey) -> Option<Var<bool>> {
        None
    }

    fn roster_ui(&self, _ui: &mut Ui, _app: &mut XirtamApp, _show_roster: &mut Option<Var<bool>>) {}

    fn history(
        &self,
        app: &mut XirtamApp,
        before: Option<i64>,
        after: Option<i64>,
        limit: u16,
    ) -> Result<Vec<Self::Message>, String> {
        let rpc = app.client.rpc();
        let result = rpc.dm_history(self.peer.clone(), before, after, limit).block_on();
        flatten_rpc(result)
    }

    fn send(&self, _ui: &mut Ui, app: &mut XirtamApp, body: Bytes) {
        let rpc = app.client.rpc();
        let _ = rpc
            .dm_send(self.peer.clone(), SmolStr::new("text/markdown"), body)
            .block_on();
    }

    fn render_item(&self, ui: &mut Ui, item: &Self::Message, app: &mut XirtamApp) {
        render_row(ui, item, Some(app));
    }
}
