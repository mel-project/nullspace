use bytes::Bytes;
use chrono::{DateTime, Local, NaiveDate};
use eframe::egui::{CentralPanel, Key, Response, RichText, Widget};
use egui::text::LayoutJob;
use egui::{Color32, ScrollArea, TextEdit, TextFormat, TopBottomPanel};
use egui_hooks::UseHookExt;
use egui_hooks::hook::state::Var;
use pollster::FutureExt;
use smol_str::SmolStr;
use tracing::debug;
use xirtam_client::internal::{DmMessage, GroupMessage};
use xirtam_structs::group::{GroupId, GroupInviteMsg};
use xirtam_structs::handle::Handle;
use xirtam_structs::msg_content::MessagePayload;
use xirtam_structs::timestamp::NanoTimestamp;

use crate::XirtamApp;
use crate::promises::flatten_rpc;
use crate::utils::color::handle_color;
use crate::utils::markdown::layout_md_raw;
use crate::widgets::group_roster::GroupRoster;
use std::collections::BTreeMap;

const INITIAL_LIMIT: u16 = 100;
const PAGE_LIMIT: u16 = 100;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChatSelection {
    Dm(Handle),
    Group(GroupId),
}

impl ChatSelection {
    fn key(&self) -> String {
        match self {
            ChatSelection::Dm(handle) => format!("dm:{}", handle.as_str()),
            ChatSelection::Group(group) => format!("group:{}", short_group_id(group)),
        }
    }

}

pub struct Convo<'a>(pub &'a mut XirtamApp, pub ChatSelection);

trait ChatRecord {
    fn id(&self) -> i64;
    fn received_at(&self) -> Option<NanoTimestamp>;
    fn sender(&self) -> &Handle;
    fn mime(&self) -> &SmolStr;
    fn body(&self) -> &Bytes;
}

impl ChatRecord for DmMessage {
    fn id(&self) -> i64 {
        self.id
    }

    fn received_at(&self) -> Option<NanoTimestamp> {
        self.received_at
    }

    fn sender(&self) -> &Handle {
        &self.sender
    }

    fn mime(&self) -> &SmolStr {
        &self.mime
    }

    fn body(&self) -> &Bytes {
        &self.body
    }
}

impl ChatRecord for GroupMessage {
    fn id(&self) -> i64 {
        self.id
    }

    fn received_at(&self) -> Option<NanoTimestamp> {
        self.received_at
    }

    fn sender(&self) -> &Handle {
        &self.sender
    }

    fn mime(&self) -> &SmolStr {
        &self.mime
    }

    fn body(&self) -> &Bytes {
        &self.body
    }
}

#[derive(Clone, Debug)]
struct ConvoState<M: ChatRecord> {
    messages: BTreeMap<i64, M>,
    oldest_id: Option<i64>,
    latest_received_id: Option<i64>,
    last_update_count_seen: u64,
    initialized: bool,
    no_more_older: bool,
}

impl<M: ChatRecord> Default for ConvoState<M> {
    fn default() -> Self {
        Self {
            messages: BTreeMap::new(),
            oldest_id: None,
            latest_received_id: None,
            last_update_count_seen: 0,
            initialized: false,
            no_more_older: false,
        }
    }
}

impl<M: ChatRecord> ConvoState<M> {
    fn apply_messages(&mut self, messages: Vec<M>) {
        for msg in messages {
            let msg_id = msg.id();
            if msg.received_at().is_some() {
                self.latest_received_id = Some(
                    self.latest_received_id
                        .map(|id| id.max(msg_id))
                        .unwrap_or(msg_id),
                );
            }
            self.oldest_id = Some(self.oldest_id.map(|id| id.min(msg_id)).unwrap_or(msg_id));
            self.messages.insert(msg_id, msg);
        }
    }

    fn load_initial(
        &mut self,
        mut fetch: impl FnMut(Option<i64>, Option<i64>, u16) -> Result<Vec<M>, String>,
    ) {
        match fetch(None, None, INITIAL_LIMIT) {
            Ok(messages) => {
                debug!(count = messages.len(), "chat initial load");
                self.apply_messages(messages);
                self.initialized = true;
            }
            Err(err) => {
                tracing::warn!("chat initial load failed: {err}");
            }
        }
    }

    fn refresh_newer(
        &mut self,
        mut fetch: impl FnMut(Option<i64>, Option<i64>, u16) -> Result<Vec<M>, String>,
    ) {
        let mut after = self
            .latest_received_id
            .and_then(|id| id.checked_add(1))
            .unwrap_or_default();
        loop {
            match fetch(None, Some(after), PAGE_LIMIT) {
                Ok(messages) => {
                    tracing::debug!(count = messages.len(), "received chat batch");
                    if messages.is_empty() {
                        break;
                    }
                    after = messages.last().map(|msg| msg.id() + 1).unwrap_or_default();
                    self.apply_messages(messages);
                }
                Err(err) => {
                    tracing::warn!("chat history refresh failed: {err}");
                    break;
                }
            }
        }
    }

    fn load_older(
        &mut self,
        mut fetch: impl FnMut(Option<i64>, Option<i64>, u16) -> Result<Vec<M>, String>,
    ) {
        if self.no_more_older {
            return;
        }
        let Some(oldest_id) = self.oldest_id else {
            self.no_more_older = true;
            return;
        };
        let Some(before) = oldest_id.checked_sub(1) else {
            self.no_more_older = true;
            return;
        };
        match fetch(Some(before), None, PAGE_LIMIT) {
            Ok(messages) => {
                if messages.is_empty() {
                    self.no_more_older = true;
                } else {
                    self.apply_messages(messages);
                }
            }
            Err(err) => {
                tracing::warn!("chat older load failed: {err}");
            }
        }
    }
}

impl Widget for Convo<'_> {
    fn ui(mut self, ui: &mut eframe::egui::Ui) -> Response {
        let key = self.1.key();
        let response = ui.push_id(key, |ui| match &self.1 {
            ChatSelection::Dm(peer) => self.render_dm(ui, peer.clone()),
            ChatSelection::Group(group) => self.render_group(ui, *group),
        });
        response.inner
    }
}

impl<'a> Convo<'a> {
    fn render_dm(&mut self, ui: &mut eframe::egui::Ui, peer: Handle) -> Response {
        let rpc = self.0.client.rpc();
        let update_count = self.0.state.update_count;
        let mut draft: Var<String> = ui.use_state(String::new, (peer.clone(), "draft")).into_var();
        let mut state: Var<ConvoState<DmMessage>> = ui
            .use_state(ConvoState::default, (peer.clone(), "state"))
            .into_var();

        let mut fetch = |before, after, limit| {
            let result = rpc.dm_history(peer.clone(), before, after, limit).block_on();
            flatten_rpc(result)
        };

        if !state.initialized {
            state.load_initial(&mut fetch);
            state.last_update_count_seen = update_count;
        } else if update_count > state.last_update_count_seen {
            state.refresh_newer(&mut fetch);
            state.last_update_count_seen = update_count;
        }

        ui.heading(peer.to_string());
        TopBottomPanel::bottom(ui.id().with("bottom"))
            .resizable(false)
            .show_inside(ui, |ui| {
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    let text_response =
                        ui.add(TextEdit::singleline(&mut *draft).desired_width(f32::INFINITY));

                    let enter_pressed = text_response.lost_focus()
                        && text_response
                            .ctx
                            .input(|input| input.key_pressed(Key::Enter));
                    if enter_pressed {
                        text_response.request_focus();
                    }
                    let send_now = enter_pressed;
                    if send_now && !draft.trim().is_empty() {
                        let peer = peer.clone();
                        let body = Bytes::from(draft.clone());
                        let rpc = self.0.client.rpc();
                        tokio::spawn(async move {
                            let _ = flatten_rpc(
                                rpc.dm_send(peer, SmolStr::new("text/markdown"), body)
                                    .await,
                            );
                        });
                        draft.clear();
                        ui.ctx().request_discard("msg sent");
                    }
                });
            });

        CentralPanel::default().show_inside(ui, |ui| {
            let mut stick_to_bottom: Var<bool> =
                ui.use_state(|| true, (peer.clone(), "stick")).into_var();
            let scroll_output = ScrollArea::vertical()
                .id_salt("scroll")
                .stick_to_bottom(*stick_to_bottom)
                .animated(false)
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    let mut last_date: Option<NaiveDate> = None;
                    for item in state.messages.values() {
                        if let Some(date) = date_from_timestamp(item.received_at())
                            && last_date != Some(date)
                        {
                            ui.add_space(4.0);
                            let label = format!("[{}]", date.format("%A, %d %b %Y"));
                            ui.label(RichText::new(label).color(Color32::GRAY).size(12.0));
                            ui.add_space(4.0);
                            last_date = Some(date);
                        }

                        if item.mime().as_str() == GroupInviteMsg::mime() {
                            render_invite_row(ui, item, self.0);
                            continue;
                        }

                        render_message_row(ui, item);
                    }
                });
            let max_offset =
                (scroll_output.content_size.y - scroll_output.inner_rect.height()).max(0.0);
            let at_bottom = max_offset - scroll_output.state.offset.y <= 2.0;
            *stick_to_bottom = at_bottom;
            let at_top = scroll_output.state.offset.y <= 2.0;
            if at_top {
                state.load_older(&mut fetch);
            }
        });

        ui.response()
    }

    fn render_group(&mut self, ui: &mut eframe::egui::Ui, group: GroupId) -> Response {
        let rpc = self.0.client.rpc();
        let update_count = self.0.state.update_count;
        let mut draft: Var<String> = ui.use_state(String::new, (group, "draft")).into_var();
        let mut state: Var<ConvoState<GroupMessage>> = ui
            .use_state(ConvoState::default, (group, "state"))
            .into_var();
        let mut show_roster: Var<bool> = ui.use_state(|| false, (group, "roster")).into_var();

        let mut fetch = |before, after, limit| {
            let result = rpc.group_history(group, before, after, limit).block_on();
            flatten_rpc(result)
        };

        if !state.initialized {
            state.load_initial(&mut fetch);
            state.last_update_count_seen = update_count;
        } else if update_count > state.last_update_count_seen {
            state.refresh_newer(&mut fetch);
            state.last_update_count_seen = update_count;
        }

        ui.horizontal(|ui| {
            ui.heading(format!("Group {}", short_group_id(&group)));
            if ui.button("Members").clicked() {
                *show_roster = true;
            }
        });

        TopBottomPanel::bottom(ui.id().with("bottom"))
            .resizable(false)
            .show_inside(ui, |ui| {
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    let text_response =
                        ui.add(TextEdit::singleline(&mut *draft).desired_width(f32::INFINITY));

                    let enter_pressed = text_response.lost_focus()
                        && text_response
                            .ctx
                            .input(|input| input.key_pressed(Key::Enter));
                    if enter_pressed {
                        text_response.request_focus();
                    }
                    let send_now = enter_pressed;
                    if send_now && !draft.trim().is_empty() {
                        let body = Bytes::from(draft.clone());
                        let rpc = self.0.client.rpc();
                        tokio::spawn(async move {
                            let _ =
                                flatten_rpc(rpc.group_send(group, SmolStr::new("text/markdown"), body).await);
                        });
                        draft.clear();
                        ui.ctx().request_discard("msg sent");
                    }
                });
            });

        CentralPanel::default().show_inside(ui, |ui| {
            let mut stick_to_bottom: Var<bool> =
                ui.use_state(|| true, (group, "stick")).into_var();
            let scroll_output = ScrollArea::vertical()
                .id_salt("scroll")
                .stick_to_bottom(*stick_to_bottom)
                .animated(false)
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    let mut last_date: Option<NaiveDate> = None;
                    for item in state.messages.values() {
                        if let Some(date) = date_from_timestamp(item.received_at())
                            && last_date != Some(date)
                        {
                            ui.add_space(4.0);
                            let label = format!("[{}]", date.format("%A, %d %b %Y"));
                            ui.label(RichText::new(label).color(Color32::GRAY).size(12.0));
                            ui.add_space(4.0);
                            last_date = Some(date);
                        }
                        render_message_row(ui, item);
                    }
                });
            let max_offset =
                (scroll_output.content_size.y - scroll_output.inner_rect.height()).max(0.0);
            let at_bottom = max_offset - scroll_output.state.offset.y <= 2.0;
            *stick_to_bottom = at_bottom;
            let at_top = scroll_output.state.offset.y <= 2.0;
            if at_top {
                state.load_older(&mut fetch);
            }
        });

        ui.add(GroupRoster {
            app: self.0,
            open: &mut show_roster,
            group,
        });

        ui.response()
    }
}

fn render_message_row<M: ChatRecord>(ui: &mut eframe::egui::Ui, item: &M) {
    let mut job = LayoutJob::default();
    let timestamp = format_timestamp(item.received_at());
    job.append(
        &format!("[{timestamp}] "),
        0.0,
        TextFormat {
            color: Color32::GRAY,
            ..Default::default()
        },
    );
    let sender_color = handle_color(item.sender());
    job.append(
        &format!("{}: ", item.sender()),
        0.0,
        TextFormat {
            color: sender_color,
            ..Default::default()
        },
    );
    match item.mime().as_str() {
        "text/plain" => {
            job.append(
                &String::from_utf8_lossy(item.body()),
                0.0,
                TextFormat {
                    color: Color32::BLACK,
                    ..Default::default()
                },
            );
        }
        "text/markdown" => {
            layout_md_raw(
                &mut job,
                TextFormat {
                    color: Color32::BLACK,
                    ..Default::default()
                },
                &String::from_utf8_lossy(item.body()),
            );
        }
        other => {
            job.append(
                &format!("unknown mime {other}"),
                0.0,
                TextFormat {
                    color: Color32::RED,
                    ..Default::default()
                },
            );
        }
    }

    ui.label(job);
}

fn render_invite_row(ui: &mut eframe::egui::Ui, item: &DmMessage, app: &mut XirtamApp) {
    let invite = serde_json::from_slice::<GroupInviteMsg>(item.body()).ok();
    let label = invite
        .as_ref()
        .map(|invite| {
            format!(
                "Group invite ({})",
                short_group_id(&invite.descriptor.id())
            )
        })
        .unwrap_or_else(|| "Group invite".to_string());
    ui.horizontal(|ui| {
        ui.label(RichText::new(format!("[{}]", format_timestamp(item.received_at))).color(Color32::GRAY));
        ui.label(RichText::new(format!("{}:", item.sender)).color(handle_color(&item.sender)));
        ui.label(label);
        if ui.button("Accept").clicked() {
            let rpc = app.client.rpc();
            let dm_id = item.id;
            tokio::spawn(async move {
                let _ = flatten_rpc(rpc.group_accept_invite(dm_id).await);
            });
        }
    });
}

fn format_timestamp(ts: Option<NanoTimestamp>) -> String {
    let Some(ts) = ts else {
        return "--:--".to_string();
    };
    let secs = (ts.0 / 1_000_000_000) as i64;
    let nsec = (ts.0 % 1_000_000_000) as u32;
    let Some(dt) = DateTime::from_timestamp(secs, nsec) else {
        return "--:--".to_string();
    };
    let local = dt.with_timezone(&Local);
    local.format("%H:%M").to_string()
}

fn date_from_timestamp(ts: Option<NanoTimestamp>) -> Option<NaiveDate> {
    let ts = ts?;
    let secs = (ts.0 / 1_000_000_000) as i64;
    let nsec = (ts.0 % 1_000_000_000) as u32;
    let dt = DateTime::from_timestamp(secs, nsec)?;
    Some(dt.with_timezone(&Local).date_naive())
}

fn short_group_id(group: &GroupId) -> String {
    let bytes = group.as_bytes();
    let mut out = String::with_capacity(8);
    for byte in bytes.iter().take(4) {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}
