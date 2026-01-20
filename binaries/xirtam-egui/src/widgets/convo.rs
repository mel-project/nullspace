use bytes::Bytes;
use chrono::{DateTime, Local, NaiveDate};
use eframe::egui::{CentralPanel, Key, Response, RichText, Widget};
use egui::text::LayoutJob;
use egui::{Color32, ScrollArea, TextEdit, TextFormat, TopBottomPanel};
use egui_hooks::UseHookExt;
use egui_hooks::hook::state::Var;
use pollster::FutureExt;
use tracing::debug;
use xirtam_client::internal::{ConvoId, ConvoMessage};
use xirtam_structs::group::{GroupId, GroupInviteMsg};
use xirtam_structs::event::EventPayload;
use xirtam_structs::timestamp::NanoTimestamp;

use crate::XirtamApp;
use crate::promises::flatten_rpc;
use crate::utils::color::username_color;
use crate::utils::markdown::layout_md_raw;
use crate::widgets::group_roster::GroupRoster;
use std::collections::BTreeMap;

const INITIAL_LIMIT: u16 = 100;
const PAGE_LIMIT: u16 = 100;

pub struct Convo<'a>(pub &'a mut XirtamApp, pub ConvoId);

#[derive(Clone, Debug)]
struct ConvoState {
    messages: BTreeMap<i64, ConvoMessage>,
    oldest_id: Option<i64>,
    latest_received_id: Option<i64>,
    last_update_count_seen: u64,
    initialized: bool,
    no_more_older: bool,
}

impl Default for ConvoState {
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

impl ConvoState {
    fn apply_messages(&mut self, messages: Vec<ConvoMessage>) {
        for msg in messages {
            let msg_id = msg.id;
            if msg.received_at.is_some() {
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
        mut fetch: impl FnMut(Option<i64>, Option<i64>, u16) -> Result<Vec<ConvoMessage>, String>,
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
        mut fetch: impl FnMut(Option<i64>, Option<i64>, u16) -> Result<Vec<ConvoMessage>, String>,
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
                    after = messages.last().map(|msg| msg.id + 1).unwrap_or_default();
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
        mut fetch: impl FnMut(Option<i64>, Option<i64>, u16) -> Result<Vec<ConvoMessage>, String>,
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
    fn ui(self, ui: &mut eframe::egui::Ui) -> Response {
        let key = convo_key(&self.1);
        let response = ui.push_id(key, |ui| render_convo(self.0, ui, self.1.clone()));
        response.inner
    }
}

fn render_convo(
    app: &mut XirtamApp,
    ui: &mut eframe::egui::Ui,
    convo_id: ConvoId,
) -> Response {
    let update_count = app.state.update_count;
    let key = convo_id.clone();
    let mut draft: Var<String> = ui.use_state(String::new, (key.clone(), "draft")).into_var();
    let mut state: Var<ConvoState> = ui
        .use_state(ConvoState::default, (key.clone(), "state"))
        .into_var();
    let mut show_roster = match convo_id {
        ConvoId::Group { .. } => Some(ui.use_state(|| false, (key.clone(), "roster")).into_var()),
        ConvoId::Direct { .. } => None,
    };

    if !state.initialized {
        let mut fetch = |before, after, limit| convo_history(app, &convo_id, before, after, limit);
        state.load_initial(&mut fetch);
        state.last_update_count_seen = update_count;
    } else if update_count > state.last_update_count_seen {
        let mut fetch = |before, after, limit| convo_history(app, &convo_id, before, after, limit);
        state.refresh_newer(&mut fetch);
        state.last_update_count_seen = update_count;
    }

    render_header(ui, &convo_id, &mut show_roster);
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
                    send_message(ui, app, &convo_id, body);
                    draft.clear();
                }
            });
        });

    CentralPanel::default().show_inside(ui, |ui| {
        let mut stick_to_bottom: Var<bool> =
            ui.use_state(|| true, (key.clone(), "stick")).into_var();
        let scroll_output = ScrollArea::vertical()
            .id_salt("scroll")
            .stick_to_bottom(*stick_to_bottom)
            .animated(false)
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                let mut last_date: Option<NaiveDate> = None;
                for item in state.messages.values() {
                    if let Some(date) = date_from_timestamp(item.received_at)
                        && last_date != Some(date)
                    {
                        ui.add_space(4.0);
                        let label = format!("[{}]", date.format("%A, %d %b %Y"));
                        ui.label(RichText::new(label).color(Color32::GRAY).size(12.0));
                        ui.add_space(4.0);
                        last_date = Some(date);
                    }
                    render_row(ui, item, app);
                }
            });
        let max_offset =
            (scroll_output.content_size.y - scroll_output.inner_rect.height()).max(0.0);
        let at_bottom = max_offset - scroll_output.state.offset.y <= 2.0;
        *stick_to_bottom = at_bottom;
        let at_top = scroll_output.state.offset.y <= 2.0;
        if at_top {
            let mut fetch = |before, after, limit| {
                convo_history(app, &convo_id, before, after, limit)
            };
            state.load_older(&mut fetch);
        }
    });

    render_roster(ui, app, &convo_id, &mut show_roster);

    ui.response()
}

fn convo_history(
    app: &mut XirtamApp,
    convo_id: &ConvoId,
    before: Option<i64>,
    after: Option<i64>,
    limit: u16,
) -> Result<Vec<ConvoMessage>, String> {
    let rpc = app.client.rpc();
    let result = rpc
        .convo_history(convo_id.clone(), before, after, limit)
        .block_on();
    flatten_rpc(result)
}

fn send_message(ui: &mut eframe::egui::Ui, app: &mut XirtamApp, convo_id: &ConvoId, body: Bytes) {
    let rpc = app.client.rpc();
    let convo_id = convo_id.clone();
    tokio::spawn(async move {
        let _ = flatten_rpc(rpc.convo_send(convo_id, "text/markdown".into(), body).await);
    });
    ui.ctx().request_discard("msg sent");
}

fn render_header(
    ui: &mut eframe::egui::Ui,
    convo_id: &ConvoId,
    show_roster: &mut Option<Var<bool>>,
) {
    match convo_id {
        ConvoId::Direct { peer } => {
            ui.heading(peer.to_string());
        }
        ConvoId::Group { group_id } => {
            ui.horizontal(|ui| {
                ui.heading(format!("Group {}", short_group_id(group_id)));
                if let Some(show_roster) = show_roster.as_mut() {
                    if ui.button("Members").clicked() {
                        **show_roster = true;
                    }
                }
            });
        }
    }
}

fn render_roster(
    ui: &mut eframe::egui::Ui,
    app: &mut XirtamApp,
    convo_id: &ConvoId,
    show_roster: &mut Option<Var<bool>>,
) {
    let ConvoId::Group { group_id } = convo_id else {
        return;
    };
    if let Some(show_roster) = show_roster.as_mut() {
        ui.add(GroupRoster {
            app,
            open: show_roster,
            group: *group_id,
        });
    }
}

fn render_row(ui: &mut eframe::egui::Ui, item: &ConvoMessage, app: &mut XirtamApp) {
    let mut job = LayoutJob::default();
    let timestamp = format_timestamp(item.received_at);
    job.append(
        &format!("[{timestamp}] "),
        0.0,
        TextFormat {
            color: Color32::GRAY,
            ..Default::default()
        },
    );
    let sender_color = username_color(&item.sender);
    job.append(
        &format!("{}: ", item.sender),
        0.0,
        TextFormat {
            color: sender_color,
            ..Default::default()
        },
    );
    match item.mime.as_str() {
        mime if mime == GroupInviteMsg::mime() => {
            let invite = serde_json::from_slice::<GroupInviteMsg>(&item.body).ok();
            let label = invite
                .as_ref()
                .map(|invite| {
                    format!(
                        "Invitation to group {}",
                        short_group_id(&invite.descriptor.id())
                    )
                })
                .unwrap_or_else(|| "Invitation to group".to_string());
            job.append(
                &label,
                0.0,
                TextFormat {
                    color: Color32::GRAY,
                    ..Default::default()
                },
            );
            ui.horizontal(|ui| {
                ui.label(job);
                if ui.link("Accept").clicked() {
                    let rpc = app.client.rpc();
                    let dm_id = item.id;
                    tokio::spawn(async move {
                        let _ = flatten_rpc(rpc.group_accept_invite(dm_id).await);
                    });
                }
            });
        }
        "text/plain" => {
            job.append(
                &String::from_utf8_lossy(&item.body),
                0.0,
                TextFormat {
                    color: Color32::BLACK,
                    ..Default::default()
                },
            );
            ui.label(job);
        }
        "text/markdown" => {
            layout_md_raw(
                &mut job,
                TextFormat {
                    color: Color32::BLACK,
                    ..Default::default()
                },
                &String::from_utf8_lossy(&item.body),
            );
            ui.label(job);
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
            ui.label(job);
        }
    }
    if let Some(err) = &item.send_error {
        ui.label(
            RichText::new(format!("Send failed: {err}"))
                .color(Color32::RED)
                .size(11.0),
        );
    }
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

fn convo_key(convo_id: &ConvoId) -> String {
    match convo_id {
        ConvoId::Direct { peer } => format!("direct:{}", peer.as_str()),
        ConvoId::Group { group_id } => format!("group:{}", group_id),
    }
}
