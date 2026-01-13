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
use xirtam_client::InternalClient;
use xirtam_client::internal::DmMessage;
use xirtam_structs::handle::Handle;
use xirtam_structs::timestamp::NanoTimestamp;

use crate::XirtamApp;
use crate::promises::flatten_rpc;
use crate::utils::color::handle_color;
use crate::utils::markdown::layout_md_raw;
use std::collections::BTreeMap;

const INITIAL_LIMIT: u16 = 100;
const PAGE_LIMIT: u16 = 100;

pub struct Convo<'a>(pub &'a mut XirtamApp, pub Handle);

#[derive(Clone, Debug, Default)]
struct ConvoState {
    messages: BTreeMap<i64, DmMessage>,
    oldest_id: Option<i64>,
    latest_received_id: Option<i64>,
    last_update_count_seen: u64,
    initialized: bool,
    no_more_older: bool,
}

impl ConvoState {
    fn apply_messages(&mut self, messages: Vec<DmMessage>) {
        for msg in messages {
            if msg.received_at.is_some() {
                self.latest_received_id = Some(
                    self.latest_received_id
                        .map(|id| id.max(msg.id))
                        .unwrap_or(msg.id),
                );
            }
            self.oldest_id = Some(self.oldest_id.map(|id| id.min(msg.id)).unwrap_or(msg.id));
            self.messages.insert(msg.id, msg);
        }
    }

    fn load_initial(&mut self, rpc: &xirtam_client::internal::InternalClient, peer: &Handle) {
        let result = rpc
            .dm_history(peer.clone(), None, None, INITIAL_LIMIT)
            .block_on();
        match flatten_rpc(result) {
            Ok(messages) => {
                debug!(count = messages.len(), "dm initial load");
                self.apply_messages(messages);
                self.initialized = true;
            }
            Err(err) => {
                tracing::warn!("dm initial load failed: {err}");
            }
        }
    }

    fn refresh_newer(&mut self, rpc: &InternalClient, peer: &Handle) {
        let mut after = self
            .latest_received_id
            .and_then(|id| id.checked_add(1))
            .unwrap_or_default();
        loop {
            let result = rpc
                .dm_history(peer.clone(), None, Some(after), PAGE_LIMIT)
                .block_on();
            match flatten_rpc(result) {
                Ok(messages) => {
                    tracing::debug!(messages = debug(&messages), "received a batch of DMs");
                    if messages.is_empty() {
                        break;
                    }
                    after = messages.last().map(|msg| msg.id + 1).unwrap_or_default();
                    self.apply_messages(messages);
                }
                Err(err) => {
                    tracing::warn!("dm history refresh failed: {err}");
                    break;
                }
            }
        }
    }

    fn load_older(&mut self, rpc: &InternalClient, peer: &Handle) {
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
        let result = rpc
            .dm_history(peer.clone(), Some(before), None, PAGE_LIMIT)
            .block_on();
        match flatten_rpc(result) {
            Ok(messages) => {
                if messages.is_empty() {
                    self.no_more_older = true;
                } else {
                    self.apply_messages(messages);
                }
            }
            Err(err) => {
                tracing::warn!("dm older load failed: {err}");
            }
        }
    }
}

impl Widget for Convo<'_> {
    fn ui(self, ui: &mut eframe::egui::Ui) -> Response {
        let rpc = self.0.client.rpc();
        let update_count = self.0.state.update_count;
        let mut draft: Var<String> = ui.use_state(String::new, (self.1.clone(),)).into_var();
        let mut state: Var<ConvoState> = ui
            .use_state(ConvoState::default, (self.1.clone(),))
            .into_var();

        if !state.initialized {
            state.load_initial(&rpc, &self.1);
            state.last_update_count_seen = update_count;
        } else if update_count > state.last_update_count_seen {
            state.refresh_newer(&rpc, &self.1);
            state.last_update_count_seen = update_count;
        }

        ui.heading(self.1.to_string());
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
                        let peer = self.1.clone();
                        let body = Bytes::from(draft.clone());
                        let rpc = self.0.client.rpc();
                        tokio::spawn(async move {
                            let _ = flatten_rpc(
                                rpc.dm_send(peer, SmolStr::new("text/markdown"), body).await,
                            );
                        });
                        draft.clear();
                        ui.ctx().request_discard("msg sent");
                    }
                });
            });

        CentralPanel::default().show_inside(ui, |ui| {
            let mut stick_to_bottom: Var<bool> =
                ui.use_state(|| true, (self.1.clone(),)).into_var();
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
                        let sender_color = handle_color(&item.sender);
                        job.append(
                            &format!("{}: ", item.sender),
                            0.0,
                            TextFormat {
                                color: sender_color,
                                ..Default::default()
                            },
                        );
                        match item.mime.as_str() {
                            "text/plain" => {
                                job.append(
                                    &String::from_utf8_lossy(&item.body),
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
                                    &String::from_utf8_lossy(&item.body),
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
                });
            let max_offset =
                (scroll_output.content_size.y - scroll_output.inner_rect.height()).max(0.0);
            let at_bottom = max_offset - scroll_output.state.offset.y <= 2.0;
            *stick_to_bottom = at_bottom;
            let at_top = scroll_output.state.offset.y <= 2.0;
            if at_top {
                state.load_older(&rpc, &self.1);
            }
        });

        ui.response()
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
