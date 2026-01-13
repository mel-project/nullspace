use bytes::Bytes;
use chrono::{DateTime, Local, NaiveDate};
use eframe::egui::{CentralPanel, Key, Response, RichText, Widget};
use egui::mutex::Mutex;
use egui::text::LayoutJob;
use egui::{Color32, ScrollArea, TextEdit, TextFormat, TopBottomPanel};
use egui_hooks::UseHookExt;
use egui_hooks::hook::state::Var;
use egui_infinite_scroll::InfiniteScroll;
use pollster::FutureExt;
use smol_str::SmolStr;
use tracing::debug;
use xirtam_client::internal::DmMessage;
use xirtam_structs::handle::Handle;
use xirtam_structs::timestamp::NanoTimestamp;

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::XirtamApp;
use crate::promises::flatten_rpc;
use crate::utils::color::handle_color;
use crate::utils::markdown::layout_md_raw;

pub struct Convo<'a>(pub &'a mut XirtamApp, pub Handle);

impl Widget for Convo<'_> {
    fn ui(self, ui: &mut eframe::egui::Ui) -> Response {
        let rpc = Arc::new(self.0.client.rpc());
        let update_count = self.0.state.update_count;
        let mut draft: Var<String> = ui.use_state(String::new, (self.1.clone(),)).into_var();
        let scroller = ui.use_memo(
            || {
                let peer = self.1.clone();
                let start_rpc = rpc.clone();
                let start_peer = peer.clone();
                let limit: u16 = 100;
                Arc::new(Mutex::new(
                    InfiniteScroll::<DmMessage, u64>::new().start_loader_async(move |cursor| {
                        let rpc = start_rpc.clone();
                        let peer = start_peer.clone();
                        async move {
                            let before = cursor.map(|value| value as i64);
                            let messages = flatten_rpc(
                                rpc.dm_history(peer.clone(), before, None, limit).await,
                            )?;
                            debug!(
                                cursor = ?before,
                                count = messages.len(),
                                "dm start_loader"
                            );
                            if messages.is_empty() {
                                return Ok((Vec::new(), None));
                            }
                            let next_cursor =
                                messages.first().and_then(|msg| msg.id.checked_sub(1));
                            Ok((messages, next_cursor.map(|value| value as u64)))
                        }
                    }),
                ))
            },
            (self.1.clone(),),
        );

        let scroller_for_effect = scroller.clone();
        let rpc_for_effect = rpc.clone();
        let peer_for_effect = self.1.clone();
        ui.use_effect(
            || {
                let last_received_id = {
                    let scroller = scroller_for_effect.lock();
                    scroller
                        .items
                        .iter()
                        .filter(|msg| msg.received_at.is_some())
                        .map(|msg| msg.id)
                        .max()
                };
                let mut after = last_received_id.and_then(|id| id.checked_add(1));
                let mut fetched = Vec::new();
                loop {
                    let result = rpc_for_effect
                        .dm_history(peer_for_effect.clone(), None, after, 200)
                        .block_on();
                    match flatten_rpc(result) {
                        Ok(messages) => {
                            if messages.is_empty() {
                                break;
                            }
                            after = messages.last().and_then(|msg| msg.id.checked_add(1));
                            fetched.extend(messages);
                            if after.is_none() {
                                break;
                            }
                        }
                        Err(err) => {
                            eprintln!("dm history refresh failed: {err}");
                            break;
                        }
                    }
                }
                if fetched.is_empty() {
                    return;
                }
                let mut scroller = scroller_for_effect.lock();
                if scroller.items.is_empty() {
                    return;
                }
                let mut by_id = BTreeMap::new();
                for item in scroller.items.drain(..) {
                    by_id.insert(item.id, item);
                }
                for item in fetched {
                    by_id.insert(item.id, item);
                }
                scroller.items = by_id.into_values().collect();
            },
            (self.1.clone(), update_count),
        );

        let mut scroller = scroller.lock();

        ui.heading(self.1.to_string());
        TopBottomPanel::bottom(ui.next_auto_id())
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
                    }
                });
            });

        CentralPanel::default().show_inside(ui, |ui| {
            let mut stick_to_bottom: Var<bool> =
                ui.use_state(|| true, (self.1.clone(),)).into_var();
            let scroll_output = ScrollArea::vertical()
                .stick_to_bottom(*stick_to_bottom)
                .animated(false)
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    let mut last_date: Option<NaiveDate> = None;
                    scroller.ui(ui, 10, |ui, _index, item| {
                        if let Some(date) = date_from_timestamp(item.received_at) {
                            if last_date != Some(date) {
                                ui.add_space(4.0);
                                let label = format!("[{}]", date.format("%A, %d %b %Y"));
                                ui.label(RichText::new(label).color(Color32::GRAY).size(12.0));
                                ui.add_space(4.0);
                                last_date = Some(date);
                            }
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
                    });
                });
            let max_offset =
                (scroll_output.content_size.y - scroll_output.inner_rect.height()).max(0.0);
            let at_bottom = max_offset - scroll_output.state.offset.y <= 2.0;
            *stick_to_bottom = at_bottom;
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
