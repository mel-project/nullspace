use bytes::Bytes;
use chrono::{DateTime, Local, NaiveDate};
use eframe::egui::{Key, Response, RichText, Widget};
use egui::{Button, Color32, Label, ProgressBar, ScrollArea, TextEdit};
use egui_hooks::UseHookExt;
use egui_hooks::hook::state::Var;
use nullspace_client::internal::{ConvoId, ConvoMessage};
use nullspace_structs::event::EventPayload;
use nullspace_structs::fragment::FragmentRoot;
use nullspace_structs::group::GroupId;
use nullspace_structs::timestamp::NanoTimestamp;
use pollster::FutureExt;
use smol_str::SmolStr;
use tracing::debug;

use crate::NullspaceApp;
use crate::promises::flatten_rpc;
use crate::utils::speed::speed_fmt;
use crate::widgets::content::Content;
use crate::widgets::group_roster::GroupRoster;
use std::collections::BTreeMap;
use std::path::Path;

const INITIAL_LIMIT: u16 = 10;
const PAGE_LIMIT: u16 = 10;

pub struct Convo<'a>(pub &'a mut NullspaceApp, pub ConvoId);

#[derive(Clone, Debug, Default)]
struct ConvoState {
    messages: BTreeMap<i64, ConvoMessage>,
    oldest_id: Option<i64>,
    latest_received_id: Option<i64>,
    last_update_count_seen: u64,
    initialized: bool,
    no_more_older: bool,
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

fn infer_mime(path: &Path) -> SmolStr {
    infer::get_from_path(path)
        .ok()
        .flatten()
        .map(|kind| SmolStr::new(kind.mime_type()))
        .unwrap_or_else(|| SmolStr::new("application/octet-stream"))
}

impl Widget for Convo<'_> {
    fn ui(self, ui: &mut eframe::egui::Ui) -> Response {
        let key = convo_key(&self.1);
        let response = ui.push_id(key, |ui| render_convo(self.0, ui, self.1.clone()));
        response.inner
    }
}

fn render_convo(app: &mut NullspaceApp, ui: &mut eframe::egui::Ui, convo_id: ConvoId) -> Response {
    let update_count = app.state.msg_updates;
    let key = convo_id.clone();
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

    let full_rect = ui.available_rect_before_wrap();
    let header_height = 40.0;
    let composer_height = 100.0;
    let width = full_rect.width();
    let header_rect = egui::Rect::from_min_size(full_rect.min, egui::vec2(width, header_height));
    let messages_height = (full_rect.height() - header_height - composer_height).max(0.0);
    let messages_rect = egui::Rect::from_min_size(
        egui::pos2(full_rect.min.x, full_rect.min.y + header_height),
        egui::vec2(width, messages_height),
    );
    let composer_rect = egui::Rect::from_min_size(
        egui::pos2(full_rect.min.x, full_rect.max.y - composer_height),
        egui::vec2(width, composer_height),
    );

    ui.allocate_rect(full_rect, egui::Sense::hover());
    ui.scope_builder(egui::UiBuilder::new().max_rect(header_rect), |ui| {
        render_header(ui, &convo_id, &mut show_roster);
    });
    ui.scope_builder(egui::UiBuilder::new().max_rect(messages_rect), |ui| {
        render_messages(ui, app, &convo_id, &mut state, &key);
    });
    ui.scope_builder(egui::UiBuilder::new().max_rect(composer_rect), |ui| {
        render_composer(ui, app, &convo_id);
    });

    render_roster(ui, app, &convo_id, &mut show_roster);

    ui.response()
}

fn convo_history(
    app: &mut NullspaceApp,
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

fn render_header(
    ui: &mut eframe::egui::Ui,
    convo_id: &ConvoId,
    show_roster: &mut Option<Var<bool>>,
) {
    match convo_id {
        ConvoId::Direct { peer } => {
            ui.horizontal_centered(|ui| {
                ui.heading(peer.to_string());
                ui.button("Info")
            });
        }
        ConvoId::Group { group_id } => {
            ui.horizontal_centered(|ui| {
                ui.add(Label::new(
                    RichText::from(format!("Group {}", short_group_id(group_id))).heading(),
                ));
                if let Some(show_roster) = show_roster.as_mut()
                    && ui.add(Button::new("Members")).clicked()
                {
                    **show_roster = true;
                }
            });
        }
    }
}

fn render_messages(
    ui: &mut eframe::egui::Ui,
    app: &mut NullspaceApp,
    convo_id: &ConvoId,
    state: &mut Var<ConvoState>,
    key: &ConvoId,
) {
    let mut stick_to_bottom: Var<bool> = ui.use_state(|| true, (key.clone(), "stick")).into_var();
    let scroll_output = ScrollArea::vertical()
        .id_salt("scroll")
        .stick_to_bottom(*stick_to_bottom)
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
    let max_offset = (scroll_output.content_size.y - scroll_output.inner_rect.height()).max(0.0);
    let at_bottom = max_offset - scroll_output.state.offset.y <= 2.0;
    *stick_to_bottom = at_bottom;
    let at_top = scroll_output.state.offset.y <= 2.0;
    if at_top {
        let mut fetch = |before, after, limit| convo_history(app, convo_id, before, after, limit);
        state.load_older(&mut fetch);
    }
}

fn render_composer(ui: &mut egui::Ui, app: &mut NullspaceApp, convo_id: &ConvoId) {
    ui.add_space(8.0);
    let mut attachment: Var<Option<i64>> = ui.use_state(|| None, convo_id.clone()).into_var();
    let key = convo_key(convo_id);
    let mut draft: Var<String> = ui.use_state(String::new, (key.clone(), "draft")).into_var();

    // attachment part
    if let Some(in_progress) = attachment.as_ref() {
        if let Some((uploaded, total)) = app.state.upload_progress.get(in_progress) {
            let speed_key = format!("upload-{in_progress}");
            let (left, speed, right) = speed_fmt(&speed_key, *uploaded, *total);
            let speed_text = format!("{left} @ {speed}, {right} remaining");
            let progress = if *total == 0 {
                0.0
            } else {
                (*uploaded as f32 / *total as f32).clamp(0.0, 1.0)
            };
            ui.add(ProgressBar::new(progress).text(speed_text.to_string()));
        } else if let Some(done) = app.state.upload_done.get(in_progress) {
            let upload_id = *in_progress;
            let root = done.clone();
            let Ok(body) = serde_json::to_vec(&root) else {
                app.state
                    .upload_error
                    .insert(upload_id, "failed to encode attachment".into());
                return;
            };
            let rpc = app.client.rpc();
            let convo_id = convo_id.clone();
            tokio::spawn(async move {
                let _ = flatten_rpc(
                    rpc.convo_send(
                        convo_id,
                        SmolStr::new(FragmentRoot::mime()),
                        Bytes::from(body),
                    )
                    .await,
                );
            });
            *attachment = None;
            app.state.upload_done.remove(&upload_id);
            app.state.upload_progress.remove(&upload_id);
            app.state.upload_error.remove(&upload_id);
        } else if let Some(error) = app.state.upload_error.get(in_progress) {
            ui.label(
                RichText::new(format!("Upload failed: {error}"))
                    .color(Color32::RED)
                    .size(11.0),
            );
            if ui.button("Clear").clicked() {
                let upload_id = *in_progress;
                *attachment = None;
                app.state.upload_done.remove(&upload_id);
                app.state.upload_progress.remove(&upload_id);
                app.state.upload_error.remove(&upload_id);
            }
        } else {
            ui.spinner();
        }
    } else {
        if ui.button("\u{f067} Attach").clicked() {
            app.file_dialog.pick_file();
        }
        app.file_dialog.update(ui.ctx());
        if let Some(path) = app.file_dialog.take_picked() {
            tracing::debug!(
                path = debug(&path),
                "picked an attachment, starting upload..."
            );
            let rpc = app.client.rpc();
            let mime = infer_mime(&path);
            let Ok(upload_id) = flatten_rpc(rpc.attachment_upload(path, mime).block_on()) else {
                return;
            };
            attachment.replace(upload_id);
        }
    }

    ui.take_available_space();

    // the texting part
    let newline_shortcut = egui::KeyboardShortcut::new(egui::Modifiers::SHIFT, egui::Key::Enter);
    let text_response = ScrollArea::vertical()
        .animated(false)
        .show(ui, |ui| {
            ui.add_sized(
                ui.available_size(),
                TextEdit::multiline(&mut *draft)
                    .desired_rows(1)
                    .hint_text("Enter a message...")
                    .desired_width(f32::INFINITY)
                    .return_key(Some(newline_shortcut)),
            )
        })
        .inner;

    let enter_pressed = text_response.has_focus()
        && text_response
            .ctx
            .input(|input| input.key_pressed(Key::Enter) && !input.modifiers.shift);
    // if enter_pressed {
    //     text_response.request_focus();
    // }
    let send_now = enter_pressed;
    if send_now && !draft.trim().is_empty() {
        let body = Bytes::from(draft.clone());
        send_message(ui, app, convo_id, body);
        draft.clear();
    }
}

fn send_message(
    ui: &mut eframe::egui::Ui,
    app: &mut NullspaceApp,
    convo_id: &ConvoId,
    body: Bytes,
) {
    let rpc = app.client.rpc();
    let convo_id = convo_id.clone();
    tokio::spawn(async move {
        let _ = flatten_rpc(rpc.convo_send(convo_id, "text/markdown".into(), body).await);
    });
}

fn render_roster(
    ui: &mut eframe::egui::Ui,
    app: &mut NullspaceApp,
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

fn render_row(ui: &mut eframe::egui::Ui, item: &ConvoMessage, app: &mut NullspaceApp) {
    let timestamp = format_timestamp(item.received_at);
    ui.horizontal_top(|ui| {
        ui.label(RichText::new(format!("[{timestamp}]")).color(Color32::GRAY));
        ui.add(Content { app, message: item });
    });
    ui.add_space(2.0);
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
