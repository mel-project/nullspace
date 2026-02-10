use arboard::Clipboard;
use bytes::Bytes;
use chrono::{DateTime, Local, NaiveDate};
use eframe::egui::{Key, Response, RichText, Widget};
use egui::{Align, Button, Color32, Image, Label, Modal, ProgressBar, ScrollArea, Sense, TextEdit};
use egui_hooks::UseHookExt;
use egui_hooks::hook::state::Var;
use image::codecs::png::PngEncoder;
use image::{ColorType, ImageEncoder};
use nullspace_client::internal::{ConvoId, ConvoMessage};
use nullspace_structs::event::EventPayload;
use nullspace_structs::fragment::Attachment;
use nullspace_structs::group::GroupId;
use nullspace_structs::timestamp::NanoTimestamp;
use pollster::FutureExt;
use smol_str::SmolStr;
use tracing::debug;

use crate::NullspaceApp;
use crate::promises::flatten_rpc;
use crate::rpc::get_rpc;
use crate::screens::group_roster::GroupRoster;
use crate::screens::user_info::UserInfo;
use crate::utils::prefs::ConvoRowStyle;
use crate::utils::speed::speed_fmt;
use crate::widgets::avatar::Avatar;
use crate::widgets::convo_row::ConvoRow;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

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
    pending_scroll_to_bottom: bool,
}

#[derive(Clone, Debug)]
struct PasteImage {
    png_bytes: Vec<u8>,
    width: usize,
    height: usize,
    uri: String,
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
    let mut state: Var<ConvoState> = ui.use_state(ConvoState::default, ()).into_var();
    let mut user_info_target: Option<nullspace_structs::username::UserName> = None;
    let mut show_roster = match convo_id {
        ConvoId::Group { .. } => Some(ui.use_state(|| false, (key.clone(), "roster")).into_var()),
        ConvoId::Direct { .. } => None,
    };

    if !state.initialized {
        let mut fetch = |before, after, limit| convo_history(&convo_id, before, after, limit);
        state.load_initial(&mut fetch);
        state.last_update_count_seen = update_count;
    } else if update_count > state.last_update_count_seen {
        let mut fetch = |before, after, limit| convo_history(&convo_id, before, after, limit);
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
        render_header(app, ui, &convo_id, &mut show_roster, &mut user_info_target);
    });
    ui.scope_builder(egui::UiBuilder::new().max_rect(messages_rect), |ui| {
        render_messages(ui, app, &convo_id, &mut state);
    });
    ui.scope_builder(egui::UiBuilder::new().max_rect(composer_rect), |ui| {
        render_composer(ui, app, &convo_id, &mut state);
    });

    render_roster(ui, app, &convo_id, &mut show_roster, &mut user_info_target);
    ui.add(UserInfo(user_info_target));

    ui.response()
}

fn convo_history(
    convo_id: &ConvoId,
    before: Option<i64>,
    after: Option<i64>,
    limit: u16,
) -> Result<Vec<ConvoMessage>, String> {
    let result = get_rpc()
        .convo_history(convo_id.clone(), before, after, limit)
        .block_on();
    flatten_rpc(result)
}

fn render_header(
    app: &mut NullspaceApp,
    ui: &mut eframe::egui::Ui,
    convo_id: &ConvoId,
    show_roster: &mut Option<Var<bool>>,
    user_info_target: &mut Option<nullspace_structs::username::UserName>,
) {
    match convo_id {
        ConvoId::Direct { peer } => {
            let view = app.state.profile_loader.view(peer);
            let display = app.state.profile_loader.label_for(peer);
            ui.horizontal_centered(|ui| {
                let size = 24.0;
                ui.add(Avatar {
                    sender: peer.clone(),
                    attachment: view.and_then(|details| details.avatar),
                    size,
                });
                ui.heading(display);
                if ui.button("Info").clicked() {
                    *user_info_target = Some(peer.clone());
                }
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
) {
    let style: ConvoRowStyle = app.state.prefs.convo_row_style;
    let scroll_output = ScrollArea::vertical()
        .id_salt("scroll")
        .stick_to_bottom(true)
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            let mut last_date: Option<NaiveDate> = None;
            for item in state.messages.values() {
                if let Some(date) = date_from_timestamp(item.received_at)
                    && last_date != Some(date)
                {
                    let label = format!("[{}]", date.format("%A, %d %b %Y"));
                    ui.label(RichText::new(label).color(Color32::GRAY).size(12.0));
                    ui.add_space(4.0);
                    last_date = Some(date);
                }

                ui.add(ConvoRow {
                    app,
                    message: item,
                    style,
                });
            }

            let anchor_response = ui.allocate_response(egui::vec2(1.0, 1.0), Sense::hover());
            if state.pending_scroll_to_bottom {
                anchor_response.scroll_to_me(Some(Align::BOTTOM));
                state.pending_scroll_to_bottom = false;
            }
        });

    let at_top = scroll_output.state.offset.y <= 2.0;
    if at_top {
        let mut fetch = |before, after, limit| convo_history(convo_id, before, after, limit);
        state.load_older(&mut fetch);
    }
}

fn start_upload(_app: &mut NullspaceApp, attachment: &mut Var<Option<i64>>, path: PathBuf) {
    tracing::debug!(
        path = debug(&path),
        "picked an attachment, starting upload..."
    );
    let mime = infer_mime(&path);
    let Ok(upload_id) = flatten_rpc(get_rpc().attachment_upload(path, mime).block_on()) else {
        return;
    };
    attachment.replace(upload_id);
}

fn render_composer(
    ui: &mut egui::Ui,
    app: &mut NullspaceApp,
    convo_id: &ConvoId,
    state: &mut Var<ConvoState>,
) {
    ui.add_space(8.0);
    let mut attachment: Var<Option<i64>> = ui.use_state(|| None, convo_id.clone()).into_var();
    let key = convo_key(convo_id);
    let mut draft: Var<String> = ui.use_state(String::new, (key.clone(), "draft")).into_var();
    let mut pasted_image: Var<Option<PasteImage>> = ui
        .use_state(|| None, (key.clone(), "paste_image"))
        .into_var();
    let text_id = ui.make_persistent_id((key.clone(), "composer_text"));

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
            let convo_id = convo_id.clone();
            tokio::spawn(async move {
                let _ = flatten_rpc(
                    get_rpc()
                        .convo_send(
                            convo_id,
                            SmolStr::new(Attachment::mime()),
                            Bytes::from(body),
                        )
                        .await,
                );
            });
            *attachment = None;
            state.pending_scroll_to_bottom = true;
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
        ui.horizontal(|ui| {
            if ui.button("\u{ea7f} Attach").clicked() {
                app.file_dialog.pick_file();
            }
            if ui.button("\u{ed7a} Clipboard image").clicked() {
                if pasted_image.is_none() {
                    match read_clipboard_image() {
                        Ok(image) => {
                            *pasted_image = Some(image);
                        }
                        Err(err) => {
                            app.state.error_dialog = Some(err);
                        }
                    }
                }
            }
        });
        app.file_dialog.update(ui.ctx());
        if let Some(path) = app.file_dialog.take_picked() {
            start_upload(app, &mut attachment, path);
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
                    .id(text_id)
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
        send_message(convo_id, body);
        draft.clear();
        state.pending_scroll_to_bottom = true;
    }

    if let Some(paste) = pasted_image.clone() {
        let modal_id = format!("paste_image_modal_{key}");
        Modal::new(modal_id.into()).show(ui.ctx(), |ui| {
            ui.heading("Send pasted image?");
            let size_kb = paste.png_bytes.len() as f32 / 1024.0;
            ui.label(format!(
                "{} x {} ({} KB)",
                paste.width,
                paste.height,
                size_kb.ceil() as u64
            ));
            ui.add(Image::from_bytes(paste.uri.clone(), paste.png_bytes.clone()).max_width(320.0));
            ui.horizontal(|ui| {
                let busy = attachment.is_some();
                if ui.add_enabled(!busy, Button::new("Send")).clicked() {
                    let path = temp_paste_path();
                    if let Err(err) = fs::write(&path, &paste.png_bytes) {
                        app.state.error_dialog =
                            Some(format!("failed to write pasted image: {err}"));
                        return;
                    }
                    start_upload(app, &mut attachment, path);
                    *pasted_image = None;
                }
                if ui.button("Cancel").clicked() {
                    *pasted_image = None;
                }
                if busy {
                    ui.label("Upload in progress");
                }
            });
        });
    }
}

fn send_message(convo_id: &ConvoId, body: Bytes) {
    let convo_id = convo_id.clone();
    tokio::spawn(async move {
        let _ = flatten_rpc(
            get_rpc()
                .convo_send(convo_id, "text/markdown".into(), body)
                .await,
        );
    });
}

fn read_clipboard_image() -> Result<PasteImage, String> {
    let mut clipboard = Clipboard::new().map_err(|err| format!("clipboard error: {err}"))?;
    let image = clipboard
        .get_image()
        .map_err(|err| format!("clipboard has no image ({err})"))?;
    let width = image.width;
    let height = image.height;
    let bytes = image.bytes.into_owned();
    let mut png_bytes = Vec::new();
    let encoder = PngEncoder::new(&mut png_bytes);
    encoder
        .write_image(
            bytes.as_slice(),
            width as u32,
            height as u32,
            ColorType::Rgba8.into(),
        )
        .map_err(|err| format!("failed to encode clipboard image: {err}"))?;
    let uri = format!("bytes://paste-image-{}", unix_nanos());
    Ok(PasteImage {
        png_bytes,
        width,
        height,
        uri,
    })
}

fn temp_paste_path() -> PathBuf {
    let name = format!("nullspace-paste-{}.png", unix_nanos());
    std::env::temp_dir().join(name)
}

fn unix_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

fn render_roster(
    ui: &mut eframe::egui::Ui,
    app: &mut NullspaceApp,
    convo_id: &ConvoId,
    show_roster: &mut Option<Var<bool>>,
    user_info_target: &mut Option<nullspace_structs::username::UserName>,
) {
    let ConvoId::Group { group_id } = convo_id else {
        return;
    };
    if let Some(show_roster) = show_roster.as_mut() {
        ui.add(GroupRoster {
            app,
            open: show_roster,
            group: *group_id,
            user_info: user_info_target,
        });
    }
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
