use eframe::egui::{Key, Response, RichText, Widget};
use egui::{Button, Color32, Image, Label, Modal, ProgressBar, ScrollArea, TextEdit};
use egui_hooks::UseHookExt;
use egui_hooks::hook::state::Var;
use egui_infinite_scroll::InfiniteScroll;
use nullspace_client::internal::{ConvoId, ConvoMessage, OutgoingMessage};
use nullspace_structs::username::UserName;
use parking_lot::Mutex;
use pollster::block_on;
use smol_str::SmolStr;

use crate::NullspaceApp;
use crate::promises::flatten_rpc;
use crate::rpc::get_rpc;
use crate::screens::group_roster::GroupRoster;
use crate::screens::user_info::UserInfo;
use crate::utils::prefs::ConvoRowStyle;
use crate::utils::speed::speed_fmt;
use crate::widgets::avatar::Avatar;
use crate::widgets::convo_row::ConvoRow;
use cluster::message_render_meta;
use image_clip::{PasteImage, persist_paste_image, read_clipboard_image};
use std::path::{Path, PathBuf};
use std::sync::Arc;

mod cluster;
mod image_clip;

const INITIAL_HISTORY_LIMIT: u16 = 10;
const PAGE_HISTORY_LIMIT: u16 = 10;
const MESSAGE_PREFETCH: usize = 1;

type Scroller = InfiniteScroll<ConvoMessage, i64>;

pub struct Convo<'a>(pub &'a mut NullspaceApp, pub ConvoId);

fn infer_mime(path: &Path) -> SmolStr {
    infer::get_from_path(path)
        .ok()
        .flatten()
        .map(|kind| SmolStr::new(kind.mime_type()))
        .unwrap_or_else(|| SmolStr::new("application/octet-stream"))
}

fn new_scroller(convo_id: ConvoId) -> Scroller {
    InfiniteScroll::<ConvoMessage, i64>::new().start_loader(move |cursor, callback| {
        let limit = if cursor.is_some() {
            PAGE_HISTORY_LIMIT
        } else {
            INITIAL_HISTORY_LIMIT
        };
        let result = flatten_rpc(block_on(get_rpc().convo_history(
            convo_id.clone(),
            cursor,
            None,
            limit,
        )))
        .map(|messages| {
            let next_cursor = messages.first().and_then(|msg| msg.id.checked_sub(1));
            (messages, next_cursor)
        });
        callback(result);
    })
}

fn refresh_newer(convo_id: &ConvoId, scroller: &mut Scroller) {
    let mut after = scroller
        .items
        .iter()
        .rev()
        .find(|message| message.received_at.is_none())
        .map(|message| message.id)
        .or_else(|| {
            scroller
                .items
                .last()
                .and_then(|message| message.id.checked_add(1))
        });

    if after.is_none() {
        return;
    }

    let mut fetched_messages = Vec::new();
    loop {
        let result = flatten_rpc(block_on(get_rpc().convo_history(
            convo_id.clone(),
            None,
            after,
            PAGE_HISTORY_LIMIT,
        )));
        let Ok(messages) = result else {
            return;
        };
        if messages.is_empty() {
            break;
        }
        after = messages
            .last()
            .and_then(|message| message.id.checked_add(1));
        fetched_messages.extend(messages);
        if after.is_none() {
            break;
        }
    }

    if fetched_messages.is_empty() {
        return;
    }

    let mut by_id = std::collections::BTreeMap::new();
    for message in std::mem::take(&mut scroller.items) {
        by_id.insert(message.id, message);
    }

    let mut replaced_existing = false;
    for message in fetched_messages {
        if by_id.insert(message.id, message).is_some() {
            replaced_existing = true;
        }
    }

    scroller.items = by_id.into_values().collect();
    if replaced_existing {
        scroller.reset_virtual_list();
    }
}

impl Widget for Convo<'_> {
    fn ui(self, ui: &mut eframe::egui::Ui) -> Response {
        let app = self.0;
        let convo_id = self.1;
        let response = ui.push_id(&convo_id, |ui| {
            let mut show_roster: Var<bool> = ui.use_state(|| false, ()).into_var();
            let mut user_info_target: Option<UserName> = None;
            let mut last_update_seen: Var<u64> =
                ui.use_state(|| app.state.msg_updates, ()).into_var();

            let convo_id_for_loader = convo_id.clone();
            let scroller = ui.use_state(
                move || Arc::new(Mutex::new(new_scroller(convo_id_for_loader))),
                (),
            );
            let mut scroller = scroller.lock();

            if *last_update_seen != app.state.msg_updates {
                refresh_newer(&convo_id, &mut scroller);
                *last_update_seen = app.state.msg_updates;
            }

            let full_rect = ui.available_rect_before_wrap();
            let header_height = 40.0;
            let composer_height = 100.0;
            let width = full_rect.width();
            let header_rect =
                egui::Rect::from_min_size(full_rect.min, egui::vec2(width, header_height));
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
                render_messages(ui, app, &mut scroller);
            });
            ui.scope_builder(egui::UiBuilder::new().max_rect(composer_rect), |ui| {
                render_composer(ui, app, &convo_id);
            });

            if let ConvoId::Group { group_id } = &convo_id {
                ui.add(GroupRoster {
                    app,
                    open: &mut show_roster,
                    group: *group_id,
                    user_info: &mut user_info_target,
                });
            }
            ui.add(UserInfo(user_info_target));

            ui.response()
        });
        response.inner
    }
}

fn render_header(
    app: &mut NullspaceApp,
    ui: &mut eframe::egui::Ui,
    convo_id: &ConvoId,
    show_roster: &mut bool,
    user_info_target: &mut Option<UserName>,
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
                    RichText::from(format!("Group {}", group_id.short_id())).heading(),
                ));
                if ui.add(Button::new("Members")).clicked() {
                    *show_roster = true;
                }
            });
        }
    }
}

fn render_messages(ui: &mut eframe::egui::Ui, app: &mut NullspaceApp, scroller: &mut Scroller) {
    let style: ConvoRowStyle = app.state.prefs.convo_row_style;
    let message_meta = message_render_meta(&scroller.items);
    let top_loading = scroller.top_loading_state().loading();
    let initial_loading = scroller.initial_loading();
    let top_error = match scroller.top_loading_state() {
        egui_infinite_scroll::LoadingState::Error(err) => Some(err.clone()),
        _ => None,
    };
    let no_more_items = matches!(
        scroller.top_loading_state(),
        egui_infinite_scroll::LoadingState::NoMoreItems
    );
    ScrollArea::vertical()
        .id_salt("scroll")
        .stick_to_bottom(true)
        .show(ui, |ui| {
            if no_more_items {
                if !scroller.items.is_empty() {
                    ui.add_space(8.0);
                    ui.label(
                        RichText::new("Start of conversation")
                            .size(11.0)
                            .color(Color32::GRAY),
                    );
                }
            }
            ui.set_width(ui.available_width());

            scroller.ui(ui, MESSAGE_PREFETCH, |ui, index, item| {
                let meta = message_meta.get(index).copied().unwrap_or_default();
                if let Some(date) = meta.date_label {
                    let label = format!("[{}]", date.format("%A, %d %b %Y"));
                    ui.label(RichText::new(label).color(Color32::GRAY).size(12.0));
                    ui.add_space(4.0);
                }
                ui.push_id(item.id, |ui| {
                    ui.add(ConvoRow {
                        app,
                        message: item,
                        style,
                        is_beginning: meta.is_beginning,
                        is_end: meta.is_end,
                    });
                });
            });

            if top_loading {
                ui.vertical_centered(|ui| {
                    ui.spinner();
                });
            }
            if initial_loading {
                ui.vertical_centered(|ui| {
                    ui.spinner();
                });
            }
            if let Some(err) = top_error.as_ref() {
                ui.horizontal(|ui| {
                    ui.colored_label(Color32::RED, format!("History load failed: {err}"));
                    if ui.button("Retry").clicked() {
                        scroller.retry_top();
                    }
                });
            }
        });
}

fn start_upload(attachment: &mut Var<Option<i64>>, path: PathBuf) {
    tracing::debug!(
        path = debug(&path),
        "picked an attachment, starting upload..."
    );
    let mime = infer_mime(&path);
    let Ok(upload_id) = flatten_rpc(block_on(get_rpc().attachment_upload(path, mime))) else {
        return;
    };
    attachment.replace(upload_id);
}

fn render_composer(ui: &mut egui::Ui, app: &mut NullspaceApp, convo_id: &ConvoId) {
    ui.add_space(8.0);
    let mut attachment: Var<Option<i64>> = ui.use_state(|| None, ()).into_var();

    let mut draft: Var<String> = ui.use_state(String::new, ()).into_var();
    let mut pasted_image: Var<Option<PasteImage>> = ui.use_state(|| None, ()).into_var();

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
            let convo_id = convo_id.clone();
            smol::spawn(async move {
                let _ = flatten_rpc(
                    get_rpc()
                        .convo_send(convo_id, OutgoingMessage::Attachment(root))
                        .await,
                );
            })
            .detach();
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
        ui.horizontal(|ui| {
            if ui.button("\u{ea7f} Attach").clicked() {
                app.file_dialog.pick_file();
            }
            if ui.button("\u{ed7a} Clipboard image").clicked() && pasted_image.is_none() {
                match read_clipboard_image() {
                    Ok(image) => {
                        *pasted_image = Some(image);
                    }
                    Err(err) => {
                        app.state.error_dialog = Some(err);
                    }
                }
            }
        });
        app.file_dialog.update(ui.ctx());
        if let Some(path) = app.file_dialog.take_picked() {
            start_upload(&mut attachment, path);
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
    let send_now = enter_pressed;
    if send_now && !draft.trim().is_empty() {
        let message = draft.clone();
        send_message(convo_id, message);
        draft.clear();
    }

    if let Some(paste) = pasted_image.clone() {
        Modal::new(ui.next_auto_id()).show(ui.ctx(), |ui| {
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
                    let path = match persist_paste_image(&paste) {
                        Ok(path) => path,
                        Err(err) => {
                            app.state.error_dialog = Some(err);
                            return;
                        }
                    };
                    start_upload(&mut attachment, path);
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

fn send_message(convo_id: &ConvoId, message: String) {
    let convo_id = convo_id.clone();
    smol::spawn(async move {
        let _ = flatten_rpc(
            get_rpc()
                .convo_send(convo_id, OutgoingMessage::PlainText(message))
                .await,
        );
    })
    .detach();
}
