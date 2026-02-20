use chrono::NaiveDate;
use eframe::egui::{Key, Response, RichText, Widget};
use egui::style::ScrollAnimation;
use egui::{Align, Button, Color32, Image, Label, Modal, ProgressBar, ScrollArea, Sense, TextEdit};
use egui_hooks::UseHookExt;
use egui_hooks::hook::state::Var;
use nullspace_client::internal::{ConvoId, OutgoingMessage};
use nullspace_structs::timestamp::NanoTimestamp;
use pollster::FutureExt;
use smol_str::SmolStr;

use crate::promises::flatten_rpc;
use crate::rpc::get_rpc;
use crate::screens::group_roster::GroupRoster;
use crate::screens::user_info::UserInfo;
use crate::utils::prefs::ConvoRowStyle;
use crate::utils::speed::speed_fmt;
use crate::widgets::avatar::Avatar;
use crate::widgets::convo_row::ConvoRow;
use crate::{NullspaceApp, widgets::convo::cluster::cluster_convo};
use convo_state::ConvoState;
use image_clip::{PasteImage, persist_paste_image, read_clipboard_image};
use std::path::{Path, PathBuf};

mod cluster;
mod convo_state;
mod image_clip;

pub struct Convo<'a>(pub &'a mut NullspaceApp, pub ConvoId);

fn infer_mime(path: &Path) -> SmolStr {
    infer::get_from_path(path)
        .ok()
        .flatten()
        .map(|kind| SmolStr::new(kind.mime_type()))
        .unwrap_or_else(|| SmolStr::new("application/octet-stream"))
}

impl Widget for Convo<'_> {
    fn ui(self, ui: &mut eframe::egui::Ui) -> Response {
        let app = self.0;
        let convo_id = self.1;
        let response = ui.push_id(&convo_id, |ui| {
            let update_count = app.state.msg_updates;
            let key = convo_id.clone();
            let mut state: Var<ConvoState> = ui
                .use_state(
                    || ConvoState {
                        pending_scroll_to_bottom: true,
                        ..ConvoState::default()
                    },
                    (),
                )
                .into_var();
            let mut user_info_target: Option<nullspace_structs::username::UserName> = None;
            let mut show_roster = match convo_id {
                ConvoId::Group { .. } => {
                    Some(ui.use_state(|| false, (key.clone(), "roster")).into_var())
                }
                ConvoId::Direct { .. } => None,
            };
            let mut fetch = |before, after, limit| {
                let result = get_rpc()
                    .convo_history(convo_id.clone(), before, after, limit)
                    .block_on();
                flatten_rpc(result)
            };

            if !state.initialized {
                state.load_initial(&mut fetch);
                state.last_update_count_seen = update_count;
            } else if update_count > state.last_update_count_seen {
                state.refresh_newer(&mut fetch);
                state.last_update_count_seen = update_count;
            }

            let convo_for_read = convo_id.clone();
            let up_to_read = state.latest_received_id;
            let frame_count = ui.use_state(|| 0, (convo_id.clone(), up_to_read));
            let window_focused = ui.ctx().input(|i| i.viewport().focused).unwrap_or(true);
            let should_mark_read = *frame_count > 30 && window_focused;
            frame_count.set_next(*frame_count + 1);
            if *frame_count <= 30 {
                ui.ctx().request_repaint();
            }
            ui.use_effect(
                move || {
                    let Some(up_to_id) = up_to_read else {
                        return;
                    };
                    if should_mark_read {
                        let _ = flatten_rpc(
                            get_rpc()
                                .convo_mark_read(convo_for_read, up_to_id)
                                .block_on(),
                        );
                    }
                },
                (convo_id.clone(), up_to_read, should_mark_read),
            );

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
                render_messages(ui, app, &convo_id, &mut state);
            });
            ui.scope_builder(egui::UiBuilder::new().max_rect(composer_rect), |ui| {
                render_composer(ui, app, &convo_id, &mut state);
            });

            if let ConvoId::Group { group_id } = &convo_id
                && let Some(show_roster) = show_roster.as_mut()
            {
                ui.add(GroupRoster {
                    app,
                    open: show_roster,
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
                    RichText::from(format!("Group {}", group_id.short_id())).heading(),
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
    let clustered = ui.use_memo(
        || {
            let msg = state.messages.values().cloned().collect::<Vec<_>>();
            cluster_convo(&msg)
        },
        (
            state.messages.len(),
            state.messages.last_key_value().map(|s| s.1.received_at),
        ),
    );

    let style: ConvoRowStyle = app.state.prefs.convo_row_style;
    ScrollArea::vertical()
        .id_salt("scroll")
        .stick_to_bottom(true)
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            if ui.link("Load more...").clicked() {
                let convo_id = convo_id.clone();
                let mut fetch = move |before, after, limit| {
                    let result = get_rpc()
                        .convo_history(convo_id.clone(), before, after, limit)
                        .block_on();
                    flatten_rpc(result)
                };
                state.load_older(&mut fetch);
            }
            let mut last_date: Option<NaiveDate> = None;
            for cluster in clustered {
                let first = cluster.first().unwrap();
                let last = cluster.last().unwrap();
                if let Some(date) = first.received_at.and_then(NanoTimestamp::naive_date)
                    && last_date != Some(date)
                {
                    let label = format!("[{}]", date.format("%A, %d %b %Y"));
                    ui.label(RichText::new(label).color(Color32::GRAY).size(12.0));
                    ui.add_space(4.0);
                    last_date = Some(date);
                }
                for item in cluster.iter() {
                    ui.push_id(item.id, |ui| {
                        ui.add(ConvoRow {
                            app,
                            message: item,
                            style,
                            is_beginning: std::ptr::eq(item, first),
                            is_end: std::ptr::eq(item, last),
                        })
                    });
                }
            }

            let anchor_response = ui.allocate_response(egui::vec2(1.0, 1.0), Sense::hover());
            if state.pending_scroll_to_bottom {
                anchor_response
                    .scroll_to_me_animation(Some(Align::BOTTOM), ScrollAnimation::none());
                state.pending_scroll_to_bottom = false;
            }
        });
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
            tokio::spawn(async move {
                let _ = flatten_rpc(
                    get_rpc()
                        .convo_send(convo_id, OutgoingMessage::Attachment(root))
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
        let message = draft.clone();
        send_message(convo_id, message);
        draft.clear();
        state.pending_scroll_to_bottom = true;
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

fn send_message(convo_id: &ConvoId, message: String) {
    let convo_id = convo_id.clone();
    tokio::spawn(async move {
        let _ = flatten_rpc(
            get_rpc()
                .convo_send(convo_id, OutgoingMessage::PlainText(message))
                .await,
        );
    });
}
