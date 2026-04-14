use eframe::egui::{Key, Response, RichText, Widget};
use egui::{Button, Image, Label, Modal, ProgressBar, ScrollArea, TextEdit};
use egui_hooks::UseHookExt;
use egui_hooks::hook::state::{State, Var};
use egui_infinite_scroll::InfiniteScroll;
use nullspace_client::{ConvoId, ConvoItem, GroupView, UploadedRoot};
use nullspace_structs::event::{MessagePayload, MessageText};
use nullspace_structs::username::UserName;
use pollster::block_on;
use smol_str::SmolStr;
use uuid::Uuid;

use crate::NullspaceApp;
use crate::fonts::FontVariant;
use crate::rpc::flatten_rpc;
use crate::rpc::get_rpc;
use crate::screens::group_window::GroupWindow;
use crate::screens::user_info::UserInfo;
use crate::utils::generational::GBox;
use crate::utils::hooks::CustomHooksExt;
use crate::utils::prefs::ConvoRowStyle;
use crate::utils::speed::speed_fmt;
use crate::widgets::avatar::Avatar;
use crate::widgets::convo_row::ConvoRow;
use cluster::message_render_meta;
use image_clip::{PasteImage, persist_paste_image, read_clipboard_image};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};

mod cluster;
mod image_clip;

const INITIAL_HISTORY_LIMIT: u16 = 50;
const PAGE_HISTORY_LIMIT: u16 = 10;
const MESSAGE_PREFETCH: usize = 10;

type Scroller = InfiniteScroll<ConvoItem, i64>;

pub struct Convo<'a>(pub &'a mut NullspaceApp, pub ConvoId);

impl Widget for Convo<'_> {
    fn ui(self, ui: &mut eframe::egui::Ui) -> Response {
        let app = self.0;
        let convo_id = self.1;
        let key = convo_id.clone();
        let convo_id = ui.use_gbox(|| convo_id, key.clone());
        let scroller = ui.use_gbox(move || new_scroller(convo_id.get()), key.clone());
        let read_up_to = scroller.read().items.last().map(|m| m.id);
        ui.use_async_memo(
            async move {
                smol::Timer::after(Duration::from_secs(1)).await;
                if let Some(val) = read_up_to {
                    let _ = get_rpc().convo_mark_read(convo_id.get(), val).await;
                }
            },
            read_up_to,
        );

        let response = ui.push_id(&*convo_id.read(), |ui| {
            let mut show_group_window: Var<bool> = ui.use_state(|| false, ()).into_var();
            let mut user_info_target: Option<UserName> = None;
            let mut last_update_seen: Var<u64> =
                ui.use_state(|| app.state.msg_updates, ()).into_var();
            let mut scroller = scroller.write();
            scroller.virtual_list.hide_on_resize(None);
            // scroller.virtual_list.over_scan(0.0);
            if *last_update_seen != app.state.msg_updates {
                refresh_newer(convo_id.get(), &mut scroller);
                *last_update_seen = app.state.msg_updates;
            }

            let group_view = match convo_id.get() {
                ConvoId::Group { group_id } => Some(ui.use_memo(
                    || flatten_rpc(block_on(get_rpc().group_view(group_id))),
                    (group_id, app.state.msg_updates),
                )),
                ConvoId::Direct { .. } => None,
            };
            let group_access = group_view
                .as_ref()
                .and_then(|view| view.as_ref().ok())
                .map(|view| group_access_state(&app.state.own_username, view));

            let full_rect = ui.available_rect_before_wrap();
            if matches!(group_access, Some(GroupAccessState::Banned)) {
                ui.allocate_rect(full_rect, egui::Sense::hover());
                ui.scope_builder(egui::UiBuilder::new().max_rect(full_rect), |ui| {
                    ui.centered_and_justified(|ui| {
                        ui.label(
                            RichText::new("You are banned")
                                .heading()
                                .color(ui.visuals().error_fg_color),
                        );
                    });
                });

                if let ConvoId::Group { group_id } = convo_id.get() {
                    ui.add(GroupWindow {
                        app,
                        open: &mut show_group_window,
                        group: group_id,
                        user_info: &mut user_info_target,
                    });
                }
                ui.add(UserInfo {
                    app,
                    target: user_info_target,
                });
                return ui.response();
            }

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
                render_header(
                    app,
                    ui,
                    convo_id.get(),
                    group_view.as_ref().and_then(|view| view.as_ref().ok()),
                    &mut show_group_window,
                    &mut user_info_target,
                );
            });
            ui.scope_builder(egui::UiBuilder::new().max_rect(messages_rect), |ui| {
                render_messages(ui, app, &mut scroller);
            });
            ui.scope_builder(egui::UiBuilder::new().max_rect(composer_rect), |ui| {
                let composer_disabled_reason = match group_access {
                    Some(GroupAccessState::Muted) => Some("You are muted"),
                    Some(GroupAccessState::PendingJoin) => Some("Joining group..."),
                    _ => None,
                };
                render_composer(ui, app, convo_id.get(), composer_disabled_reason);
            });

            if let ConvoId::Group { group_id } = convo_id.get() {
                ui.add(GroupWindow {
                    app,
                    open: &mut show_group_window,
                    group: group_id,
                    user_info: &mut user_info_target,
                });
            }
            ui.add(UserInfo {
                app,
                target: user_info_target,
            });

            ui.response()
        });
        response.inner
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GroupAccessState {
    Active,
    Muted,
    Banned,
    PendingJoin,
}

fn group_access_state(own_username: &Option<UserName>, group_view: &GroupView) -> GroupAccessState {
    let Some(own_username) = own_username.as_ref() else {
        return if group_view.capabilities.can_send_messages {
            GroupAccessState::Active
        } else {
            GroupAccessState::PendingJoin
        };
    };

    match group_view
        .roster
        .iter()
        .find(|entry| entry.username == *own_username)
    {
        Some(entry) if entry.is_banned => GroupAccessState::Banned,
        Some(entry) if entry.is_muted => GroupAccessState::Muted,
        Some(_) => GroupAccessState::Active,
        None if group_view.capabilities.can_send_messages => GroupAccessState::Active,
        None => GroupAccessState::PendingJoin,
    }
}

fn infer_mime(path: &Path) -> SmolStr {
    infer::get_from_path(path)
        .ok()
        .flatten()
        .map(|kind| SmolStr::new(kind.mime_type()))
        .unwrap_or_else(|| SmolStr::new("application/octet-stream"))
}

fn new_scroller(convo_id: ConvoId) -> Scroller {
    InfiniteScroll::<ConvoItem, i64>::new().start_loader(move |cursor, callback| {
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

fn refresh_newer(convo_id: ConvoId, scroller: &mut Scroller) {
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
        })
        .or(Some(0));

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

fn render_header(
    app: &mut NullspaceApp,
    ui: &mut eframe::egui::Ui,
    convo_id: ConvoId,
    group_view: Option<&GroupView>,
    show_group_window: &mut bool,
    user_info_target: &mut Option<UserName>,
) {
    match convo_id {
        ConvoId::Direct { peer } => {
            let view = app.state.profile_loader.view(&peer);
            let display = app.state.profile_loader.label_for(&peer);
            ui.horizontal_centered(|ui| {
                let size = 24.0;
                ui.add(Avatar::for_user(
                    &peer,
                    view.and_then(|details| details.avatar),
                    size,
                ));
                ui.add(Label::new(
                    RichText::new(display).family(FontVariant::Bold.family()),
                ));
                if ui.button("Info").clicked() {
                    *user_info_target = Some(peer.clone());
                }
            });
        }
        ConvoId::Group { group_id } => {
            let display_title = group_view
                .map(|view| view.display_title.clone())
                .unwrap_or_else(|| format!("Group {}", group_id.short_id()));
            ui.horizontal_centered(|ui| {
                ui.add(Avatar::for_group(group_id, None, 24.0));
                ui.add(Label::new(RichText::from(display_title).heading()));
                if ui.add(Button::new("Manage")).clicked() {
                    *show_group_window = true;
                }
            });
        }
    }
}

fn render_messages(ui: &mut eframe::egui::Ui, app: &mut NullspaceApp, scroller: &mut Scroller) {
    let style: ConvoRowStyle = app.state.prefs.convo_row_style;
    let message_meta = message_render_meta(&scroller.items);
    let top_error = match scroller.top_loading_state() {
        egui_infinite_scroll::LoadingState::Error(err) => Some(err.clone()),
        _ => None,
    };
    ScrollArea::vertical()
        .id_salt("scroll")
        .stick_to_bottom(true)
        .animated(false)
        .show(ui, |ui| {
            ui.set_width(ui.available_width());

            scroller.ui(ui, MESSAGE_PREFETCH, |ui, index, item| {
                let meta = message_meta.get(index).copied().unwrap_or_default();
                if let Some(date) = meta.date_label {
                    ui.add_space(8.0);
                    ui.vertical_centered(|ui| {
                        let label = format!("{}", date.format("%A, %d %b %Y"));
                        ui.label(
                            RichText::new(label)
                                .color(ui.visuals().weak_text_color())
                                .size(12.0),
                        );
                    });
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

            if let Some(err) = top_error.as_ref() {
                ui.horizontal(|ui| {
                    ui.colored_label(
                        ui.visuals().error_fg_color,
                        format!("History load failed: {err}"),
                    );
                    if ui.button("Retry").clicked() {
                        scroller.retry_top();
                    }
                });
            }
        });
}

fn start_upload(attachment: &mut Var<Option<Uuid>>, path: PathBuf) {
    tracing::debug!(
        path = debug(&path),
        "picked an attachment, starting upload..."
    );
    let mime = infer_mime(&path);
    let result = if mime.starts_with("image/") {
        flatten_rpc(block_on(get_rpc().image_attachment_upload(path)))
    } else {
        flatten_rpc(block_on(get_rpc().attachment_upload(path, mime)))
    };
    let Ok(upload_id) = result else {
        return;
    };
    attachment.replace(upload_id);
}

fn render_composer(
    ui: &mut egui::Ui,
    app: &mut NullspaceApp,
    convo_id: ConvoId,
    disabled_reason: Option<&str>,
) {
    ui.add_space(8.0);
    let composer_enabled = disabled_reason.is_none();
    let mut attachment: Var<Option<Uuid>> = ui.use_state(|| None, ()).into_var();
    let pending_attachments: GBox<Vec<PathBuf>> = ui.use_gbox(Vec::new, ());
    let upload_files_done: State<usize> = ui.use_state(|| 0, ());
    let upload_files_total: State<usize> = ui.use_state(|| 0, ());

    let mut draft: Var<String> = ui.use_state(String::new, ()).into_var();
    let mut pasted_image: Var<Option<PasteImage>> = ui.use_state(|| None, ()).into_var();

    if attachment.is_none() && !pending_attachments.read().is_empty() {
        let next = pending_attachments.write().remove(0);
        start_upload(&mut attachment, next);
        if attachment.is_none() {
            upload_files_done.set_next(*upload_files_done + 1);
        }
    }

    let mut byte_progress = 0.0f32;
    let mut byte_progress_text = "Preparing upload...".to_string();

    // attachment part
    if let Some(in_progress) = attachment.as_ref() {
        if let Some((uploaded, total)) = app.state.upload_progress.get(in_progress) {
            let speed_key = format!("upload-{in_progress}");
            let (left, speed, right) = speed_fmt(&speed_key, *uploaded, *total);
            byte_progress_text = format!("{left} @ {speed}, {right} remaining");
            byte_progress = if *total == 0 {
                0.0
            } else {
                (*uploaded as f32 / *total as f32).clamp(0.0, 1.0)
            };
        } else if let Some(error) = app.state.upload_error.get(in_progress) {
            byte_progress_text = "Upload failed".to_string();
            ui.label(
                RichText::new(format!("Upload failed: {error}"))
                    .color(ui.visuals().error_fg_color)
                    .size(11.0),
            );
            if ui.button("Clear").clicked() {
                let upload_id = *in_progress;
                *attachment = None;
                app.state.upload_done.remove(&upload_id);
                app.state.upload_progress.remove(&upload_id);
                app.state.upload_error.remove(&upload_id);
                if pending_attachments.read().is_empty() {
                    upload_files_done.set_next(0);
                    upload_files_total.set_next(0);
                }
            }
        } else if composer_enabled {
            if let Some(done) = app.state.upload_done.get(in_progress) {
                let upload_id = *in_progress;
                let root = done.clone();
                let convo_id = convo_id.clone();
                smol::spawn(async move {
                    let payload = match root {
                        UploadedRoot::Attachment(root) => MessagePayload {
                            payload: MessageText::Plain(String::new()),
                            attachments: vec![root],
                            images: Vec::new(),
                            replies_to: None,
                            metadata: Default::default(),
                        },
                        UploadedRoot::ImageAttachment(root) => MessagePayload {
                            payload: MessageText::Plain(String::new()),
                            attachments: Vec::new(),
                            images: vec![root],
                            replies_to: None,
                            metadata: Default::default(),
                        },
                    };
                    let _ = flatten_rpc(get_rpc().convo_send(convo_id, payload).await);
                })
                .detach();
                *attachment = None;
                let next_done = *upload_files_done + 1;
                upload_files_done.set_next(next_done);
                app.state.upload_done.remove(&upload_id);
                app.state.upload_progress.remove(&upload_id);
                app.state.upload_error.remove(&upload_id);
                if pending_attachments.read().is_empty() && next_done >= *upload_files_total {
                    upload_files_done.set_next(0);
                    upload_files_total.set_next(0);
                }
            }
        }
    } else {
        ui.horizontal(|ui| {
            if ui
                .add_enabled(composer_enabled, Button::new("\u{ea7f} Attach"))
                .clicked()
            {
                app.file_dialog.pick_multiple();
            }
            if ui
                .add_enabled(
                    composer_enabled && pasted_image.is_none(),
                    Button::new("\u{ed7a} Clipboard image"),
                )
                .clicked()
            {
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
        if let Some(paths) = app.file_dialog.take_picked_multiple() {
            let mut added = 0usize;
            for path in paths {
                if path.is_file() {
                    pending_attachments.write().push(path);
                    added += 1;
                }
            }
            if added > 0 {
                if *upload_files_total == 0 {
                    upload_files_done.set_next(0);
                }
                upload_files_total.set_next(*upload_files_total + added);
            }
        } else if let Some(path) = app.file_dialog.take_picked()
            && path.is_file()
        {
            pending_attachments.write().push(path);
            if *upload_files_total == 0 {
                upload_files_done.set_next(0);
            }
            upload_files_total.set_next(*upload_files_total + 1);
        }
    }

    let uploads_pending = attachment.is_some() || !pending_attachments.read().is_empty();
    if uploads_pending {
        ui.add(ProgressBar::new(byte_progress).text(byte_progress_text));
        let total_files = (*upload_files_total).max(1);
        let done_files = (*upload_files_done).min(total_files);
        let files_progress = done_files as f32 / total_files as f32;
        ui.add(ProgressBar::new(files_progress).text(format!("{done_files}/{total_files} files")));
    }

    ui.take_available_space();

    if let Some(reason) = disabled_reason {
        ui.label(RichText::new(reason).color(ui.visuals().weak_text_color()));
    }

    // the texting part
    let newline_shortcut = egui::KeyboardShortcut::new(egui::Modifiers::SHIFT, egui::Key::Enter);
    let text_response = ScrollArea::vertical()
        .animated(false)
        .show(ui, |ui| {
            ui.add_enabled_ui(composer_enabled, |ui| {
                ui.add_sized(
                    ui.available_size(),
                    TextEdit::multiline(&mut *draft)
                        .desired_rows(1)
                        .hint_text("Enter a message...")
                        .desired_width(f32::INFINITY)
                        .return_key(Some(newline_shortcut)),
                )
            })
            .inner
        })
        .inner;

    let enter_pressed = composer_enabled
        && text_response.has_focus()
        && text_response
            .ctx
            .input(|input| input.key_pressed(Key::Enter) && !input.modifiers.shift);
    let send_now = enter_pressed;
    if send_now && !draft.trim().is_empty() {
        let message = draft.clone();
        send_message(&convo_id, message);
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
                let busy = attachment.is_some() || !composer_enabled;
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
                if busy && attachment.is_some() {
                    ui.label("Upload in progress");
                } else if let Some(reason) = disabled_reason {
                    ui.label(reason);
                }
            });
        });
    }
}

fn send_message(convo_id: &ConvoId, message: String) {
    let convo_id = convo_id.clone();
    smol::spawn(async move {
        let payload = MessagePayload {
            payload: MessageText::Plain(message),
            attachments: Vec::new(),
            images: Vec::new(),
            replies_to: None,
            metadata: Default::default(),
        };
        let _ = flatten_rpc(get_rpc().convo_send(convo_id, payload).await);
    })
    .detach();
}
