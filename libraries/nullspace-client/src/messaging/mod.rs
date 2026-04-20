//! Conversation primitives shared across the frontend API.
//!
//! This module defines the types that frontends use to display and interact
//! with conversations.

mod convo_impl;
mod device_crypt;
mod dm_recv;
mod dm_send;
mod group_recv;
mod group_rotation;
mod group_send;
mod groups;
mod queries;
mod send;

pub use convo_impl::*;

use anyctx::AnyCtx;
use bytes::Bytes;
use futures_concurrency::future::Race;
use nullspace_structs::event::{
    GroupPermissionChange, GroupSettingsChange, MessagePayload, MessageText, TAG_GROUP_INVITATION,
    TAG_GROUP_PERMISSION_CHANGE, TAG_GROUP_SETTINGS_CHANGE, TAG_JOIN_REQUEST, TAG_LEAVE_REQUEST,
    TAG_MESSAGE,
};
use nullspace_structs::group::GroupId;
use nullspace_structs::timestamp::NanoTimestamp;
use nullspace_structs::username::UserName;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

use crate::config::Config;

pub const THREAD_KIND_DIRECT: &str = "direct";
pub const THREAD_KIND_GROUP: &str = "group";

pub fn encode_event_body<T: Serialize>(value: &T) -> anyhow::Result<Bytes> {
    Ok(Bytes::from(serde_json::to_vec(value)?))
}

pub fn decode_event_body<T: DeserializeOwned>(body: &[u8]) -> anyhow::Result<T> {
    Ok(serde_json::from_slice(body)?)
}

/// Identifies a conversation.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ConvoId {
    Direct { peer: UserName },
    Group { group_id: GroupId },
}

impl ConvoId {
    pub fn convo_type(&self) -> &'static str {
        match self {
            ConvoId::Direct { .. } => THREAD_KIND_DIRECT,
            ConvoId::Group { .. } => THREAD_KIND_GROUP,
        }
    }

    pub fn counterparty(&self) -> String {
        match self {
            ConvoId::Direct { peer } => peer.as_str().to_owned(),
            ConvoId::Group { group_id } => group_id.to_string(),
        }
    }
}

fn parse_convo_id(convo_type: &str, counterparty: &str) -> Option<ConvoId> {
    match convo_type {
        THREAD_KIND_DIRECT => UserName::parse(counterparty)
            .ok()
            .map(|peer| ConvoId::Direct { peer }),
        THREAD_KIND_GROUP => GroupId::from_str(counterparty)
            .ok()
            .map(|group_id| ConvoId::Group { group_id }),
        _ => None,
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConvoItem {
    pub id: i64,
    pub convo_id: ConvoId,
    pub sender: UserName,
    pub sent_at: NanoTimestamp,
    pub send_error: Option<String>,
    pub received_at: Option<NanoTimestamp>,
    pub read_at: Option<NanoTimestamp>,
    pub orphaned: bool,
    pub kind: ConvoItemKind,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConvoItemKind {
    Message(MessagePayload),
    Event(ConvoEventItem),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConvoEventItem {
    GroupPermissionChange(GroupPermissionChange),
    GroupSettingsChange(GroupSettingsChange),
    JoinRequest,
    LeaveRequest,
    Unknown { tag: u16 },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConvoItemPreview {
    pub sender: Option<UserName>,
    pub text: String,
    pub is_event: bool,
}

impl ConvoItem {
    pub fn preview(&self) -> ConvoItemPreview {
        match &self.kind {
            ConvoItemKind::Message(message) => {
                let text = match &message.payload {
                    MessageText::Plain(text) | MessageText::Rich(text) => text.clone(),
                };
                let text = if !text.is_empty() {
                    text
                } else if !message.images.is_empty() {
                    "Image".to_string()
                } else if !message.attachments.is_empty() {
                    "Attachment".to_string()
                } else {
                    "Message".to_string()
                };
                ConvoItemPreview {
                    sender: Some(self.sender.clone()),
                    text,
                    is_event: false,
                }
            }
            ConvoItemKind::Event(event) => ConvoItemPreview {
                sender: None,
                text: event.summary_text(&self.sender),
                is_event: true,
            },
        }
    }
}

impl ConvoEventItem {
    pub fn summary_text(&self, sender: &UserName) -> String {
        match self {
            ConvoEventItem::GroupPermissionChange(change) => {
                if change.muted {
                    format!("{} muted", change.username)
                } else {
                    format!("{} unmuted", change.username)
                }
            }
            ConvoEventItem::GroupSettingsChange(change) => {
                let title = change
                    .title
                    .as_deref()
                    .map(|title| format!("title \"{title}\""))
                    .unwrap_or_else(|| "title cleared".to_string());
                let description = change
                    .description
                    .as_deref()
                    .map(|description| format!("description \"{description}\""))
                    .unwrap_or_else(|| "description cleared".to_string());
                let new_members = if change.new_members_muted {
                    "new members muted"
                } else {
                    "new members unmuted"
                };
                let history = if change.allow_new_members_to_see_history {
                    "history visible to new members"
                } else {
                    "history hidden from new members"
                };
                format!(
                    "Group settings now set to: {title}; {description}; {new_members}; {history}"
                )
            }
            ConvoEventItem::JoinRequest => format!("{sender} joined"),
            ConvoEventItem::LeaveRequest => format!("{sender} left"),
            ConvoEventItem::Unknown { tag } => format!("Unknown event tag {tag}"),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConvoSummary {
    pub convo_id: ConvoId,
    pub display_title: String,
    pub last_item: Option<ConvoItemPreview>,
    pub unread_count: u64,
}

#[derive(sqlx::FromRow)]
#[allow(dead_code)]
struct ThreadEventsRow {
    pub id: i64,
    pub thread_id: i64,
    pub sender_username: String,
    pub event_tag: i64,
    pub event_body: Vec<u8>,
    pub event_after: Option<Vec<u8>>,
    pub event_hash: Vec<u8>,
    pub sent_at: i64,
    pub send_error: Option<String>,
    pub received_at: Option<i64>,
}

#[derive(sqlx::FromRow)]
struct ConvoListRow {
    pub thread_kind: String,
    pub thread_counterparty: String,
    pub unread_count: i64,
    pub msg_id: Option<i64>,
    pub sender_username: Option<String>,
    pub event_tag: Option<i64>,
    pub event_body: Option<Vec<u8>>,
    pub received_at: Option<i64>,
    pub read_at: Option<i64>,
    pub send_error: Option<String>,
    pub orphaned: Option<bool>,
}

#[derive(sqlx::FromRow)]
struct ConvoHistoryRow {
    #[sqlx(flatten)]
    pub event: ThreadEventsRow,
    pub read_at: Option<i64>,
    pub orphaned: bool,
}

pub async fn message_loop(ctx: &AnyCtx<Config>) {
    (send::send_loop(ctx), dm_recv::dm_recv_loop(ctx))
        .race()
        .await;
}

pub async fn group_worker_loop(ctx: &AnyCtx<Config>) {
    (
        group_recv::group_recv_loop(ctx),
        groups::group_refresh_loop(ctx),
        group_rotation::group_rotation_loop(ctx),
    )
        .race()
        .await;
}

fn decode_convo_item_kind(event_tag: u16, body: &[u8]) -> anyhow::Result<Option<ConvoItemKind>> {
    if event_tag == TAG_MESSAGE {
        return Ok(Some(ConvoItemKind::Message(decode_event_body(body)?)));
    }
    if event_tag == TAG_GROUP_INVITATION {
        return Ok(None);
    }

    let event = match event_tag {
        TAG_GROUP_PERMISSION_CHANGE => {
            ConvoEventItem::GroupPermissionChange(decode_event_body(body)?)
        }
        TAG_GROUP_SETTINGS_CHANGE => ConvoEventItem::GroupSettingsChange(decode_event_body(body)?),
        TAG_JOIN_REQUEST => ConvoEventItem::JoinRequest,
        TAG_LEAVE_REQUEST => ConvoEventItem::LeaveRequest,
        _ => ConvoEventItem::Unknown { tag: event_tag },
    };

    Ok(Some(ConvoItemKind::Event(event)))
}
