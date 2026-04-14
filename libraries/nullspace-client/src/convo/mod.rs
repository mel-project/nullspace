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
pub use queries::last_dm_received_at;

use anyctx::AnyCtx;
use bytes::Bytes;
use futures_concurrency::future::Race;
use nullspace_crypt::hash::Hash;
use nullspace_structs::event::{
    GroupPermissionChange, GroupSettingsChange, GroupUnban, MessagePayload, MessageText,
    TAG_GROUP_INVITATION, TAG_GROUP_PERMISSION_CHANGE, TAG_GROUP_SETTINGS_CHANGE, TAG_GROUP_UNBAN,
    TAG_LEAVE_REQUEST, TAG_MESSAGE,
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

pub(super) fn encode_event_body<T: Serialize>(value: &T) -> anyhow::Result<Bytes> {
    Ok(Bytes::from(serde_json::to_vec(value)?))
}

pub(super) fn decode_event_body<T: DeserializeOwned>(body: &[u8]) -> anyhow::Result<T> {
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

pub async fn ensure_thread_id(
    conn: &mut sqlx::SqliteConnection,
    thread_kind: &str,
    counterparty: &str,
) -> anyhow::Result<i64> {
    let created_at = NanoTimestamp::now().0 as i64;
    let row = sqlx::query_as::<_, (i64,)>(
        "INSERT INTO event_threads (thread_kind, thread_counterparty, created_at) \
         VALUES (?, ?, ?) \
         ON CONFLICT(thread_kind, thread_counterparty) DO UPDATE \
         SET thread_kind = excluded.thread_kind \
         RETURNING id",
    )
    .bind(thread_kind)
    .bind(counterparty)
    .bind(created_at)
    .fetch_one(&mut *conn)
    .await?;
    Ok(row.0)
}

/// Fields for inserting a new thread event row.
pub struct NewThreadEvent<'a> {
    pub thread_id: i64,
    pub sender: &'a str,
    pub event_tag: u16,
    pub event_body: &'a [u8],
    pub event_after: Option<&'a Hash>,
    pub event_hash: &'a Hash,
    pub sent_at: NanoTimestamp,
    pub received_at: Option<NanoTimestamp>,
}

/// Shared INSERT INTO thread_events used by both send.rs and dm_recv.rs.
pub async fn insert_thread_event(
    conn: &mut sqlx::SqliteConnection,
    event: &NewThreadEvent<'_>,
) -> anyhow::Result<Option<i64>> {
    let row = sqlx::query_as::<_, (i64,)>(
        "INSERT OR IGNORE INTO thread_events \
         (thread_id, sender_username, event_tag, event_body, event_after, event_hash, sent_at, received_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?) \
         RETURNING id",
    )
    .bind(event.thread_id)
    .bind(event.sender)
    .bind(i64::from(event.event_tag))
    .bind(event.event_body)
    .bind(event.event_after.map(|hash| hash.to_bytes().to_vec()))
    .bind(event.event_hash.to_bytes().to_vec())
    .bind(event.sent_at.0 as i64)
    .bind(event.received_at.map(|ts| ts.0 as i64))
    .fetch_optional(&mut *conn)
    .await?;
    Ok(row.map(|(id,)| id))
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
    GroupUnban(GroupUnban),
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
            ConvoEventItem::GroupSettingsChange(_) => "Group settings updated".to_string(),
            ConvoEventItem::GroupUnban(change) => format!("{} unbanned", change.username),
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
}

#[derive(sqlx::FromRow)]
struct ConvoHistoryRow {
    #[sqlx(flatten)]
    pub event: ThreadEventsRow,
    pub read_at: Option<i64>,
}

pub async fn convo_loop(ctx: &AnyCtx<Config>) {
    (
        send::send_loop(ctx),
        dm_recv::dm_recv_loop(ctx),
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
        TAG_GROUP_UNBAN => ConvoEventItem::GroupUnban(decode_event_body(body)?),
        TAG_LEAVE_REQUEST => ConvoEventItem::LeaveRequest,
        _ => ConvoEventItem::Unknown { tag: event_tag },
    };

    Ok(Some(ConvoItemKind::Event(event)))
}

pub(super) async fn thread_accepts_event_link(
    conn: &mut sqlx::SqliteConnection,
    thread_id: i64,
    event_after: Option<&Hash>,
) -> anyhow::Result<bool> {
    let Some(prev_hash) = event_after else {
        return Ok(true);
    };

    let exists = sqlx::query_scalar::<_, i64>(
        "SELECT 1 FROM thread_events WHERE thread_id = ? AND event_hash = ? LIMIT 1",
    )
    .bind(thread_id)
    .bind(prev_hash.to_bytes().to_vec())
    .fetch_optional(&mut *conn)
    .await?;
    if exists.is_some() {
        return Ok(true);
    }

    let has_any =
        sqlx::query_scalar::<_, i64>("SELECT 1 FROM thread_events WHERE thread_id = ? LIMIT 1")
            .bind(thread_id)
            .fetch_optional(&mut *conn)
            .await?;
    Ok(has_any.is_none())
}
