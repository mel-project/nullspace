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
use futures_concurrency::future::Race;
use nullspace_crypt::hash::Hash;
use nullspace_structs::event::{MessagePayload, MessageText, TAG_MESSAGE};
use nullspace_structs::group::GroupId;
use nullspace_structs::timestamp::NanoTimestamp;
use nullspace_structs::username::UserName;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

use crate::config::Config;

pub const THREAD_KIND_DIRECT: &str = "direct";
pub const THREAD_KIND_GROUP: &str = "group";

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
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ConvoItemKind {
    Message(MessagePayload),
    System(SystemItem),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SystemItem {
    Notice {
        text: String,
    },
    GroupCreated,
    GroupInvitationReceived {
        invitation_id: i64,
        group_id: GroupId,
        display_title: String,
    },
    GroupInvitationShared {
        username: UserName,
    },
    GroupMemberJoined {
        username: UserName,
    },
    GroupMemberLeft {
        username: UserName,
    },
    GroupMetadataChanged {
        title: Option<String>,
        description: Option<String>,
    },
    GroupMemberMutedChanged {
        username: UserName,
        muted: bool,
    },
    GroupNewMembersMutedChanged {
        muted: bool,
    },
    GroupHistorySharingChanged {
        allow_new_members_to_see_history: bool,
    },
    GroupAdminChanged {
        username: UserName,
        is_admin: bool,
    },
    GroupBanChanged {
        username: UserName,
        banned: bool,
    },
    GroupKeysRotated,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConvoItemPreview {
    pub sender: Option<UserName>,
    pub text: String,
    pub is_system: bool,
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
                    is_system: false,
                }
            }
            ConvoItemKind::System(system) => ConvoItemPreview {
                sender: None,
                text: system.summary_text(),
                is_system: true,
            },
        }
    }
}

impl SystemItem {
    pub fn summary_text(&self) -> String {
        match self {
            SystemItem::Notice { text } => text.clone(),
            SystemItem::GroupCreated => "Group created".to_string(),
            SystemItem::GroupInvitationReceived { display_title, .. } => {
                format!("Invited to {display_title}")
            }
            SystemItem::GroupInvitationShared { username } => {
                format!("Shared invite with {username}")
            }
            SystemItem::GroupMemberJoined { username } => format!("{username} joined"),
            SystemItem::GroupMemberLeft { username } => format!("{username} left"),
            SystemItem::GroupMetadataChanged { .. } => "Group details updated".to_string(),
            SystemItem::GroupMemberMutedChanged { username, muted } => {
                if *muted {
                    format!("{username} muted")
                } else {
                    format!("{username} unmuted")
                }
            }
            SystemItem::GroupNewMembersMutedChanged { muted } => {
                if *muted {
                    "New members muted".to_string()
                } else {
                    "New members unmuted".to_string()
                }
            }
            SystemItem::GroupHistorySharingChanged {
                allow_new_members_to_see_history,
            } => {
                if *allow_new_members_to_see_history {
                    "History sharing enabled".to_string()
                } else {
                    "History sharing disabled".to_string()
                }
            }
            SystemItem::GroupAdminChanged { username, is_admin } => {
                if *is_admin {
                    format!("{username} is now an admin")
                } else {
                    format!("{username} is no longer an admin")
                }
            }
            SystemItem::GroupBanChanged { username, banned } => {
                if *banned {
                    format!("{username} banned")
                } else {
                    format!("{username} unbanned")
                }
            }
            SystemItem::GroupKeysRotated => "Group keys rotated".to_string(),
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
        group_rotation::group_rotation_loop(ctx),
    )
        .race()
        .await;
}

fn display_title_for_convo(convo_id: &ConvoId) -> String {
    match convo_id {
        ConvoId::Direct { peer } => peer.as_str().to_owned(),
        ConvoId::Group { group_id } => format!("Group {}", group_id.short_id()),
    }
}

fn decode_convo_item_kind(
    event_tag: u16,
    body: &[u8],
    local_id: i64,
) -> anyhow::Result<ConvoItemKind> {
    if event_tag == TAG_MESSAGE {
        return Ok(ConvoItemKind::Message(bcs::from_bytes(body)?));
    }
    Ok(ConvoItemKind::System(SystemItem::Notice {
        text: format!("Unsupported item #{local_id}"),
    }))
}
