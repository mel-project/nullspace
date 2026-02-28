//! Conversation primitives shared across the frontend API.
//!
//! This module defines the types that frontends use to display and interact
//! with conversations.

use anyctx::AnyCtx;
use futures_concurrency::future::Race;
use nullspace_structs::event::{MessagePayload, MessageText, TAG_MESSAGE};
use nullspace_structs::group::GroupId;
use nullspace_structs::timestamp::NanoTimestamp;
use nullspace_structs::username::UserName;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

use crate::attachments::store_attachment_root;
use crate::config::Config;

mod dm_common;
mod dm_recv;
mod send;

pub use send::queue_message;

/// Identifies a conversation.
///
/// Every conversation is either a direct message with a single peer or a
/// named group with multiple members.  This enum is the primary key used
/// throughout the API to refer to conversations in list, history, send,
/// and mark-read calls.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ConvoId {
    /// A one-to-one direct message conversation.
    Direct { peer: UserName },
    /// A group conversation.
    Group { group_id: GroupId },
}

impl ConvoId {
    pub fn convo_type(&self) -> &'static str {
        match self {
            ConvoId::Direct { .. } => "direct",
            ConvoId::Group { .. } => "group",
        }
    }

    pub fn counterparty(&self) -> String {
        match self {
            ConvoId::Direct { peer } => peer.as_str().to_string(),
            ConvoId::Group { group_id } => group_id.to_string(),
        }
    }
}

pub fn parse_convo_id(convo_type: &str, counterparty: &str) -> Option<ConvoId> {
    match convo_type {
        "direct" => UserName::parse(counterparty)
            .ok()
            .map(|peer| ConvoId::Direct { peer }),
        "group" => GroupId::from_str(counterparty)
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

/// A single message in a conversation, as returned by
/// [`convo_history`](crate::internal::InternalProtocol::convo_history).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConvoMessage {
    /// Locally-assigned, monotonically increasing message ID.
    pub id: i64,
    /// The conversation this message belongs to.
    pub convo_id: ConvoId,
    /// Who sent the message.
    pub sender: UserName,
    /// The decoded message payload.
    pub body: MessagePayload,
    /// If the send loop failed to deliver this message, the error
    /// description.  `None` for incoming messages and successfully
    /// delivered outgoing messages.
    pub send_error: Option<String>,
    /// Timestamp set by the server when the message was received.
    /// `None` for outgoing messages that have not yet been delivered.
    pub received_at: Option<NanoTimestamp>,
    /// Timestamp at which the local user marked this message as read.
    pub read_at: Option<NanoTimestamp>,
}

/// Summary of a conversation for list views.
///
/// Returned by
/// [`convo_list`](crate::internal::InternalProtocol::convo_list).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConvoSummary {
    pub convo_id: ConvoId,
    /// The most recent message in the conversation, if any.
    pub last_message: Option<ConvoMessage>,
    /// Number of unread incoming messages.
    pub unread_count: u64,
}

pub async fn convo_loop(ctx: &AnyCtx<Config>) {
    (send::send_loop(ctx), dm_recv::dm_recv_loop(ctx))
        .race()
        .await;
}

pub async fn convo_list(db: &mut sqlx::SqliteConnection) -> anyhow::Result<Vec<ConvoSummary>> {
    let rows = sqlx::query_as::<
        _,
        (
            String,
            String,
            i64,
            i64,
            Option<i64>,
            Option<String>,
            Option<i64>,
            Option<Vec<u8>>,
            Option<i64>,
            Option<i64>,
            Option<String>,
        ),
    >(
        "SELECT t.thread_kind, t.thread_counterparty, t.created_at, \
                (SELECT COUNT(*) FROM thread_events ue \
                 JOIN client_identity ci ON ci.id = 1 \
                 LEFT JOIN message_reads mr ON mr.message_id = ue.id \
                 WHERE ue.thread_id = t.id \
                   AND ue.received_at IS NOT NULL \
                   AND ue.sender_username != ci.username \
                   AND mr.message_id IS NULL) AS unread_count, \
                e.id, e.sender_username, e.event_tag, e.event_body, e.received_at, mr.read_at, e.send_error \
         FROM event_threads t \
         LEFT JOIN thread_events e \
           ON e.id = (SELECT MAX(id) FROM thread_events WHERE thread_id = t.id) \
         LEFT JOIN message_reads mr ON mr.message_id = e.id \
         ORDER BY (e.received_at IS NULL) DESC, e.received_at DESC, t.created_at DESC, t.id DESC",
    )
    .fetch_all(&mut *db)
    .await?;
    let mut out = Vec::with_capacity(rows.len());
    for (
        thread_kind,
        counterparty,
        _created_at,
        unread_count,
        msg_id,
        sender_username,
        event_tag,
        event_body,
        received_at,
        read_at,
        send_error,
    ) in rows
    {
        let convo_id = parse_convo_id(&thread_kind, &counterparty)
            .ok_or_else(|| anyhow::anyhow!("invalid convo row"))?;
        let last_message = match (msg_id, sender_username, event_tag, event_body) {
            (Some(id), Some(sender_username), Some(event_tag), Some(body)) => {
                let sender = UserName::parse(sender_username)?;
                let body = decode_message_payload(&mut *db, &sender, u16::try_from(event_tag)?, &body)
                    .await
                    .ok();
                body.map(|body| ConvoMessage {
                    id,
                    convo_id: convo_id.clone(),
                    sender,
                    body,
                    send_error,
                    received_at: received_at.map(|ts| NanoTimestamp(ts as u64)),
                    read_at: read_at.map(|ts| NanoTimestamp(ts as u64)),
                })
            }
            _ => None,
        };
        out.push(ConvoSummary {
            convo_id,
            last_message,
            unread_count: unread_count as u64,
        });
    }
    Ok(out)
}

pub async fn convo_history(
    db: &mut sqlx::SqliteConnection,
    convo_id: ConvoId,
    before: Option<i64>,
    after: Option<i64>,
    limit: u16,
) -> anyhow::Result<Vec<ConvoMessage>> {
    let before = before.unwrap_or(i64::MAX);
    let after = after.unwrap_or(i64::MIN);
    let thread_kind = convo_id.convo_type();
    let counterparty = convo_id.counterparty();
    let mut rows = sqlx::query_as::<
        _,
        (
            i64,
            String,
            i64,
            Vec<u8>,
            Option<i64>,
            Option<i64>,
            Option<String>,
        ),
    >(
        "SELECT e.id, e.sender_username, e.event_tag, e.event_body, e.received_at, mr.read_at, e.send_error \
         FROM thread_events e \
         JOIN event_threads t ON e.thread_id = t.id \
         LEFT JOIN message_reads mr ON mr.message_id = e.id \
         WHERE t.thread_kind = ? AND t.thread_counterparty = ? AND e.id <= ? AND e.id >= ? \
         ORDER BY e.id DESC \
         LIMIT ?",
    )
    .bind(thread_kind)
    .bind(counterparty)
    .bind(before)
    .bind(after)
    .bind(limit as i64)
    .fetch_all(&mut *db)
    .await?;
    rows.reverse();
    let mut out = Vec::with_capacity(rows.len());
    for (id, sender_username, event_tag, body, received_at, read_at, send_error) in rows {
        let sender = UserName::parse(sender_username)?;
        let body =
            match decode_message_payload(&mut *db, &sender, u16::try_from(event_tag)?, &body).await
            {
                Ok(body) => body,
                Err(_) => {
                    continue;
                }
            };
        out.push(ConvoMessage {
            id,
            convo_id: convo_id.clone(),
            sender,
            body,
            send_error,
            received_at: received_at.map(|ts| NanoTimestamp(ts as u64)),
            read_at: read_at.map(|ts| NanoTimestamp(ts as u64)),
        });
    }
    Ok(out)
}

pub async fn mark_convo_read(
    db: &mut sqlx::SqliteConnection,
    convo_id: ConvoId,
    up_to_id: i64,
) -> anyhow::Result<u64> {
    let read_at = NanoTimestamp::now().0 as i64;
    let affected = sqlx::query(
        "INSERT OR IGNORE INTO message_reads (message_id, read_at) \
         SELECT e.id, ? \
         FROM thread_events e \
         JOIN event_threads t ON e.thread_id = t.id \
         JOIN client_identity ci ON ci.id = 1 \
         WHERE t.thread_kind = ? \
           AND t.thread_counterparty = ? \
           AND e.id <= ? \
           AND e.received_at IS NOT NULL \
           AND e.sender_username != ci.username",
    )
    .bind(read_at)
    .bind(convo_id.convo_type())
    .bind(convo_id.counterparty())
    .bind(up_to_id)
    .execute(&mut *db)
    .await?
    .rows_affected();
    Ok(affected)
}

pub async fn last_dm_received_at(
    db: &mut sqlx::SqliteConnection,
    local_username: &UserName,
    other_username: &UserName,
) -> anyhow::Result<Option<NanoTimestamp>> {
    let convo_id = ConvoId::Direct {
        peer: other_username.clone(),
    };
    let thread_kind = convo_id.convo_type();
    let counterparty = convo_id.counterparty();
    let received_at = sqlx::query_scalar::<_, Option<i64>>(
        "SELECT e.received_at \
         FROM thread_events e \
         JOIN event_threads t ON e.thread_id = t.id \
         WHERE t.thread_kind = ? AND t.thread_counterparty = ? AND e.sender_username != ? \
         ORDER BY e.id DESC \
         LIMIT 1",
    )
    .bind(thread_kind)
    .bind(counterparty)
    .bind(local_username.as_str())
    .fetch_optional(&mut *db)
    .await?
    .flatten();
    Ok(received_at.map(|ts| NanoTimestamp(ts as u64)))
}

async fn decode_message_payload(
    db: &mut sqlx::SqliteConnection,
    sender: &UserName,
    event_tag: u16,
    body: &[u8],
) -> anyhow::Result<MessagePayload> {
    if event_tag != TAG_MESSAGE {
        return Ok(MessagePayload {
            payload: MessageText::Plain("Unsupported message".to_string()),
            attachments: Vec::new(),
            images: Vec::new(),
            replies_to: None,
            metadata: Default::default(),
        });
    }

    let payload: MessagePayload = bcs::from_bytes(body)?;
    for root in &payload.attachments {
        let _ = store_attachment_root(&mut *db, sender, root).await?;
    }
    for image in &payload.images {
        let _ = store_attachment_root(&mut *db, sender, &image.inner).await?;
    }
    Ok(payload)
}
