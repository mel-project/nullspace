//! Conversation primitives shared across the frontend API.
//!
//! This module defines the types that frontends use to display and interact
//! with conversations.

use anyctx::AnyCtx;
use futures_concurrency::future::Race;
use nullspace_crypt::hash::Hash;
use nullspace_structs::event::{MessagePayload, MessageText, TAG_MESSAGE};
use nullspace_structs::group::GroupId;
use nullspace_structs::timestamp::NanoTimestamp;
use nullspace_structs::username::UserName;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use tracing::warn;

use crate::config::Config;

mod dm_recv;
mod send;

pub use send::queue_message;

pub const THREAD_KIND_DIRECT: &str = "direct";
pub const THREAD_KIND_GROUP: &str = "group";

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

pub fn parse_convo_id(convo_type: &str, counterparty: &str) -> Option<ConvoId> {
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

/// Shared INSERT INTO thread_events used by both send.rs and dm_recv.rs.
///
/// Returns `Some(id)` if a row was inserted, `None` if it was ignored
/// (duplicate event hash).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn insert_thread_event(
    conn: &mut sqlx::SqliteConnection,
    thread_id: i64,
    sender: &str,
    event_tag: u16,
    event_body: &[u8],
    event_after: Option<&Hash>,
    event_hash: &Hash,
    sent_at: NanoTimestamp,
    received_at: Option<NanoTimestamp>,
) -> anyhow::Result<Option<i64>> {
    let row = sqlx::query_as::<_, (i64,)>(
        "INSERT OR IGNORE INTO thread_events \
         (thread_id, sender_username, event_tag, event_body, event_after, event_hash, sent_at, received_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?) \
         RETURNING id",
    )
    .bind(thread_id)
    .bind(sender)
    .bind(i64::from(event_tag))
    .bind(event_body)
    .bind(event_after.map(|hash| hash.to_bytes().to_vec()))
    .bind(event_hash.to_bytes().to_vec())
    .bind(sent_at.0 as i64)
    .bind(received_at.map(|ts| ts.0 as i64))
    .fetch_optional(&mut *conn)
    .await?;
    Ok(row.map(|(id,)| id))
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

#[derive(sqlx::FromRow)]
#[allow(dead_code)]
pub(super) struct ThreadEventsRow {
    id: i64,
    thread_id: i64,
    sender_username: String,
    event_tag: i64,
    event_body: Vec<u8>,
    event_after: Option<Vec<u8>>,
    event_hash: Vec<u8>,
    sent_at: i64,
    send_error: Option<String>,
    received_at: Option<i64>,
}

#[derive(sqlx::FromRow)]
struct ConvoListRow {
    thread_kind: String,
    thread_counterparty: String,
    unread_count: i64,
    msg_id: Option<i64>,
    sender_username: Option<String>,
    event_tag: Option<i64>,
    event_body: Option<Vec<u8>>,
    received_at: Option<i64>,
    read_at: Option<i64>,
    send_error: Option<String>,
}

#[derive(sqlx::FromRow)]
struct ConvoHistoryRow {
    #[sqlx(flatten)]
    event: ThreadEventsRow,
    read_at: Option<i64>,
}

pub async fn convo_loop(ctx: &AnyCtx<Config>) {
    (send::send_loop(ctx), dm_recv::dm_recv_loop(ctx))
        .race()
        .await;
}

pub async fn convo_list(db: &mut sqlx::SqliteConnection) -> anyhow::Result<Vec<ConvoSummary>> {
    let rows = sqlx::query_as::<_, ConvoListRow>(
        "SELECT t.thread_kind, t.thread_counterparty, \
                (SELECT COUNT(*) FROM thread_events ue \
                 JOIN client_identity ci ON ci.id = 1 \
                 LEFT JOIN message_reads mr ON mr.message_id = ue.id \
                 WHERE ue.thread_id = t.id \
                   AND ue.received_at IS NOT NULL \
                   AND ue.sender_username != ci.username \
                   AND mr.message_id IS NULL) AS unread_count, \
                e.id AS msg_id, e.sender_username, e.event_tag, e.event_body, e.received_at, mr.read_at, e.send_error \
         FROM event_threads t \
         LEFT JOIN thread_events e \
           ON e.id = (SELECT MAX(id) FROM thread_events WHERE thread_id = t.id) \
         LEFT JOIN message_reads mr ON mr.message_id = e.id \
         ORDER BY (e.received_at IS NULL) DESC, e.received_at DESC, t.created_at DESC, t.id DESC",
    )
    .fetch_all(&mut *db)
    .await?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let convo_id = parse_convo_id(&row.thread_kind, &row.thread_counterparty)
            .ok_or_else(|| anyhow::anyhow!("invalid convo row"))?;
        let last_message = match (row.msg_id, row.sender_username, row.event_tag, row.event_body) {
            (Some(id), Some(sender_username), Some(event_tag), Some(body)) => {
                let sender = UserName::parse(sender_username)?;
                let body = match decode_message_payload(u16::try_from(event_tag)?, &body) {
                    Ok(body) => Some(body),
                    Err(err) => {
                        warn!(error = %err, "failed to decode message payload in convo_list");
                        None
                    }
                };
                body.map(|body| ConvoMessage {
                    id,
                    convo_id: convo_id.clone(),
                    sender,
                    body,
                    send_error: row.send_error,
                    received_at: row.received_at.map(|ts| NanoTimestamp(ts as u64)),
                    read_at: row.read_at.map(|ts| NanoTimestamp(ts as u64)),
                })
            }
            _ => None,
        };
        out.push(ConvoSummary {
            convo_id,
            last_message,
            unread_count: row.unread_count as u64,
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
    let mut rows = sqlx::query_as::<_, ConvoHistoryRow>(
        "SELECT e.*, mr.read_at \
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
    for row in rows {
        let sender = UserName::parse(row.event.sender_username)?;
        let body = match decode_message_payload(
            u16::try_from(row.event.event_tag)?,
            &row.event.event_body,
        ) {
            Ok(body) => body,
            Err(err) => {
                warn!(error = %err, "failed to decode message payload in convo_history");
                continue;
            }
        };
        out.push(ConvoMessage {
            id: row.event.id,
            convo_id: convo_id.clone(),
            sender,
            body,
            send_error: row.event.send_error,
            received_at: row.event.received_at.map(|ts| NanoTimestamp(ts as u64)),
            read_at: row.read_at.map(|ts| NanoTimestamp(ts as u64)),
        });
    }
    Ok(out)
}

pub async fn mark_convo_read(
    db: &mut sqlx::SqliteConnection,
    convo_id: &ConvoId,
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

fn decode_message_payload(event_tag: u16, body: &[u8]) -> anyhow::Result<MessagePayload> {
    if event_tag != TAG_MESSAGE {
        return Ok(MessagePayload {
            payload: MessageText::Plain("Unsupported message".to_string()),
            attachments: Vec::new(),
            images: Vec::new(),
            replies_to: None,
            metadata: Default::default(),
        });
    }
    Ok(bcs::from_bytes(body)?)
}
