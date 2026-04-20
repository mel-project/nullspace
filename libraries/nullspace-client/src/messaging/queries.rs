use nullspace_structs::event::TAG_GROUP_INVITATION;
use nullspace_structs::group::GroupId;
use nullspace_structs::timestamp::NanoTimestamp;
use nullspace_structs::username::UserName;
use tracing::warn;

use super::{
    ConvoHistoryRow, ConvoId, ConvoItem, ConvoListRow, ConvoSummary, decode_convo_item_kind,
    parse_convo_id,
};

pub async fn convo_list(db: &mut sqlx::SqliteConnection) -> anyhow::Result<Vec<ConvoSummary>> {
    let local_username = sqlx::query_scalar::<_, String>(
        "SELECT username FROM client_identity WHERE id = 1",
    )
    .fetch_one(&mut *db)
    .await?;
    let rows = sqlx::query_as::<_, ConvoListRow>(
        "SELECT t.thread_kind, t.thread_counterparty, \
                (SELECT COUNT(*) FROM thread_events ue \
                 JOIN client_identity ci ON ci.id = 1 \
                 LEFT JOIN message_reads mr ON mr.message_id = ue.id \
                 WHERE ue.thread_id = t.id \
                   AND ue.received_at IS NOT NULL \
                   AND ue.event_tag != ? \
                   AND ue.sender_username != ci.username \
                   AND mr.message_id IS NULL) AS unread_count, \
                e.id AS msg_id, e.sender_username, e.event_tag, e.event_body, e.received_at, mr.read_at, e.send_error, \
                CASE \
                    WHEN e.id IS NULL OR e.event_after IS NULL THEN 0 \
                    WHEN EXISTS (SELECT 1 FROM thread_events parent WHERE parent.thread_id = e.thread_id AND parent.event_hash = e.event_after) THEN 0 \
                    ELSE 1 \
                END AS orphaned \
         FROM event_threads t \
         LEFT JOIN thread_events e \
           ON e.id = (SELECT MAX(id) FROM thread_events WHERE thread_id = t.id AND event_tag != ?) \
         LEFT JOIN message_reads mr ON mr.message_id = e.id \
         ORDER BY (e.received_at IS NULL) DESC, e.received_at DESC, t.created_at DESC, t.id DESC",
    )
    .bind(i64::from(TAG_GROUP_INVITATION))
    .bind(i64::from(TAG_GROUP_INVITATION))
    .fetch_all(&mut *db)
    .await?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let convo_id = parse_convo_id(&row.thread_kind, &row.thread_counterparty)
            .ok_or_else(|| anyhow::anyhow!("invalid convo row"))?;
        if let ConvoId::Group { group_id } = convo_id {
            if !group_is_active_for_user(db, group_id, &local_username).await? {
                continue;
            }
        }
        let last_item = match (
            row.msg_id,
            row.sender_username,
            row.event_tag,
            row.event_body,
        ) {
            (Some(id), Some(sender_username), Some(event_tag), Some(body)) => {
                let sender = UserName::parse(sender_username)?;
                let kind = match decode_convo_item_kind(u16::try_from(event_tag)?, &body) {
                    Ok(kind) => Some(kind),
                    Err(err) => {
                        warn!(error = %err, "failed to decode message payload in convo_list");
                        None
                    }
                };
                kind.flatten().map(|kind| {
                    ConvoItem {
                        id,
                        convo_id: convo_id.clone(),
                        sender,
                        sent_at: NanoTimestamp(0),
                        send_error: row.send_error.clone(),
                        received_at: row.received_at.map(|ts| NanoTimestamp(ts as u64)),
                        read_at: row.read_at.map(|ts| NanoTimestamp(ts as u64)),
                        orphaned: row.orphaned.unwrap_or(false),
                        kind,
                    }
                    .preview()
                })
            }
            _ => None,
        };
        let display_title = display_title_for_convo(db, &convo_id).await?;
        if matches!(convo_id, ConvoId::Direct { .. }) && last_item.is_none() {
            continue;
        }
        out.push(ConvoSummary {
            convo_id,
            display_title,
            last_item,
            unread_count: row.unread_count as u64,
        });
    }
    Ok(out)
}

async fn group_is_active_for_user(
    db: &mut sqlx::SqliteConnection,
    group_id: GroupId,
    local_username: &str,
) -> anyhow::Result<bool> {
    let row = sqlx::query_scalar::<_, i64>(
        "SELECT 1 \
         FROM group_keys gk \
         JOIN group_members_current gm ON gm.group_id = gk.group_id \
         WHERE gk.group_id = ? AND gm.username = ? \
         LIMIT 1",
    )
    .bind(group_id.to_bytes().to_vec())
    .bind(local_username)
    .fetch_optional(&mut *db)
    .await?;
    Ok(row.is_some())
}

async fn display_title_for_convo(
    db: &mut sqlx::SqliteConnection,
    convo_id: &ConvoId,
) -> anyhow::Result<String> {
    match convo_id {
        ConvoId::Direct { peer } => Ok(peer.as_str().to_owned()),
        ConvoId::Group { group_id } => Ok(load_group_title(db, *group_id)
            .await?
            .unwrap_or_else(|| format!("Group {}", group_id.short_id()))),
    }
}

async fn load_group_title(
    db: &mut sqlx::SqliteConnection,
    group_id: GroupId,
) -> anyhow::Result<Option<String>> {
    let gid = group_id.to_bytes().to_vec();
    let row = sqlx::query_as::<_, (Option<String>,)>(
        "SELECT title FROM group_state_current WHERE group_id = ?",
    )
    .bind(gid)
    .fetch_optional(&mut *db)
    .await?;
    Ok(row.and_then(|(title,)| title))
}

pub async fn convo_history(
    db: &mut sqlx::SqliteConnection,
    convo_id: ConvoId,
    before: Option<i64>,
    after: Option<i64>,
    limit: u16,
) -> anyhow::Result<Vec<ConvoItem>> {
    let before = before.unwrap_or(i64::MAX);
    let after = after.unwrap_or(i64::MIN);
    let thread_kind = convo_id.convo_type();
    let counterparty = convo_id.counterparty();
    let mut rows = sqlx::query_as::<_, ConvoHistoryRow>(
        "SELECT e.*, mr.read_at, \
                CASE \
                    WHEN e.event_after IS NULL THEN 0 \
                    WHEN EXISTS (SELECT 1 FROM thread_events parent WHERE parent.thread_id = e.thread_id AND parent.event_hash = e.event_after) THEN 0 \
                    ELSE 1 \
                END AS orphaned \
         FROM thread_events e \
         JOIN event_threads t ON e.thread_id = t.id \
         LEFT JOIN message_reads mr ON mr.message_id = e.id \
         WHERE t.thread_kind = ? AND t.thread_counterparty = ? AND e.event_tag != ? AND e.id <= ? AND e.id >= ? \
         ORDER BY e.id DESC \
         LIMIT ?",
    )
    .bind(thread_kind)
    .bind(counterparty)
    .bind(i64::from(TAG_GROUP_INVITATION))
    .bind(before)
    .bind(after)
    .bind(limit as i64)
    .fetch_all(&mut *db)
    .await?;
    rows.reverse();
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let sender = UserName::parse(row.event.sender_username)?;
        let kind = match decode_convo_item_kind(
            u16::try_from(row.event.event_tag)?,
            &row.event.event_body,
        ) {
            Ok(Some(kind)) => kind,
            Ok(None) => continue,
            Err(err) => {
                warn!(error = %err, "failed to decode message payload in convo_history");
                continue;
            }
        };
        out.push(ConvoItem {
            id: row.event.id,
            convo_id: convo_id.clone(),
            sender,
            sent_at: NanoTimestamp(row.event.sent_at as u64),
            send_error: row.event.send_error,
            received_at: row.event.received_at.map(|ts| NanoTimestamp(ts as u64)),
            read_at: row.read_at.map(|ts| NanoTimestamp(ts as u64)),
            orphaned: row.orphaned,
            kind,
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
