use nullspace_crypt::hash::Hash;
use nullspace_structs::event::TAG_GROUP_INVITATION;
use nullspace_structs::timestamp::NanoTimestamp;
use nullspace_structs::username::UserName;

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

pub async fn thread_accepts_event_link(
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

pub async fn last_dm_received_at(
    db: &mut sqlx::SqliteConnection,
    local_username: &UserName,
    other_username: &UserName,
) -> anyhow::Result<Option<NanoTimestamp>> {
    let received_at = sqlx::query_scalar::<_, Option<i64>>(
        "SELECT e.received_at \
         FROM thread_events e \
         JOIN event_threads t ON e.thread_id = t.id \
         WHERE t.thread_kind = 'direct' AND t.thread_counterparty = ? AND e.event_tag != ? AND e.sender_username != ? \
         ORDER BY e.id DESC \
         LIMIT 1",
    )
    .bind(other_username.as_str())
    .bind(i64::from(TAG_GROUP_INVITATION))
    .bind(local_username.as_str())
    .fetch_optional(&mut *db)
    .await?
    .flatten();
    Ok(received_at.map(|ts| NanoTimestamp(ts as u64)))
}
