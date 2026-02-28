use anyctx::AnyCtx;
use async_channel::Sender as AsyncSender;
use futures_concurrency::future::Race;
use parking_lot::Mutex;
use std::collections::HashSet;

use crate::Config;
use crate::config::Ctx;
use crate::convo::{ConvoId, parse_convo_id};
use crate::database::{DATABASE, DbNotify};
use crate::identity::identity_exists;
use crate::internal::Event;

static EVENT_TX: Ctx<Mutex<Option<AsyncSender<Event>>>> = |_ctx| Mutex::new(None);

pub fn init_event_tx(ctx: &AnyCtx<Config>, tx: AsyncSender<Event>) {
    let mut guard = ctx.get(EVENT_TX).lock();
    *guard = Some(tx);
}

pub fn emit_event(ctx: &AnyCtx<Config>, event: Event) {
    let tx = ctx.get(EVENT_TX).lock();
    let Some(tx) = tx.as_ref() else {
        return;
    };
    let _ = tx.send_blocking(event);
}

pub async fn event_loop(ctx: &AnyCtx<Config>) {
    (login_event_loop(ctx), message_event_loop(ctx))
        .race()
        .await;
}

async fn login_event_loop(ctx: &AnyCtx<Config>) {
    let db = ctx.get(DATABASE);
    let mut notify = DbNotify::new();
    let mut logged_in = loop {
        match db.acquire().await {
            Ok(mut conn) => match identity_exists(&mut conn).await {
                Ok(value) => break value,
                Err(err) => {
                    tracing::warn!(error = %err, "failed to check identity state");
                }
            },
            Err(err) => {
                tracing::warn!(error = %err, "failed to acquire database connection");
            }
        }
    };
    emit_event(ctx, Event::State { logged_in });
    loop {
        notify.wait_for_change().await;
        let next_logged_in = match db.acquire().await {
            Ok(mut conn) => match identity_exists(&mut conn).await {
                Ok(value) => value,
                Err(err) => {
                    tracing::warn!(error = %err, "failed to check identity state");
                    continue;
                }
            },
            Err(err) => {
                tracing::warn!(error = %err, "failed to acquire database connection");
                continue;
            }
        };
        if next_logged_in != logged_in {
            logged_in = next_logged_in;
            emit_event(ctx, Event::State { logged_in });
        }
    }
}

async fn message_event_loop(ctx: &AnyCtx<Config>) {
    let db = ctx.get(DATABASE);
    let mut notify = DbNotify::new();
    let mut last_seen_id = match db.acquire().await {
        Ok(mut conn) => current_max_msg(&mut conn).await.unwrap_or(0),
        Err(_) => 0,
    };
    let mut last_seen_received_at = match db.acquire().await {
        Ok(mut conn) => current_max_received_at(&mut conn).await.unwrap_or(0),
        Err(_) => 0,
    };
    let mut last_seen_read_rowid = match db.acquire().await {
        Ok(mut conn) => current_max_read_rowid(&mut conn).await.unwrap_or(0),
        Err(_) => 0,
    };
    loop {
        notify.wait_for_change().await;
        let (new_last, mut convos) = match db.acquire().await {
            Ok(mut conn) => match new_message_convos(&mut conn, last_seen_id).await {
                Ok(result) => result,
                Err(err) => {
                    tracing::warn!(error = %err, "failed to query convo messages");
                    continue;
                }
            },
            Err(err) => {
                tracing::warn!(error = %err, "failed to acquire database connection");
                continue;
            }
        };
        last_seen_id = new_last;
        let (new_received_at, received_convos) = match db.acquire().await {
            Ok(mut conn) => match new_received_convos(&mut conn, last_seen_received_at).await {
                Ok(result) => result,
                Err(err) => {
                    tracing::warn!(error = %err, "failed to query convo received_at updates");
                    continue;
                }
            },
            Err(err) => {
                tracing::warn!(error = %err, "failed to acquire database connection");
                continue;
            }
        };
        last_seen_received_at = new_received_at;
        convos.extend(received_convos);
        let (new_read_rowid, read_convos) = match db.acquire().await {
            Ok(mut conn) => match new_read_convos(&mut conn, last_seen_read_rowid).await {
                Ok(result) => result,
                Err(err) => {
                    tracing::warn!(error = %err, "failed to query convo read updates");
                    continue;
                }
            },
            Err(err) => {
                tracing::warn!(error = %err, "failed to acquire database connection");
                continue;
            }
        };
        last_seen_read_rowid = new_read_rowid;
        convos.extend(read_convos);
        for convo_id in convos {
            emit_event(ctx, Event::ConvoUpdated { convo_id });
        }
    }
}

async fn current_max_msg(db: &mut sqlx::SqliteConnection) -> anyhow::Result<i64> {
    let row = sqlx::query_as::<_, (Option<i64>,)>("SELECT MAX(id) FROM thread_events")
        .fetch_one(&mut *db)
        .await?;
    Ok(row.0.unwrap_or(0))
}

async fn current_max_received_at(db: &mut sqlx::SqliteConnection) -> anyhow::Result<i64> {
    let row = sqlx::query_as::<_, (Option<i64>,)>(
        "SELECT MAX(received_at) FROM thread_events WHERE received_at IS NOT NULL",
    )
    .fetch_one(&mut *db)
    .await?;
    Ok(row.0.unwrap_or(0))
}

async fn current_max_read_rowid(db: &mut sqlx::SqliteConnection) -> anyhow::Result<i64> {
    let row = sqlx::query_as::<_, (Option<i64>,)>("SELECT MAX(rowid) FROM message_reads")
        .fetch_one(&mut *db)
        .await?;
    Ok(row.0.unwrap_or(0))
}

async fn new_message_convos(
    db: &mut sqlx::SqliteConnection,
    last_seen_id: i64,
) -> anyhow::Result<(i64, Vec<ConvoId>)> {
    let rows = sqlx::query_as::<_, (i64, String, String)>(
        "SELECT e.id, t.thread_kind, t.thread_counterparty \
         FROM thread_events e \
         JOIN event_threads t ON e.thread_id = t.id \
         WHERE e.id > ? \
         ORDER BY e.id",
    )
    .bind(last_seen_id)
    .fetch_all(&mut *db)
    .await?;
    if rows.is_empty() {
        return Ok((last_seen_id, Vec::new()));
    }
    let mut convos = HashSet::new();
    let mut max_id = last_seen_id;
    for (id, convo_type, counterparty) in rows {
        max_id = max_id.max(id);
        if let Some(convo_id) = parse_convo_id(&convo_type, &counterparty) {
            convos.insert(convo_id);
        }
    }
    Ok((max_id, convos.into_iter().collect()))
}

async fn new_received_convos(
    db: &mut sqlx::SqliteConnection,
    last_seen_received_at: i64,
) -> anyhow::Result<(i64, Vec<ConvoId>)> {
    let rows = sqlx::query_as::<_, (i64, String, String)>(
        "SELECT e.received_at, t.thread_kind, t.thread_counterparty \
         FROM thread_events e \
         JOIN event_threads t ON e.thread_id = t.id \
         WHERE e.received_at IS NOT NULL AND e.received_at > ? \
         ORDER BY e.received_at",
    )
    .bind(last_seen_received_at)
    .fetch_all(&mut *db)
    .await?;
    if rows.is_empty() {
        return Ok((last_seen_received_at, Vec::new()));
    }
    let mut convos = HashSet::new();
    let mut max_received_at = last_seen_received_at;
    for (received_at, convo_type, counterparty) in rows {
        max_received_at = max_received_at.max(received_at);
        if let Some(convo_id) = parse_convo_id(&convo_type, &counterparty) {
            convos.insert(convo_id);
        }
    }
    Ok((max_received_at, convos.into_iter().collect()))
}

async fn new_read_convos(
    db: &mut sqlx::SqliteConnection,
    last_seen_rowid: i64,
) -> anyhow::Result<(i64, Vec<ConvoId>)> {
    let rows = sqlx::query_as::<_, (i64, String, String)>(
        "SELECT mr.rowid, t.thread_kind, t.thread_counterparty \
         FROM message_reads mr \
         JOIN thread_events e ON e.id = mr.message_id \
         JOIN event_threads t ON e.thread_id = t.id \
         WHERE mr.rowid > ? \
         ORDER BY mr.rowid",
    )
    .bind(last_seen_rowid)
    .fetch_all(&mut *db)
    .await?;
    if rows.is_empty() {
        return Ok((last_seen_rowid, Vec::new()));
    }
    let mut convos = HashSet::new();
    let mut max_rowid = last_seen_rowid;
    for (rowid, convo_type, counterparty) in rows {
        max_rowid = max_rowid.max(rowid);
        if let Some(convo_id) = parse_convo_id(&convo_type, &counterparty) {
            convos.insert(convo_id);
        }
    }
    Ok((max_rowid, convos.into_iter().collect()))
}
