use std::time::Duration;

use anyctx::AnyCtx;
use futures_concurrency::future::Race;
use nullspace_structs::group::GroupId;
use nullspace_structs::server::MailboxId;
use nullspace_structs::timestamp::NanoTimestamp;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{Executor, Sqlite, SqlitePool};

use crate::Config;
use crate::config::Ctx;
use crate::convo::parse_convo_id;
use crate::events::emit_event;
use crate::internal::Event;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::Notify;

static DB_NOTIFY: Notify = Notify::const_new();
static DB_NOTIFY_GEN: AtomicU64 = AtomicU64::new(0);

pub struct DbNotify {
    last_seen: u64,
}

impl DbNotify {
    pub fn new() -> Self {
        Self {
            last_seen: DB_NOTIFY_GEN.load(Ordering::Relaxed),
        }
    }

    pub fn touch() {
        DB_NOTIFY_GEN.fetch_add(1, Ordering::Relaxed);
        DB_NOTIFY.notify_waiters();
    }

    pub async fn wait_for_change(&mut self) {
        loop {
            let now = DB_NOTIFY_GEN.load(Ordering::Relaxed);
            if now != self.last_seen {
                self.last_seen = now;
                return;
            }
            DB_NOTIFY.notified().await;
        }
    }
}

pub static DATABASE: Ctx<SqlitePool> = |ctx| {
    let options = SqliteConnectOptions::new()
        .filename(&ctx.init().db_path)
        .create_if_missing(true)
        .busy_timeout(Duration::from_secs(1))
        .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
        .foreign_keys(true)
        .synchronous(sqlx::sqlite::SqliteSynchronous::Normal);
    pollster::block_on(async {
        let pool = SqlitePoolOptions::new()
            .max_connections(10)
            .connect_with(options)
            .await?;
        sqlx::migrate!("./migrations").run(&pool).await?;
        Ok::<_, anyhow::Error>(pool)
    })
    .expect("failed to initialize database")
};

pub async fn event_loop(ctx: &AnyCtx<Config>) {
    (login_event_loop(ctx), message_event_loop(ctx))
        .race()
        .await;
}

async fn login_event_loop(ctx: &AnyCtx<Config>) {
    let db = ctx.get(DATABASE);
    let mut notify = DbNotify::new();
    let mut logged_in = loop {
        match identity_exists(db).await {
            Ok(value) => break value,
            Err(err) => {
                tracing::warn!(error = %err, "failed to check identity state");
            }
        }
    };
    emit_event(ctx, Event::State { logged_in });
    loop {
        notify.wait_for_change().await;
        let next_logged_in = match identity_exists(db).await {
            Ok(value) => value,
            Err(err) => {
                tracing::warn!(error = %err, "failed to check identity state");
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
    let mut last_seen_id = current_max_msg(db).await.unwrap_or(0);
    let mut last_seen_received_at = current_max_received_at(db).await.unwrap_or(0);
    let mut last_seen_read_rowid = current_max_read_rowid(db).await.unwrap_or(0);
    let mut group_versions = load_group_versions(db).await.unwrap_or_default();
    loop {
        notify.wait_for_change().await;
        let (new_last, mut convos) = match new_message_convos(db, last_seen_id).await {
            Ok(result) => result,
            Err(err) => {
                tracing::warn!(error = %err, "failed to query convo messages");
                continue;
            }
        };
        last_seen_id = new_last;
        let (new_received_at, received_convos) =
            match new_received_convos(db, last_seen_received_at).await {
                Ok(result) => result,
                Err(err) => {
                    tracing::warn!(error = %err, "failed to query convo received_at updates");
                    continue;
                }
            };
        last_seen_received_at = new_received_at;
        convos.extend(received_convos);
        let (new_read_rowid, read_convos) = match new_read_convos(db, last_seen_read_rowid).await {
            Ok(result) => result,
            Err(err) => {
                tracing::warn!(error = %err, "failed to query convo read updates");
                continue;
            }
        };
        last_seen_read_rowid = new_read_rowid;
        convos.extend(read_convos);
        for convo_id in convos {
            emit_event(ctx, Event::ConvoUpdated { convo_id });
        }
        let (next_versions, roster_groups) = match updated_group_versions(db, &group_versions).await
        {
            Ok(result) => result,
            Err(err) => {
                tracing::warn!(error = %err, "failed to query group roster updates");
                continue;
            }
        };
        group_versions = next_versions;
        for group in roster_groups {
            emit_event(ctx, Event::GroupUpdated { group });
        }
    }
}

pub async fn identity_exists(db: &sqlx::SqlitePool) -> anyhow::Result<bool> {
    let row = sqlx::query_as::<_, (i64,)>("SELECT 1 FROM client_identity WHERE id = 1")
        .fetch_optional(db)
        .await?;
    Ok(row.is_some())
}

async fn current_max_msg(db: &sqlx::SqlitePool) -> anyhow::Result<i64> {
    let row = sqlx::query_as::<_, (Option<i64>,)>("SELECT MAX(id) FROM convo_messages")
        .fetch_one(db)
        .await?;
    Ok(row.0.unwrap_or(0))
}

async fn current_max_received_at(db: &sqlx::SqlitePool) -> anyhow::Result<i64> {
    let row = sqlx::query_as::<_, (Option<i64>,)>(
        "SELECT MAX(received_at) FROM convo_messages WHERE received_at IS NOT NULL",
    )
    .fetch_one(db)
    .await?;
    Ok(row.0.unwrap_or(0))
}

async fn current_max_read_rowid(db: &sqlx::SqlitePool) -> anyhow::Result<i64> {
    let row = sqlx::query_as::<_, (Option<i64>,)>("SELECT MAX(rowid) FROM message_reads")
        .fetch_one(db)
        .await?;
    Ok(row.0.unwrap_or(0))
}

async fn new_message_convos(
    db: &sqlx::SqlitePool,
    last_seen_id: i64,
) -> anyhow::Result<(i64, Vec<crate::convo::ConvoId>)> {
    let rows = sqlx::query_as::<_, (i64, String, String)>(
        "SELECT m.id, c.convo_type, c.convo_counterparty \
         FROM convo_messages m \
         JOIN convos c ON m.convo_id = c.id \
         WHERE m.id > ? \
         ORDER BY m.id",
    )
    .bind(last_seen_id)
    .fetch_all(db)
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
    db: &sqlx::SqlitePool,
    last_seen_received_at: i64,
) -> anyhow::Result<(i64, Vec<crate::convo::ConvoId>)> {
    let rows = sqlx::query_as::<_, (i64, String, String)>(
        "SELECT m.received_at, c.convo_type, c.convo_counterparty \
         FROM convo_messages m \
         JOIN convos c ON m.convo_id = c.id \
         WHERE m.received_at IS NOT NULL AND m.received_at > ? \
         ORDER BY m.received_at",
    )
    .bind(last_seen_received_at)
    .fetch_all(db)
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
    db: &sqlx::SqlitePool,
    last_seen_rowid: i64,
) -> anyhow::Result<(i64, Vec<crate::convo::ConvoId>)> {
    let rows = sqlx::query_as::<_, (i64, String, String)>(
        "SELECT mr.rowid, c.convo_type, c.convo_counterparty \
         FROM message_reads mr \
         JOIN convo_messages m ON m.id = mr.message_id \
         JOIN convos c ON m.convo_id = c.id \
         WHERE mr.rowid > ? \
         ORDER BY mr.rowid",
    )
    .bind(last_seen_rowid)
    .fetch_all(db)
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

async fn load_group_versions(db: &sqlx::SqlitePool) -> anyhow::Result<HashMap<GroupId, i64>> {
    let rows = sqlx::query_as::<_, (Vec<u8>, i64)>("SELECT group_id, roster_version FROM groups")
        .fetch_all(db)
        .await?;
    let mut out = HashMap::new();
    for (group_id, roster_version) in rows {
        let Ok(group_id) = <[u8; 32]>::try_from(group_id.as_slice()).map(GroupId::from_bytes)
        else {
            continue;
        };
        out.insert(group_id, roster_version);
    }
    Ok(out)
}

async fn updated_group_versions(
    db: &sqlx::SqlitePool,
    known: &HashMap<GroupId, i64>,
) -> anyhow::Result<(HashMap<GroupId, i64>, Vec<GroupId>)> {
    let current = load_group_versions(db).await?;
    if current.is_empty() {
        return Ok((current, Vec::new()));
    }
    let mut updated = Vec::new();
    for (group_id, roster_version) in &current {
        match known.get(group_id) {
            Some(prev) if *prev >= *roster_version => {}
            _ => updated.push(*group_id),
        }
    }
    Ok((current, updated))
}

pub async fn ensure_mailbox_state<'e, E>(
    exec: E,
    server_name: &nullspace_structs::server::ServerName,
    mailbox: MailboxId,
    initial_after: NanoTimestamp,
) -> anyhow::Result<()>
where
    E: Executor<'e, Database = Sqlite>,
{
    sqlx::query(
        "INSERT OR IGNORE INTO mailbox_state (server_name, mailbox_id, after_timestamp) \
         VALUES (?, ?, ?)",
    )
    .bind(server_name.as_str())
    .bind(mailbox.to_bytes().to_vec())
    .bind(initial_after.0 as i64)
    .execute(exec)
    .await?;
    Ok(())
}

pub async fn load_mailbox_after<'e, E>(
    exec: E,
    server_name: &nullspace_structs::server::ServerName,
    mailbox: MailboxId,
) -> anyhow::Result<NanoTimestamp>
where
    E: Executor<'e, Database = Sqlite>,
{
    let row = sqlx::query_as::<_, (i64,)>(
        "SELECT after_timestamp FROM mailbox_state \
         WHERE server_name = ? AND mailbox_id = ?",
    )
    .bind(server_name.as_str())
    .bind(mailbox.to_bytes().to_vec())
    .fetch_optional(exec)
    .await?;
    Ok(row
        .map(|(after,)| NanoTimestamp(after as u64))
        .unwrap_or(NanoTimestamp(0)))
}

pub async fn update_mailbox_after<'e, E>(
    exec: E,
    server_name: &nullspace_structs::server::ServerName,
    mailbox: MailboxId,
    after: NanoTimestamp,
) -> anyhow::Result<()>
where
    E: Executor<'e, Database = Sqlite>,
{
    sqlx::query(
        "UPDATE mailbox_state SET after_timestamp = ? \
         WHERE server_name = ? AND mailbox_id = ?",
    )
    .bind(after.0 as i64)
    .bind(server_name.as_str())
    .bind(mailbox.to_bytes().to_vec())
    .execute(exec)
    .await?;
    Ok(())
}

pub async fn ensure_convo_id<'e, E>(
    exec: E,
    convo_type: &str,
    counterparty: &str,
) -> anyhow::Result<i64>
where
    E: Executor<'e, Database = Sqlite>,
{
    let created_at = NanoTimestamp::now().0 as i64;
    let row = sqlx::query_as::<_, (i64,)>(
        "INSERT INTO convos (convo_type, convo_counterparty, created_at) \
         VALUES (?, ?, ?) \
         ON CONFLICT(convo_type, convo_counterparty) DO UPDATE \
         SET convo_type = excluded.convo_type \
         RETURNING id",
    )
    .bind(convo_type)
    .bind(counterparty)
    .bind(created_at)
    .fetch_one(exec)
    .await?;
    Ok(row.0)
}
