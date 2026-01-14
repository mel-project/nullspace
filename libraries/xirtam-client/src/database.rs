use std::time::Duration;

use anyctx::AnyCtx;
use async_channel::Sender as AsyncSender;
use futures_concurrency::future::Race;
use sqlx::SqlitePool;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use xirtam_structs::gateway::MailboxId;
use xirtam_structs::group::GroupId;
use xirtam_structs::handle::Handle;
use xirtam_structs::timestamp::NanoTimestamp;

use crate::Config;
use crate::config::Ctx;
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
        .busy_timeout(Duration::from_secs(60))
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

pub async fn event_loop(ctx: &AnyCtx<Config>, event_tx: AsyncSender<Event>) {
    (
        login_event_loop(ctx, event_tx.clone()),
        message_event_loop(ctx, event_tx),
    )
        .race()
        .await;
}

async fn login_event_loop(ctx: &AnyCtx<Config>, event_tx: AsyncSender<Event>) {
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
    if event_tx.send(Event::State { logged_in }).await.is_err() {
        return;
    }
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
            if event_tx.send(Event::State { logged_in }).await.is_err() {
                return;
            }
        }
    }
}

async fn message_event_loop(ctx: &AnyCtx<Config>, event_tx: AsyncSender<Event>) {
    let db = ctx.get(DATABASE);
    let mut notify = DbNotify::new();
    let mut last_seen_id = current_max_msg(db).await.unwrap_or(0);
    let mut last_seen_received_at = current_max_received_at(db).await.unwrap_or(0);
    let mut last_seen_group_id = current_max_group_msg(db).await.unwrap_or(0);
    let mut last_seen_group_received_at = current_max_group_received_at(db).await.unwrap_or(0);
    let mut group_versions = load_group_versions(db).await.unwrap_or_default();
    loop {
        notify.wait_for_change().await;
        let (new_last, mut peers) = match new_message_peers(db, last_seen_id).await {
            Ok(result) => result,
            Err(err) => {
                tracing::warn!(error = %err, "failed to query dm messages");
                continue;
            }
        };
        last_seen_id = new_last;
        let (new_received_at, received_peers) =
            match new_received_peers(db, last_seen_received_at).await {
                Ok(result) => result,
                Err(err) => {
                    tracing::warn!(error = %err, "failed to query dm received_at updates");
                    continue;
                }
            };
        last_seen_received_at = new_received_at;
        peers.extend(received_peers);
        for peer in peers {
            if event_tx.send(Event::DmUpdated { peer }).await.is_err() {
                return;
            }
        }

        let (new_group_last, mut groups) = match new_group_message_ids(db, last_seen_group_id).await
        {
            Ok(result) => result,
            Err(err) => {
                tracing::warn!(error = %err, "failed to query group messages");
                continue;
            }
        };
        last_seen_group_id = new_group_last;
        let (new_group_received, received_groups) =
            match new_group_received_ids(db, last_seen_group_received_at).await {
                Ok(result) => result,
                Err(err) => {
                    tracing::warn!(error = %err, "failed to query group received_at updates");
                    continue;
                }
            };
        last_seen_group_received_at = new_group_received;
        groups.extend(received_groups);
        let (next_versions, roster_groups) = match updated_group_versions(db, &group_versions).await
        {
            Ok(result) => result,
            Err(err) => {
                tracing::warn!(error = %err, "failed to query group roster updates");
                continue;
            }
        };
        group_versions = next_versions;
        groups.extend(roster_groups);
        for group in groups {
            if event_tx.send(Event::GroupUpdated { group }).await.is_err() {
                return;
            }
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
    let row = sqlx::query_as::<_, (Option<i64>,)>("SELECT MAX(id) FROM dm_messages")
        .fetch_one(db)
        .await?;
    Ok(row.0.unwrap_or(0))
}

async fn current_max_received_at(db: &sqlx::SqlitePool) -> anyhow::Result<i64> {
    let row = sqlx::query_as::<_, (Option<i64>,)>(
        "SELECT MAX(received_at) FROM dm_messages WHERE received_at IS NOT NULL",
    )
    .fetch_one(db)
    .await?;
    Ok(row.0.unwrap_or(0))
}

async fn new_message_peers(
    db: &sqlx::SqlitePool,
    last_seen_id: i64,
) -> anyhow::Result<(i64, Vec<Handle>)> {
    let rows = sqlx::query_as::<_, (i64, String)>(
        "SELECT id, peer_handle FROM dm_messages WHERE id > ? ORDER BY id",
    )
    .bind(last_seen_id)
    .fetch_all(db)
    .await?;
    if rows.is_empty() {
        return Ok((last_seen_id, Vec::new()));
    }
    let mut peers = HashSet::new();
    let mut max_id = last_seen_id;
    for (id, peer_handle) in rows {
        max_id = max_id.max(id);
        if let Ok(peer) = Handle::parse(peer_handle) {
            peers.insert(peer);
        }
    }
    Ok((max_id, peers.into_iter().collect()))
}

async fn new_received_peers(
    db: &sqlx::SqlitePool,
    last_seen_received_at: i64,
) -> anyhow::Result<(i64, Vec<Handle>)> {
    let rows = sqlx::query_as::<_, (i64, String)>(
        "SELECT received_at, peer_handle FROM dm_messages \
         WHERE received_at IS NOT NULL AND received_at > ? \
         ORDER BY received_at",
    )
    .bind(last_seen_received_at)
    .fetch_all(db)
    .await?;
    if rows.is_empty() {
        return Ok((last_seen_received_at, Vec::new()));
    }
    let mut peers = HashSet::new();
    let mut max_received_at = last_seen_received_at;
    for (received_at, peer_handle) in rows {
        max_received_at = max_received_at.max(received_at);
        if let Ok(peer) = Handle::parse(peer_handle) {
            peers.insert(peer);
        }
    }
    Ok((max_received_at, peers.into_iter().collect()))
}

async fn current_max_group_msg(db: &sqlx::SqlitePool) -> anyhow::Result<i64> {
    let row = sqlx::query_as::<_, (Option<i64>,)>("SELECT MAX(id) FROM group_messages")
        .fetch_one(db)
        .await?;
    Ok(row.0.unwrap_or(0))
}

async fn current_max_group_received_at(db: &sqlx::SqlitePool) -> anyhow::Result<i64> {
    let row = sqlx::query_as::<_, (Option<i64>,)>(
        "SELECT MAX(received_at) FROM group_messages WHERE received_at IS NOT NULL",
    )
    .fetch_one(db)
    .await?;
    Ok(row.0.unwrap_or(0))
}

async fn new_group_message_ids(
    db: &sqlx::SqlitePool,
    last_seen_id: i64,
) -> anyhow::Result<(i64, Vec<GroupId>)> {
    let rows = sqlx::query_as::<_, (i64, Vec<u8>)>(
        "SELECT id, group_id FROM group_messages WHERE id > ? ORDER BY id",
    )
    .bind(last_seen_id)
    .fetch_all(db)
    .await?;
    if rows.is_empty() {
        return Ok((last_seen_id, Vec::new()));
    }
    let mut groups = HashSet::new();
    let mut max_id = last_seen_id;
    for (id, group_id) in rows {
        max_id = max_id.max(id);
        let Ok(group_id) = bcs::from_bytes::<GroupId>(&group_id) else {
            continue;
        };
        groups.insert(group_id);
    }
    Ok((max_id, groups.into_iter().collect()))
}

async fn new_group_received_ids(
    db: &sqlx::SqlitePool,
    last_seen_received_at: i64,
) -> anyhow::Result<(i64, Vec<GroupId>)> {
    let rows = sqlx::query_as::<_, (i64, Vec<u8>)>(
        "SELECT received_at, group_id FROM group_messages \
         WHERE received_at IS NOT NULL AND received_at > ? \
         ORDER BY received_at",
    )
    .bind(last_seen_received_at)
    .fetch_all(db)
    .await?;
    if rows.is_empty() {
        return Ok((last_seen_received_at, Vec::new()));
    }
    let mut groups = HashSet::new();
    let mut max_received_at = last_seen_received_at;
    for (received_at, group_id) in rows {
        max_received_at = max_received_at.max(received_at);
        let Ok(group_id) = bcs::from_bytes::<GroupId>(&group_id) else {
            continue;
        };
        groups.insert(group_id);
    }
    Ok((max_received_at, groups.into_iter().collect()))
}

async fn load_group_versions(db: &sqlx::SqlitePool) -> anyhow::Result<HashMap<GroupId, i64>> {
    let rows = sqlx::query_as::<_, (Vec<u8>, i64)>("SELECT group_id, roster_version FROM groups")
        .fetch_all(db)
        .await?;
    let mut out = HashMap::new();
    for (group_id, roster_version) in rows {
        let Ok(group_id) = bcs::from_bytes::<GroupId>(&group_id) else {
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

pub async fn ensure_mailbox_state(
    db: &sqlx::SqlitePool,
    gateway_name: &xirtam_structs::gateway::GatewayName,
    mailbox: MailboxId,
    initial_after: NanoTimestamp,
) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT OR IGNORE INTO mailbox_state (gateway_name, mailbox_id, after_timestamp) \
         VALUES (?, ?, ?)",
    )
    .bind(gateway_name.as_str())
    .bind(mailbox.to_bytes().to_vec())
    .bind(initial_after.0 as i64)
    .execute(db)
    .await?;
    Ok(())
}

pub async fn load_mailbox_after(
    db: &sqlx::SqlitePool,
    gateway_name: &xirtam_structs::gateway::GatewayName,
    mailbox: MailboxId,
) -> anyhow::Result<NanoTimestamp> {
    let row = sqlx::query_as::<_, (i64,)>(
        "SELECT after_timestamp FROM mailbox_state \
         WHERE gateway_name = ? AND mailbox_id = ?",
    )
    .bind(gateway_name.as_str())
    .bind(mailbox.to_bytes().to_vec())
    .fetch_optional(db)
    .await?;
    Ok(row
        .map(|(after,)| NanoTimestamp(after as u64))
        .unwrap_or(NanoTimestamp(0)))
}

pub async fn update_mailbox_after(
    db: &sqlx::SqlitePool,
    gateway_name: &xirtam_structs::gateway::GatewayName,
    mailbox: MailboxId,
    after: NanoTimestamp,
) -> anyhow::Result<()> {
    sqlx::query(
        "UPDATE mailbox_state SET after_timestamp = ? \
         WHERE gateway_name = ? AND mailbox_id = ?",
    )
    .bind(after.0 as i64)
    .bind(gateway_name.as_str())
    .bind(mailbox.to_bytes().to_vec())
    .execute(db)
    .await?;
    Ok(())
}
