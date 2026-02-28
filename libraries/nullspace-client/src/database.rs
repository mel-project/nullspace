use std::time::Duration;

use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::SqlitePool;

use crate::config::Ctx;
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
        .pragma("secure_delete", "ON")
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
