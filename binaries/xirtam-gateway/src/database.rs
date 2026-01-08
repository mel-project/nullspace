use std::{sync::LazyLock, time::Duration};

use sqlx::{
    SqlitePool,
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
};

use crate::config::CONFIG;

pub static DATABASE: LazyLock<SqlitePool> = LazyLock::new(|| {
    let options = SqliteConnectOptions::new()
        .filename(&CONFIG.db_path)
        .create_if_missing(true)
        .busy_timeout(Duration::from_secs(5))
        .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
        .foreign_keys(true)
        .synchronous(sqlx::sqlite::SqliteSynchronous::Normal);
    pollster::block_on(async {
        let pool = SqlitePoolOptions::new()
            .max_connections(500)
            .connect_with(options)
            .await?;
        sqlx::migrate!("./migrations").run(&pool).await?;
        Ok::<_, anyhow::Error>(pool)
    })
    .expect("failed to initialize database")
});
