use std::{path::Path, time::Duration};

use sqlx::{SqlitePool, sqlite::SqliteConnectOptions};
use xirtam_crypt::hash::Hash;
use xirtam_structs::directory::{DirectoryChunk, DirectoryHeader, PowSeed};

pub async fn init_sqlite(db_dir: &Path) -> anyhow::Result<SqlitePool> {
    let path = db_dir.join("directory.db");
    let options = SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(true)
        .busy_timeout(Duration::from_secs(5));
    let pool = SqlitePool::connect_with(options).await?;
    sqlx::migrate!("./migrations").run(&pool).await?;
    Ok(pool)
}

pub async fn insert_pow_seed(pool: &SqlitePool, seed: &PowSeed, effort: u64) -> anyhow::Result<()> {
    sqlx::query("INSERT OR REPLACE INTO pow_seeds (seed, use_before, effort) VALUES (?, ?, ?)")
        .bind(seed.seed.to_bytes().to_vec())
        .bind(seed.use_before.0 as i64)
        .bind(effort as i64)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn fetch_pow_seed(pool: &SqlitePool, seed: &Hash) -> anyhow::Result<Option<(u64, u64)>> {
    let row =
        sqlx::query_as::<_, (i64, i64)>("SELECT use_before, effort FROM pow_seeds WHERE seed = ?")
            .bind(seed.to_bytes().to_vec())
            .fetch_optional(pool)
            .await?;
    Ok(row.map(|(use_before, effort)| (use_before as u64, effort as u64)))
}

pub async fn purge_pow_seeds(pool: &SqlitePool, now: u64) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM pow_seeds WHERE use_before < ?")
        .bind(now as i64)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn load_last_header(pool: &SqlitePool) -> anyhow::Result<Option<(u64, DirectoryHeader)>> {
    let row =
        sqlx::query_as::<_, (i64, Vec<u8>)>("SELECT height, header FROM headers ORDER BY height DESC LIMIT 1")
            .fetch_optional(pool)
            .await?;
    match row {
        Some((height, header_bytes)) => {
            let header: DirectoryHeader = bcs::from_bytes(&header_bytes)?;
            Ok(Some((height as u64, header)))
        }
        None => Ok(None),
    }
}

pub async fn insert_chunk(
    pool: &SqlitePool,
    height: u64,
    header: &DirectoryHeader,
    header_hash: &Hash,
    chunk: &DirectoryChunk,
) -> anyhow::Result<()> {
    let header_bytes = bcs::to_bytes(header)?;
    let chunk_bytes = bcs::to_bytes(chunk)?;
    let mut tx = pool.begin().await?;
    sqlx::query("INSERT INTO headers (height, header, header_hash) VALUES (?, ?, ?)")
        .bind(height as i64)
        .bind(header_bytes)
        .bind(header_hash.to_bytes().to_vec())
        .execute(&mut *tx)
        .await?;

    sqlx::query("INSERT INTO chunks (height, chunk_blob) VALUES (?, ?)")
        .bind(height as i64)
        .bind(chunk_bytes)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;
    Ok(())
}

pub async fn load_headers(
    pool: &SqlitePool,
    first: u64,
    last: u64,
) -> anyhow::Result<Vec<DirectoryHeader>> {
    let rows = sqlx::query_scalar::<_, Vec<u8>>(
        "SELECT header FROM headers WHERE height >= ? AND height <= ? ORDER BY height ASC",
    )
    .bind(first as i64)
    .bind(last as i64)
    .fetch_all(pool)
    .await?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        out.push(bcs::from_bytes(&row)?);
    }
    tracing::debug!("loading headers from {first} to {last}");
    Ok(out)
}

pub async fn load_chunk(pool: &SqlitePool, height: u64) -> anyhow::Result<Option<DirectoryChunk>> {
    let data = sqlx::query_scalar::<_, Vec<u8>>("SELECT chunk_blob FROM chunks WHERE height = ?")
        .bind(height as i64)
        .fetch_optional(pool)
        .await?;
    match data {
        Some(data) => Ok(Some(bcs::from_bytes(&data)?)),
        None => Ok(None),
    }
}
