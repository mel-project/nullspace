use nanorpc::DynRpcTransport;
use nullspace_crypt::hash::Hash;
use nullspace_structs::directory::{DirectoryAnchor, DirectoryClient, DirectoryHeader};
use sqlx::SqlitePool;
use tokio::sync::Semaphore;
use tracing::debug;

const BATCH_LIMIT: u64 = 1_000;

pub async fn max_stored_height(pool: &SqlitePool) -> anyhow::Result<Option<u64>> {
    let height = sqlx::query_scalar::<_, Option<i64>>("SELECT MAX(height) FROM _dirclient_headers")
        .fetch_one(pool)
        .await?
        .map(|s| s as u64);
    Ok(height)
}

pub async fn load_header(pool: &SqlitePool, height: u64) -> anyhow::Result<DirectoryHeader> {
    let data =
        sqlx::query_scalar::<_, Vec<u8>>("SELECT header FROM _dirclient_headers WHERE height = ?")
            .bind(height as i64)
            .fetch_optional(pool)
            .await?;
    let Some(data) = data else {
        anyhow::bail!("missing header {}", height);
    };
    Ok(bcs::from_bytes(&data)?)
}

async fn load_header_hash(pool: &SqlitePool, height: u64) -> anyhow::Result<Option<Hash>> {
    let data = sqlx::query_scalar::<_, Vec<u8>>(
        "SELECT header_hash FROM _dirclient_headers WHERE height = ?",
    )
    .bind(height as i64)
    .fetch_optional(pool)
    .await?;
    Ok(data.map(|bytes| {
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&bytes);
        Hash::from_bytes(buf)
    }))
}

pub async fn sync_headers(
    raw: &DirectoryClient<DynRpcTransport>,
    pool: &SqlitePool,
    anchor: &DirectoryAnchor,
) -> anyhow::Result<()> {
    // use a semaphore to enforce one sync at a time to prevent futile fetches
    static SEMAPHORE: Semaphore = Semaphore::const_new(1);
    let _guard = SEMAPHORE.acquire().await?;

    let mut current = max_stored_height(pool).await?;

    let mut prev_hash = match current {
        Some(current) => load_header_hash(pool, current).await?.expect("gap"),
        None => Hash::from_bytes([0u8; 32]),
    };

    let mut next = match current {
        Some(current) => current + 1,
        None => 0,
    };
    while next <= anchor.last_header_height {
        let end = (next + BATCH_LIMIT - 1).min(anchor.last_header_height);
        debug!(from = next, to = end, "syncing directory headers");
        let headers = raw
            .v1_get_headers(next, end)
            .await?
            .map_err(|err| anyhow::anyhow!(err.to_string()))?;
        let expected_len = (end - next + 1) as usize;
        if headers.len() != expected_len {
            anyhow::bail!(
                "header range incomplete, got {} instead of {expected_len}",
                headers.len()
            );
        }

        let mut staged = Vec::with_capacity(headers.len());
        let mut expected_prev = prev_hash;
        for (offset, header) in headers.iter().enumerate() {
            if header.prev != expected_prev {
                anyhow::bail!(
                    "header chain mismatch at height {}, expected prev {}, got {}",
                    next + offset as u64,
                    expected_prev,
                    header.prev
                );
            }
            let data = bcs::to_bytes(header)?;
            let hash = Hash::digest(&data);
            staged.push((next + offset as u64, data, hash));
            expected_prev = hash;
        }

        let mut tx = pool.begin().await?;
        for (height, data, hash) in staged {
            sqlx::query(
                "INSERT OR REPLACE INTO _dirclient_headers (height, header, header_hash) VALUES (?, ?, ?)",
            )
            .bind(height as i64)
            .bind(data)
            .bind(hash.to_bytes().to_vec())
            .execute(&mut *tx)
            .await?;
            prev_hash = hash;
            current = Some(height);
        }
        tx.commit().await?;
        debug!(height = current, "synced directory headers batch");
        next = end + 1;
    }

    if prev_hash != anchor.last_header_hash {
        anyhow::bail!(
            "header chain mismatch at anchor {}, expected {}, got {}",
            anchor.last_header_height,
            anchor.last_header_hash,
            prev_hash
        );
    }
    Ok(())
}
