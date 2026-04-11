use nanorpc::DynRpcTransport;
use nullspace_crypt::hash::Hash;
use nullspace_structs::directory::{DirectoryAnchor, DirectoryClient, DirectoryHeader};
use sqlx::SqlitePool;
use tokio::sync::Semaphore;
use tracing::debug;

const BATCH_MIN: u64 = 1;
const BATCH_MAX: u64 = 10_000;
const BATCH_START: u64 = 2_000;
const BATCH_INC: u64 = 500;
const BATCH_DEC_NUM: u64 = 8;
const BATCH_DEC_DEN: u64 = 10;

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
    let mut batch_len = BATCH_START;
    while next <= anchor.last_header_height {
        let end = next
            .saturating_add(batch_len.saturating_sub(1))
            .min(anchor.last_header_height);
        debug!(
            from = next,
            to = end,
            batch_len,
            "syncing directory headers"
        );
        let headers = match raw.get_headers(next, end).await {
            Ok(Ok(headers)) => headers,
            Ok(Err(err)) => {
                let err = anyhow::anyhow!(err.to_string());
                let next_batch_len = aimd_decrease(batch_len);
                if next_batch_len == batch_len {
                    return Err(err);
                }
                debug!(
                    from = next,
                    to = end,
                    old_batch_len = batch_len,
                    new_batch_len = next_batch_len,
                    err = debug(&err),
                    "directory header batch failed"
                );
                batch_len = next_batch_len;
                continue;
            }
            Err(err) => {
                let next_batch_len = aimd_decrease(batch_len);
                if next_batch_len == batch_len {
                    return Err(err.into());
                }
                debug!(
                    from = next,
                    to = end,
                    old_batch_len = batch_len,
                    new_batch_len = next_batch_len,
                    err = debug(&err),
                    "directory header batch failed"
                );
                batch_len = next_batch_len;
                continue;
            }
        };
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
        debug!(
            height = current,
            batch_len, "synced directory headers batch"
        );
        next = end + 1;
        batch_len = aimd_increase(batch_len);
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

fn aimd_increase(current: u64) -> u64 {
    current
        .saturating_add(BATCH_INC)
        .clamp(BATCH_MIN, BATCH_MAX)
}

fn aimd_decrease(current: u64) -> u64 {
    current
        .saturating_mul(BATCH_DEC_NUM)
        .saturating_div(BATCH_DEC_DEN)
        .clamp(BATCH_MIN, BATCH_MAX)
}

#[cfg(test)]
mod tests {
    use super::{BATCH_INC, BATCH_MAX, BATCH_MIN, aimd_decrease, aimd_increase};

    #[test]
    fn aimd_increase_adds_inc_until_cap() {
        assert_eq!(aimd_increase(BATCH_MIN), BATCH_MIN + BATCH_INC);
        assert_eq!(aimd_increase(BATCH_MAX), BATCH_MAX);
    }

    #[test]
    fn aimd_decrease_scales_down_and_floors_at_one() {
        assert_eq!(aimd_decrease(100), 80);
        assert_eq!(aimd_decrease(5), 4);
        assert_eq!(aimd_decrease(BATCH_MIN), BATCH_MIN);
    }
}
