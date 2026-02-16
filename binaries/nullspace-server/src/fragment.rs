use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::time::Duration;

use nullspace_crypt::hash::{BcsHashExt, Hash};
use nullspace_structs::fragment::Fragment;
use nullspace_structs::server::{AuthToken, ServerRpcError};
use nullspace_structs::timestamp::NanoTimestamp;
use sqlx::{Sqlite, Transaction};

use crate::config::CONFIG;
use crate::database::DATABASE;
use crate::{device, fatal_retry_later};

pub static FRAGMENTS: LazyLock<FragmentDb> = LazyLock::new(|| {
    let db = FragmentDb::new(CONFIG.fragments_path.clone());
    start_janitor(db.root.clone());
    db
});

pub struct FragmentDb {
    root: PathBuf,
}

impl FragmentDb {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    fn path_for_hash(&self, hash: &Hash) -> PathBuf {
        let hex = hash.to_string();
        let xx = &hex[0..2];
        let yy = &hex[2..4];
        self.root.join(xx).join(yy).join(format!("{hex}.frag"))
    }

    async fn ensure_parent_dir(path: &Path) -> Result<(), ServerRpcError> {
        let Some(parent) = path.parent() else {
            return Err(fatal_retry_later("invalid fragment path"));
        };
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(fatal_retry_later)?;
        Ok(())
    }

    async fn store_bcs_bytes(&self, hash: &Hash, bytes: &[u8]) -> Result<(), ServerRpcError> {
        let path = self.path_for_hash(hash);
        Self::ensure_parent_dir(&path).await?;
        tokio::fs::write(&path, bytes)
            .await
            .map_err(fatal_retry_later)?;
        Ok(())
    }

    pub async fn load(&self, hash: Hash) -> Result<Option<Fragment>, ServerRpcError> {
        let path = self.path_for_hash(&hash);
        let bytes = match tokio::fs::read(&path).await {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(fatal_retry_later(err)),
        };
        let frag: Fragment =
            bcs::from_bytes(&bytes).map_err(|_| fatal_retry_later("invalid fragment bcs"))?;
        Ok(Some(frag))
    }
}

pub async fn upload_frag(auth: AuthToken, frag: Fragment, ttl: u32) -> Result<(), ServerRpcError> {
    if !device::auth_token_exists(auth).await? {
        return Err(ServerRpcError::AccessDenied);
    }

    let now = NanoTimestamp::now();
    let hash = frag.bcs_hash();
    let bytes = bcs::to_bytes(&frag).map_err(|_| fatal_retry_later("fragment bcs encode"))?;
    let size = i64::try_from(bytes.len()).map_err(|_| fatal_retry_later("fragment too large"))?;
    let expires_at = expires_at_from_ttl(now, ttl);

    FRAGMENTS.store_bcs_bytes(&hash, &bytes).await?;

    let mut tx = DATABASE.begin().await.map_err(fatal_retry_later)?;
    upsert_fragment_row(&mut tx, hash, now, expires_at, size).await?;
    tx.commit().await.map_err(fatal_retry_later)?;

    Ok(())
}

pub async fn download_frag(hash: Hash) -> Result<Option<Fragment>, ServerRpcError> {
    // Intentionally avoids hitting SQLite; the janitor is responsible for deleting expired items.
    FRAGMENTS.load(hash).await
}

fn expires_at_from_ttl(now: NanoTimestamp, ttl: u32) -> Option<i64> {
    if ttl == 0 {
        return None;
    }
    let ttl_ns = u64::from(ttl).saturating_mul(1_000_000_000);
    Some(now.0.saturating_add(ttl_ns) as i64)
}

async fn upsert_fragment_row(
    tx: &mut Transaction<'_, Sqlite>,
    hash: Hash,
    created_at: NanoTimestamp,
    expires_at: Option<i64>,
    size: i64,
) -> Result<(), ServerRpcError> {
    sqlx::query(
        "INSERT INTO fragments (hash, created_at, expires_at, size) \
         VALUES (?, ?, ?, ?) \
         ON CONFLICT(hash) DO UPDATE SET \
           expires_at = ( \
             CASE \
               WHEN fragments.expires_at IS NULL OR excluded.expires_at IS NULL THEN NULL \
               WHEN fragments.expires_at > excluded.expires_at THEN fragments.expires_at \
               ELSE excluded.expires_at \
             END \
           ), \
           size = excluded.size",
    )
    .bind(hash.to_bytes().to_vec())
    .bind(created_at.0 as i64)
    .bind(expires_at)
    .bind(size)
    .execute(tx.as_mut())
    .await
    .map_err(fatal_retry_later)?;
    Ok(())
}

fn start_janitor(root: PathBuf) {
    tokio::spawn(async move {
        loop {
            let now = NanoTimestamp::now();
            if let Err(err) = janitor_once(&root, now).await {
                tracing::error!(error = %err, "fragment janitor error");
            }
            tokio::time::sleep(Duration::from_secs(60)).await;
        }
    });
}

async fn janitor_once(root: &Path, now: NanoTimestamp) -> Result<(), ServerRpcError> {
    const BATCH: usize = 500;

    loop {
        let mut tx = DATABASE.begin().await.map_err(fatal_retry_later)?;
        let rows = sqlx::query_as::<_, (Vec<u8>,)>(
            "SELECT hash FROM fragments \
             WHERE expires_at IS NOT NULL AND expires_at <= ? \
             LIMIT ?",
        )
        .bind(now.0 as i64)
        .bind(i64::try_from(BATCH).unwrap())
        .fetch_all(tx.as_mut())
        .await
        .map_err(fatal_retry_later)?;

        if rows.is_empty() {
            tx.commit().await.map_err(fatal_retry_later)?;
            return Ok(());
        }

        for (hash_bytes,) in &rows {
            let buf: [u8; 32] = hash_bytes
                .as_slice()
                .try_into()
                .map_err(|_| fatal_retry_later("invalid fragment hash length"))?;
            let hash = Hash::from_bytes(buf);

            sqlx::query("DELETE FROM fragments WHERE hash = ?")
                .bind(hash.to_bytes().to_vec())
                .execute(tx.as_mut())
                .await
                .map_err(fatal_retry_later)?;

            let path = path_for_hash(root, &hash);
            match tokio::fs::remove_file(&path).await {
                Ok(()) => {}
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => {
                    tracing::warn!(
                        error = %err,
                        path = %path.display(),
                        "failed to delete fragment file"
                    );
                }
            }
        }

        tx.commit().await.map_err(fatal_retry_later)?;
    }
}

fn path_for_hash(root: &Path, hash: &Hash) -> PathBuf {
    let hex = hash.to_string();
    let xx = &hex[0..2];
    let yy = &hex[2..4];
    root.join(xx).join(yy).join(format!("{hex}.frag"))
}
