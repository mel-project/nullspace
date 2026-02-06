use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Instant;

use anyhow::Context;
use futures_concurrency::future::TryJoin;
use nullspace_crypt::hash::{BcsHashExt, Hash};
use nullspace_structs::certificate::CertificateChain;
use nullspace_structs::server::{ServerClient, ServerName, SignedMediumPk};
use nullspace_structs::username::{UserDescriptor, UserName};
use tracing::warn;

use crate::config::Config;
use crate::database::DATABASE;
use crate::directory::DIR_CLIENT;
use crate::server::get_server_client;

pub struct UserInfo {
    pub username: UserName,
    pub server: Arc<ServerClient>,
    pub server_name: ServerName,
    pub device_chains: BTreeMap<Hash, CertificateChain>,
    pub medium_pks: BTreeMap<Hash, SignedMediumPk>,
}

const USER_CACHE_TTL_SECONDS: i64 = 60;

pub async fn get_user_descriptor(
    ctx: &anyctx::AnyCtx<Config>,
    username: &UserName,
) -> anyhow::Result<UserDescriptor> {
    let db = ctx.get(DATABASE);
    if let Some((descriptor, fetched_at)) = load_cached_descriptor(db, username).await?
        && is_fresh(fetched_at) {
            return Ok(descriptor);
        }

    let dir = ctx.get(DIR_CLIENT);
    let descriptor = dir
        .get_user_descriptor(username)
        .await?
        .context("username not in directory")?;
    store_cached_descriptor(db, username, &descriptor).await?;
    Ok(descriptor)
}

pub async fn get_user_info(
    ctx: &anyctx::AnyCtx<Config>,
    username: &UserName,
) -> anyhow::Result<Arc<UserInfo>> {
    let db = ctx.get(DATABASE);
    let start = Instant::now();
    let descriptor = get_user_descriptor(ctx, username).await?;
    let root_hash = descriptor.root_cert_hash;
    let server = get_server_client(ctx, &descriptor.server_name).await?;

    let mut cached_device_chains = load_cached_device_chains(db, username).await?;
    let mut cached_medium_pks = load_cached_medium_pks(db, username).await?;
    let cached_fetched_at = load_cached_user_info_fetched_at(db, username).await?;
    let cache_fresh = cached_fetched_at.map(is_fresh).unwrap_or(false);

    let should_refresh = !cache_fresh || cached_device_chains.is_empty();

    if should_refresh {
        let (chains, medium_pks) = (
            fetch_chains(&server, username),
            fetch_medium_pks(&server, username),
        )
            .try_join()
            .await?;

        cached_device_chains = chains;
        cached_medium_pks = merge_monotonic_medium_pks(username, cached_medium_pks, medium_pks);
        store_cached_user_info(db, username, &cached_device_chains, &cached_medium_pks).await?;
        tracing::debug!(username=%username, elapsed=debug(start.elapsed()), "refreshed peer info");
    }

    let mut device_chains = BTreeMap::new();
    for (device_hash, chain) in cached_device_chains {
        if chain.verify(root_hash).is_err() {
            warn!(username=%username, device_hash=%device_hash, "invalid device certificate chain");
            continue;
        }
        let chain_hash = chain.last_device().pk.bcs_hash();
        if chain_hash != device_hash {
            warn!(
                username=%username,
                device_hash=%device_hash,
                chain_hash=%chain_hash,
                "device certificate hash mismatch"
            );
            continue;
        }
        device_chains.insert(device_hash, chain);
    }
    if device_chains.is_empty() {
        return Err(anyhow::anyhow!(
            "no valid device certificate chains for {username}"
        ));
    }

    Ok(Arc::new(UserInfo {
        username: username.clone(),
        server,
        server_name: descriptor.server_name.clone(),
        device_chains,
        medium_pks: cached_medium_pks,
    }))
}

pub async fn get_user_root_hash(
    ctx: &anyctx::AnyCtx<Config>,
    username: &UserName,
) -> anyhow::Result<Hash> {
    Ok(get_user_descriptor(ctx, username).await?.root_cert_hash)
}

async fn fetch_chains(
    server: &ServerClient,
    username: &UserName,
) -> anyhow::Result<BTreeMap<Hash, CertificateChain>> {
    server
        .v1_device_certs(username.clone())
        .await?
        .map_err(|err| anyhow::anyhow!(err.to_string()))?
        .context("username has no certificate chains")
}

async fn fetch_medium_pks(
    server: &ServerClient,
    username: &UserName,
) -> anyhow::Result<BTreeMap<Hash, SignedMediumPk>> {
    server
        .v1_device_medium_pks(username.clone())
        .await?
        .map_err(|err| anyhow::anyhow!(err.to_string()))
}

fn is_fresh(fetched_at: i64) -> bool {
    now_seconds().saturating_sub(fetched_at) <= USER_CACHE_TTL_SECONDS
}

fn now_seconds() -> i64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    i64::try_from(now).unwrap_or(i64::MAX)
}

fn merge_monotonic_medium_pks(
    username: &UserName,
    cached: BTreeMap<Hash, SignedMediumPk>,
    fetched: BTreeMap<Hash, SignedMediumPk>,
) -> BTreeMap<Hash, SignedMediumPk> {
    let mut out = cached;
    for (device_hash, medium_pk) in fetched {
        match out.get(&device_hash) {
            Some(existing) if medium_pk.created < existing.created => {
                warn!(
                    username=%username,
                    device_hash=%device_hash,
                    cached_created=existing.created.0,
                    fetched_created=medium_pk.created.0,
                    "medium key timestamp regressed; keeping cached value"
                );
            }
            _ => {
                out.insert(device_hash, medium_pk);
            }
        }
    }
    out
}

async fn load_cached_descriptor(
    db: &sqlx::SqlitePool,
    username: &UserName,
) -> anyhow::Result<Option<(UserDescriptor, i64)>> {
    let row = sqlx::query_as::<_, (Vec<u8>, i64)>(
        "SELECT descriptor, fetched_at FROM user_descriptor_cache WHERE username = ?",
    )
    .bind(username.as_str())
    .fetch_optional(db)
    .await?;
    let Some((descriptor_bytes, fetched_at)) = row else {
        return Ok(None);
    };
    let descriptor = bcs::from_bytes(&descriptor_bytes)?;
    Ok(Some((descriptor, fetched_at)))
}

async fn store_cached_descriptor(
    db: &sqlx::SqlitePool,
    username: &UserName,
    descriptor: &UserDescriptor,
) -> anyhow::Result<()> {
    let data = bcs::to_bytes(descriptor)?;
    sqlx::query(
        "INSERT OR REPLACE INTO user_descriptor_cache (username, descriptor, fetched_at) \
         VALUES (?, ?, ?)",
    )
    .bind(username.as_str())
    .bind(data)
    .bind(now_seconds())
    .execute(db)
    .await?;
    Ok(())
}

async fn load_cached_user_info_fetched_at(
    db: &sqlx::SqlitePool,
    username: &UserName,
) -> anyhow::Result<Option<i64>> {
    let row =
        sqlx::query_scalar::<_, i64>("SELECT fetched_at FROM user_info_cache WHERE username = ?")
            .bind(username.as_str())
            .fetch_optional(db)
            .await?;
    Ok(row)
}

async fn load_cached_device_chains(
    db: &sqlx::SqlitePool,
    username: &UserName,
) -> anyhow::Result<BTreeMap<Hash, CertificateChain>> {
    let row = sqlx::query_scalar::<_, Vec<u8>>(
        "SELECT chains FROM user_device_certs_cache WHERE username = ?",
    )
    .bind(username.as_str())
    .fetch_optional(db)
    .await?;
    let Some(chains_bytes) = row else {
        return Ok(BTreeMap::new());
    };
    let chains = bcs::from_bytes(&chains_bytes)?;
    Ok(chains)
}

async fn load_cached_medium_pks(
    db: &sqlx::SqlitePool,
    username: &UserName,
) -> anyhow::Result<BTreeMap<Hash, SignedMediumPk>> {
    let row = sqlx::query_scalar::<_, Vec<u8>>(
        "SELECT medium_pks FROM user_device_medium_pks_cache WHERE username = ?",
    )
    .bind(username.as_str())
    .fetch_optional(db)
    .await?;
    let Some(medium_pks_bytes) = row else {
        return Ok(BTreeMap::new());
    };
    let medium_pks = bcs::from_bytes(&medium_pks_bytes)?;
    Ok(medium_pks)
}

async fn store_cached_user_info(
    db: &sqlx::SqlitePool,
    username: &UserName,
    device_chains: &BTreeMap<Hash, CertificateChain>,
    medium_pks: &BTreeMap<Hash, SignedMediumPk>,
) -> anyhow::Result<()> {
    let mut tx = db.begin().await?;

    let chains_bytes = bcs::to_bytes(device_chains)?;
    sqlx::query("INSERT OR REPLACE INTO user_device_certs_cache (username, chains) VALUES (?, ?)")
        .bind(username.as_str())
        .bind(chains_bytes)
        .execute(tx.as_mut())
        .await?;

    let medium_pks_bytes = bcs::to_bytes(medium_pks)?;
    sqlx::query(
        "INSERT OR REPLACE INTO user_device_medium_pks_cache (username, medium_pks) \
         VALUES (?, ?)",
    )
    .bind(username.as_str())
    .bind(medium_pks_bytes)
    .execute(tx.as_mut())
    .await?;

    sqlx::query("INSERT OR REPLACE INTO user_info_cache (username, fetched_at) VALUES (?, ?)")
        .bind(username.as_str())
        .bind(now_seconds())
        .execute(tx.as_mut())
        .await?;

    tx.commit().await?;
    Ok(())
}
