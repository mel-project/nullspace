use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Instant;

use anyhow::Context;
use nullspace_crypt::hash::{BcsHashExt, Hash};
use nullspace_crypt::signing::{Signable, SigningPublic};
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
    pub devices: BTreeSet<SigningPublic>,
    pub medium_pks: BTreeMap<Hash, SignedMediumPk>,
}

const USER_CACHE_TTL_SECONDS: i64 = 60;

pub async fn get_user_descriptor(
    ctx: &anyctx::AnyCtx<Config>,
    username: &UserName,
) -> anyhow::Result<UserDescriptor> {
    let db = ctx.get(DATABASE);
    if let Some((descriptor, fetched_at)) = load_cached_descriptor(db, username).await?
        && is_fresh(fetched_at)
    {
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
    let server_name = descriptor.server_name.clone();
    let server = get_server_client(ctx, &server_name).await?;

    let devices = descriptor.devices.clone();
    if devices.is_empty() {
        return Err(anyhow::anyhow!("no active devices for {username}"));
    }

    let mut cached_devices = load_cached_devices(db, username).await?;
    let mut cached_medium_pks = load_cached_medium_pks(db, username).await?;
    let cached_fetched_at = load_cached_user_info_fetched_at(db, username).await?;
    let cache_fresh = cached_fetched_at.map(is_fresh).unwrap_or(false);

    let should_refresh = !cache_fresh || cached_devices != devices;
    if should_refresh {
        let medium_pks = fetch_medium_pks(&server, username).await?;
        cached_devices = devices.clone();
        cached_medium_pks = merge_monotonic_medium_pks(username, cached_medium_pks, medium_pks);
        store_cached_user_info(db, username, &cached_devices, &cached_medium_pks).await?;
        tracing::debug!(username=%username, elapsed=debug(start.elapsed()), "refreshed peer info");
    }

    let device_by_hash: BTreeMap<Hash, SigningPublic> = devices
        .iter()
        .copied()
        .map(|device_pk| (device_pk.bcs_hash(), device_pk))
        .collect();
    let mut valid_medium_pks = BTreeMap::new();
    for (device_hash, medium_pk) in cached_medium_pks {
        let Some(device_pk) = device_by_hash.get(&device_hash) else {
            continue;
        };
        if medium_pk.verify(*device_pk).is_err() {
            warn!(username=%username, device_hash=%device_hash, "invalid medium-term key signature");
            continue;
        }
        valid_medium_pks.insert(device_hash, medium_pk);
    }

    Ok(Arc::new(UserInfo {
        username: username.clone(),
        server,
        server_name,
        devices,
        medium_pks: valid_medium_pks,
    }))
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

async fn load_cached_devices(
    db: &sqlx::SqlitePool,
    username: &UserName,
) -> anyhow::Result<BTreeSet<SigningPublic>> {
    let row = sqlx::query_scalar::<_, Vec<u8>>(
        "SELECT devices FROM user_devices_cache WHERE username = ?",
    )
    .bind(username.as_str())
    .fetch_optional(db)
    .await?;
    let Some(devices_bytes) = row else {
        return Ok(BTreeSet::new());
    };
    let devices = bcs::from_bytes(&devices_bytes)?;
    Ok(devices)
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
    devices: &BTreeSet<SigningPublic>,
    medium_pks: &BTreeMap<Hash, SignedMediumPk>,
) -> anyhow::Result<()> {
    let mut tx = db.begin().await?;

    let devices_bytes = bcs::to_bytes(devices)?;
    sqlx::query("INSERT OR REPLACE INTO user_devices_cache (username, devices) VALUES (?, ?)")
        .bind(username.as_str())
        .bind(devices_bytes)
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
