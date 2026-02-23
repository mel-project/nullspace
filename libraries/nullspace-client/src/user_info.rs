use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use moka::future::Cache;
use nullspace_crypt::hash::{BcsHashExt, Hash};
use nullspace_crypt::signing::{Signable, SigningPublic};
use nullspace_structs::server::{ServerClient, ServerName, SignedMediumPk};
use nullspace_structs::username::{UserDescriptor, UserName};
use tracing::warn;

use crate::config::{Config, Ctx};
use crate::directory::DIR_CLIENT;
use crate::server::get_server_client;

pub struct UserInfo {
    pub username: UserName,
    pub server: Arc<ServerClient>,
    pub server_name: ServerName,
    pub devices: BTreeSet<SigningPublic>,
    pub medium_pks: BTreeMap<Hash, SignedMediumPk>,
}

const CACHE_TTL: Duration = Duration::from_secs(60);

static DESCRIPTOR_CACHE: Ctx<Cache<UserName, UserDescriptor>> =
    |_| Cache::builder().time_to_live(CACHE_TTL).build();

static USER_INFO_CACHE: Ctx<Cache<UserName, Arc<UserInfo>>> =
    |_| Cache::builder().time_to_live(CACHE_TTL).build();

pub async fn get_user_descriptor(
    ctx: &anyctx::AnyCtx<Config>,
    username: &UserName,
) -> anyhow::Result<UserDescriptor> {
    ctx.get(DESCRIPTOR_CACHE)
        .try_get_with(username.clone(), async {
            ctx.get(DIR_CLIENT)
                .get_user_descriptor(username)
                .await?
                .context("username not in directory")
        })
        .await
        .map_err(|err: Arc<anyhow::Error>| anyhow::anyhow!(err.to_string()))
}

pub async fn get_user_info(
    ctx: &anyctx::AnyCtx<Config>,
    username: &UserName,
) -> anyhow::Result<Arc<UserInfo>> {
    ctx.get(USER_INFO_CACHE)
        .try_get_with(username.clone(), async {
            let descriptor = get_user_descriptor(ctx, username).await?;
            let server_name = descriptor.server_name.clone();
            let server = get_server_client(ctx, &server_name).await?;
            let devices = descriptor.devices.clone();

            if devices.is_empty() {
                anyhow::bail!("no active devices for {username}");
            }

            let medium_pks = fetch_medium_pks(&server, username).await?;
            let medium_pks = validate_medium_pks(username, &devices, medium_pks);

            Ok(Arc::new(UserInfo {
                username: username.clone(),
                server,
                server_name,
                devices,
                medium_pks,
            }))
        })
        .await
        .map_err(|err: Arc<anyhow::Error>| anyhow::anyhow!(err.to_string()))
}

fn validate_medium_pks(
    username: &UserName,
    devices: &BTreeSet<SigningPublic>,
    medium_pks: BTreeMap<Hash, SignedMediumPk>,
) -> BTreeMap<Hash, SignedMediumPk> {
    let device_by_hash: BTreeMap<Hash, SigningPublic> = devices
        .iter()
        .copied()
        .map(|pk| (pk.bcs_hash(), pk))
        .collect();

    medium_pks
        .into_iter()
        .filter(|(device_hash, medium_pk)| {
            let Some(device_pk) = device_by_hash.get(device_hash) else {
                return false;
            };
            if medium_pk.verify(*device_pk).is_err() {
                warn!(username=%username, device_hash=%device_hash, "invalid medium-term key signature");
                return false;
            }
            true
        })
        .collect()
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
