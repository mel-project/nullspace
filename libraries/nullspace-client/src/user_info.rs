use std::collections::BTreeMap;
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use anyhow::Context;
use futures_concurrency::future::TryJoin;
use moka::future::Cache;
use nullspace_crypt::hash::{BcsHashExt, Hash};
use nullspace_structs::certificate::CertificateChain;
use nullspace_structs::server::{ServerClient, ServerName, SignedMediumPk};
use nullspace_structs::username::UserName;
use tracing::warn;

use crate::config::Config;
use crate::directory::DIR_CLIENT;
use crate::server::get_server_client;

pub struct UserInfo {
    pub username: UserName,
    pub server: Arc<ServerClient>,
    pub server_name: ServerName,
    pub device_chains: BTreeMap<Hash, CertificateChain>,
    pub medium_pks: BTreeMap<Hash, SignedMediumPk>,
}

static USER_CACHE: LazyLock<Cache<UserName, Arc<UserInfo>>> = LazyLock::new(|| {
    Cache::builder()
        .time_to_live(Duration::from_secs(60))
        .build()
});

static USER_ROOT_HASH_CACHE: LazyLock<Cache<UserName, Hash>> = LazyLock::new(|| {
    Cache::builder()
        .time_to_live(Duration::from_secs(60))
        .build()
});

pub async fn get_user_info(
    ctx: &anyctx::AnyCtx<Config>,
    username: &UserName,
) -> anyhow::Result<Arc<UserInfo>> {
    USER_CACHE
        .try_get_with(username.clone(), async {
            let start = Instant::now();
            let dir = ctx.get(DIR_CLIENT);
            let descriptor = dir
                .get_user_descriptor(username)
                .await?
                .context("username not in directory")?;
            let root_hash = get_user_root_hash(ctx, username).await?;
            let server = get_server_client(ctx, &descriptor.server_name).await?;
            let (chains, medium_pks) = (
                fetch_chains(&server, username),
                fetch_medium_pks(&server, username),
            )
                .try_join()
                .await?;
            let mut device_chains = BTreeMap::new();
            for (device_hash, chain) in chains {
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
                return Err(anyhow::anyhow!("no valid device certificate chains for {username}"));
            }
            tracing::debug!(username=%username, elapsed=debug(start.elapsed()), "refreshed peer info");
            Ok(Arc::new(UserInfo {
                username: username.clone(),
                server,
                server_name: descriptor.server_name.clone(),
                device_chains,
                medium_pks,
            }))
        })
        .await
        .map_err(|err: Arc<anyhow::Error>| anyhow::anyhow!(err.to_string()))
}

pub async fn get_user_root_hash(
    ctx: &anyctx::AnyCtx<Config>,
    username: &UserName,
) -> anyhow::Result<Hash> {
    USER_ROOT_HASH_CACHE
        .try_get_with(username.clone(), async {
            let dir = ctx.get(DIR_CLIENT);
            let descriptor = dir
                .get_user_descriptor(username)
                .await?
                .context("username not in directory")?;
            Ok(descriptor.root_cert_hash)
        })
        .await
        .map_err(|err: Arc<anyhow::Error>| anyhow::anyhow!(err.to_string()))
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
