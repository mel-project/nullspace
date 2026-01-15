use std::collections::BTreeMap;
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use anyhow::Context;
use futures_concurrency::future::TryJoin;
use moka::future::Cache;
use xirtam_structs::certificate::{CertificateChain, DeviceCertificate};
use xirtam_structs::server::{ServerClient, ServerName, SignedMediumPk};
use xirtam_structs::username::UserName;

use crate::config::Config;
use crate::directory::DIR_CLIENT;
use crate::server::get_server_client;

pub struct PeerInfo {
    pub username: UserName,
    pub server: Arc<ServerClient>,
    pub server_name: ServerName,
    pub certs: Vec<DeviceCertificate>,
    pub medium_pks: BTreeMap<xirtam_crypt::hash::Hash, SignedMediumPk>,
}

static PEER_CACHE: LazyLock<Cache<UserName, Arc<PeerInfo>>> = LazyLock::new(|| {
    Cache::builder()
        .time_to_live(Duration::from_secs(60))
        .build()
});

pub async fn get_peer_info(
    ctx: &anyctx::AnyCtx<Config>,
    username: &UserName,
) -> anyhow::Result<Arc<PeerInfo>> {
    PEER_CACHE
        .try_get_with(username.clone(), async {
            let start = Instant::now();
            let dir = ctx.get(DIR_CLIENT);
            let descriptor = dir
                .get_user_descriptor(username)
                .await?
                .context("username not in directory")?;
            let server = get_server_client(ctx, &descriptor.server_name).await?;
            let (chain, medium_pks) = (
                fetch_chain(&server, username),
                fetch_medium_pks(&server, username),
            )
                .try_join()
                .await?;
            let certs = chain
                .verify(descriptor.root_cert_hash)
                .map_err(|err| anyhow::anyhow!(err.to_string()))?;
            tracing::debug!(username=%username, elapsed=debug(start.elapsed()), "refreshed peer info");
            Ok(Arc::new(PeerInfo {
                username: username.clone(),
                server,
                server_name: descriptor.server_name.clone(),
                certs,
                medium_pks,
            }))
        })
        .await
        .map_err(|err: Arc<anyhow::Error>| anyhow::anyhow!(err.to_string()))
}

async fn fetch_chain(server: &ServerClient, username: &UserName) -> anyhow::Result<CertificateChain> {
    server
        .v1_device_certs(username.clone())
        .await?
        .map_err(|err| anyhow::anyhow!(err.to_string()))?
        .context("username has no certificate chain")
}

async fn fetch_medium_pks(
    server: &ServerClient,
    username: &UserName,
) -> anyhow::Result<BTreeMap<xirtam_crypt::hash::Hash, SignedMediumPk>> {
    server
        .v1_device_medium_pks(username.clone())
        .await?
        .map_err(|err| anyhow::anyhow!(err.to_string()))
}
