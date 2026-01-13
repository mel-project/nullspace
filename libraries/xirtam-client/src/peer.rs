use std::collections::BTreeMap;
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use anyhow::Context;
use futures_concurrency::future::TryJoin;
use moka::future::Cache;
use xirtam_structs::certificate::{CertificateChain, DeviceCertificate};
use xirtam_structs::gateway::{GatewayClient, GatewayName, SignedMediumPk};
use xirtam_structs::handle::Handle;

use crate::config::Config;
use crate::directory::DIR_CLIENT;
use crate::gateway::get_gateway_client;

pub struct PeerInfo {
    pub handle: Handle,
    pub gateway: Arc<GatewayClient>,
    pub gateway_name: GatewayName,
    pub certs: Vec<DeviceCertificate>,
    pub medium_pks: BTreeMap<xirtam_crypt::hash::Hash, SignedMediumPk>,
}

static PEER_CACHE: LazyLock<Cache<Handle, Arc<PeerInfo>>> = LazyLock::new(|| {
    Cache::builder()
        .time_to_live(Duration::from_secs(60))
        .build()
});

pub async fn get_peer_info(
    ctx: &anyctx::AnyCtx<Config>,
    handle: &Handle,
) -> anyhow::Result<Arc<PeerInfo>> {
    PEER_CACHE
        .try_get_with(handle.clone(), async {
            let start = Instant::now();
            let dir = ctx.get(DIR_CLIENT);
            let descriptor = dir
                .get_handle_descriptor(handle)
                .await?
                .context("handle not in directory")?;
            let gateway = get_gateway_client(ctx, &descriptor.gateway_name).await?;
            let (chain, medium_pks) = (
                fetch_chain(&gateway, handle),
                fetch_medium_pks(&gateway, handle),
            )
                .try_join()
                .await?;
            let certs = chain
                .verify(descriptor.root_cert_hash)
                .map_err(|err| anyhow::anyhow!(err.to_string()))?;
            tracing::debug!(handle=%handle, elapsed=debug(start.elapsed()), "refreshed peer info");
            Ok(Arc::new(PeerInfo {
                handle: handle.clone(),
                gateway,
                gateway_name: descriptor.gateway_name.clone(),
                certs,
                medium_pks,
            }))
        })
        .await
        .map_err(|err: Arc<anyhow::Error>| anyhow::anyhow!(err.to_string()))
}

async fn fetch_chain(gateway: &GatewayClient, handle: &Handle) -> anyhow::Result<CertificateChain> {
    gateway
        .v1_device_certs(handle.clone())
        .await?
        .map_err(|err| anyhow::anyhow!(err.to_string()))?
        .context("handle has no certificate chain")
}

async fn fetch_medium_pks(
    gateway: &GatewayClient,
    handle: &Handle,
) -> anyhow::Result<BTreeMap<xirtam_crypt::hash::Hash, SignedMediumPk>> {
    gateway
        .v1_device_medium_pks(handle.clone())
        .await?
        .map_err(|err| anyhow::anyhow!(err.to_string()))
}
