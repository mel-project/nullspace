use std::sync::{Arc, LazyLock};
use std::time::Duration;

use anyhow::Context;
use moka::future::Cache;
use xirtam_dirclient::DirClient;
use xirtam_nanorpc::Transport;
use xirtam_structs::server::{ServerClient, ServerName};

use crate::config::Config;
use crate::database::DATABASE;

static SERVER_CACHE: LazyLock<Cache<ServerName, Arc<ServerClient>>> = LazyLock::new(|| {
    Cache::builder()
        .time_to_idle(Duration::from_secs(12 * 60 * 60))
        .build()
});

pub async fn get_server_client(
    ctx: &anyctx::AnyCtx<Config>,
    name: &ServerName,
) -> anyhow::Result<Arc<ServerClient>> {
    SERVER_CACHE
        .try_get_with(name.clone(), async {
            let transport = Transport::new(ctx.init().dir_endpoint.clone());
            let dir = DirClient::new(
                transport,
                ctx.init().dir_anchor_pk,
                ctx.get(DATABASE).clone(),
            )
            .await?;
            let descriptor = dir
                .get_server_descriptor(name)
                .await?
                .context("server not in directory")?;
            let endpoint = descriptor
                .public_urls
                .first()
                .cloned()
                .context("server has no public URLs")?;
            Ok(Arc::new(ServerClient::from(Transport::new(endpoint))))
        })
        .await
        .map_err(|err: Arc<anyhow::Error>| anyhow::anyhow!(err.to_string()))
}
