use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use moka::future::Cache;
use nullspace_structs::server::{ServerClient, ServerName};

use crate::DIR_CLIENT;
use crate::RPC_POOL;
use crate::config::{Config, Ctx};

pub static SERVER_CACHE: Ctx<Cache<ServerName, Arc<ServerClient>>> =
    |_ctx: &anyctx::AnyCtx<Config>| {
        Cache::builder()
            .time_to_idle(Duration::from_secs(3600))
            .build()
    };

pub async fn get_server_client(
    ctx: &anyctx::AnyCtx<Config>,
    name: &ServerName,
) -> anyhow::Result<Arc<ServerClient>> {
    let cache = ctx.get(SERVER_CACHE);
    cache
        .try_get_with(name.clone(), async {
            let descriptor = ctx
                .get(DIR_CLIENT)
                .get_server_descriptor(name)
                .await?
                .context("server not in directory")?;
            let endpoint = descriptor
                .public_urls
                .first()
                .cloned()
                .context("server has no public URLs")?;
            Ok(Arc::new(ServerClient::from(
                ctx.get(RPC_POOL).rpc(endpoint),
            )))
        })
        .await
        .map_err(|err: Arc<anyhow::Error>| anyhow::anyhow!(err.to_string()))
}
