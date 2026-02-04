use std::sync::Arc;
use std::time::Duration;

use anyctx::AnyCtx;
use anyhow::Context;
use moka::future::Cache;
use nullspace_structs::server::{AuthToken, ServerClient, ServerName};

use crate::config::{Config, Ctx};
use crate::database::DATABASE;
use crate::directory::DIR_CLIENT;
use crate::identity::{Identity, store_server_name};
use crate::rpc_pool::RPC_POOL;

const AUTH_TOKEN_TTL: Duration = Duration::from_secs(60 * 60);

static AUTH_TOKEN_CACHE: Ctx<Cache<ServerName, AuthToken>> =
    |_ctx: &AnyCtx<Config>| Cache::builder().time_to_idle(AUTH_TOKEN_TTL).build();

pub async fn get_auth_token(ctx: &AnyCtx<Config>) -> anyhow::Result<AuthToken> {
    let db = ctx.get(DATABASE);
    let identity = Identity::load(db).await?;
    let server_name = own_server_name(ctx, db, &identity).await?;
    let cache = ctx.get(AUTH_TOKEN_CACHE);
    let cache_key = server_name.clone();
    let username = identity.username.clone();
    let cert_chain = identity.cert_chain.clone();
    cache
        .try_get_with(cache_key, async move {
            let server = server_client_direct(ctx, &server_name).await?;
            let auth = server
                .v1_device_auth(username, cert_chain)
                .await?
                .map_err(|err| anyhow::anyhow!(err.to_string()))?;
            Ok(auth)
        })
        .await
        .map_err(|err: Arc<anyhow::Error>| anyhow::anyhow!(err.to_string()))
}

async fn own_server_name(
    ctx: &AnyCtx<Config>,
    db: &sqlx::SqlitePool,
    identity: &Identity,
) -> anyhow::Result<ServerName> {
    if let Some(server_name) = identity.server_name.clone() {
        return Ok(server_name);
    }
    let dir = ctx.get(DIR_CLIENT);
    let descriptor = dir
        .get_user_descriptor(&identity.username)
        .await?
        .context("identity username not in directory")?;
    store_server_name(db, &descriptor.server_name).await?;
    Ok(descriptor.server_name)
}

async fn server_client_direct(
    ctx: &AnyCtx<Config>,
    server_name: &ServerName,
) -> anyhow::Result<ServerClient> {
    let dir = ctx.get(DIR_CLIENT);
    let descriptor = dir
        .get_server_descriptor(server_name)
        .await?
        .context("server not in directory")?;
    let endpoint = descriptor
        .public_urls
        .first()
        .cloned()
        .context("server has no public URLs")?;
    let rpc_pool = ctx.get(RPC_POOL);
    Ok(ServerClient::from(rpc_pool.rpc(endpoint)))
}
