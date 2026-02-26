use anyctx::AnyCtx;
use anyhow::Context;
use nullspace_structs::server::{AuthToken, ServerName};

use crate::auth_tokens::get_auth_token;
use crate::config::Config;
use crate::directory::DIR_CLIENT;
use crate::identity::{Identity, store_server_name};

pub(super) async fn device_auth(ctx: &AnyCtx<Config>) -> anyhow::Result<AuthToken> {
    get_auth_token(ctx).await
}

pub(super) async fn refresh_own_server_name(
    ctx: &AnyCtx<Config>,
    db: &sqlx::SqlitePool,
    identity: &Identity,
) -> anyhow::Result<ServerName> {
    let dir = ctx.get(DIR_CLIENT);
    let descriptor = dir
        .get_user_descriptor(&identity.username)
        .await?
        .context("identity username not in directory")?;
    let server_name = descriptor.server_name.clone();
    store_server_name(db, &server_name).await?;
    Ok(server_name)
}
