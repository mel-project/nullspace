use nullspace_structs::server::ServerName;
use nullspace_structs::username::UserName;

use crate::config::Config;
use crate::database::DATABASE;
use crate::internal::{InternalRpcError, internal_err};

use super::Identity;

pub async fn own_server_impl(ctx: &anyctx::AnyCtx<Config>) -> Result<ServerName, InternalRpcError> {
    let db = ctx.get(DATABASE);
    let identity = Identity::load(&mut *db.acquire().await.map_err(internal_err)?)
        .await
        .map_err(internal_err)?;
    identity
        .server_name
        .ok_or_else(|| InternalRpcError::Other("server name not available".into()))
}

pub async fn own_username_impl(ctx: &anyctx::AnyCtx<Config>) -> Result<UserName, InternalRpcError> {
    let db = ctx.get(DATABASE);
    let identity = Identity::load(&mut *db.acquire().await.map_err(internal_err)?)
        .await
        .map_err(internal_err)?;
    Ok(identity.username)
}
