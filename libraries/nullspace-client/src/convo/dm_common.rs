use anyctx::AnyCtx;
use nullspace_structs::server::AuthToken;

use crate::auth_tokens::get_auth_token;
use crate::config::Config;

pub(super) async fn device_auth(ctx: &AnyCtx<Config>) -> anyhow::Result<AuthToken> {
    get_auth_token(ctx).await
}
