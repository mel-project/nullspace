use std::time::Duration;

use anyctx::AnyCtx;
use anyhow::Context;
use xirtam_crypt::dh::DhSecret;
use xirtam_crypt::signing::Signable;
use xirtam_structs::server::SignedMediumPk;
use xirtam_structs::timestamp::Timestamp;

use crate::Config;
use crate::database::DATABASE;
use crate::directory::DIR_CLIENT;
use crate::server::get_server_client;
use crate::identity::Identity;

const MEDIUM_ROTATE_INTERVAL: Duration = Duration::from_secs(60 * 60);

pub async fn rotation_loop(ctx: &AnyCtx<Config>) {
    loop {
        tokio::time::sleep(MEDIUM_ROTATE_INTERVAL).await;
        if let Err(err) = rotate_once(ctx).await {
            tracing::warn!(error = %err, "medium-key rotation error");
        }
    }
}

async fn rotate_once(ctx: &AnyCtx<Config>) -> anyhow::Result<()> {
    let db = ctx.get(DATABASE);
    let identity = Identity::load(db).await?;
    let dir = ctx.get(DIR_CLIENT);
    let descriptor = dir
        .get_user_descriptor(&identity.username)
        .await?
        .context("identity username not in directory")?;
    let server = get_server_client(ctx, &descriptor.server_name).await?;
    let auth = server
        .v1_device_auth(identity.username.clone(), identity.cert_chain.clone())
        .await?
        .map_err(|err| anyhow::anyhow!(err.to_string()))?;
    let new_sk = DhSecret::random();
    let mut signed = SignedMediumPk {
        medium_pk: new_sk.public_key(),
        created: Timestamp::now(),
        signature: xirtam_crypt::signing::Signature::from_bytes([0u8; 64]),
    };
    signed.sign(&identity.device_secret);
    sqlx::query(
        "UPDATE client_identity \
         SET medium_sk_prev = ?, medium_sk_current = ? \
         WHERE id = 1",
    )
    .bind(bcs::to_bytes(&identity.medium_sk_current)?)
    .bind(bcs::to_bytes(&new_sk)?)
    .execute(db)
    .await?;
    server
        .v1_device_add_medium_pk(auth, signed)
        .await?
        .map_err(|err| anyhow::anyhow!(err.to_string()))?;
    tracing::debug!("medium-term key successfully rotated!");
    Ok(())
}
