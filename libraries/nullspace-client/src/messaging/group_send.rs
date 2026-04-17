use anyctx::AnyCtx;
use bytes::Bytes;
use nullspace_structs::Blob;
use nullspace_structs::e2ee::DeviceSigned;
use nullspace_structs::event::Event;
use nullspace_structs::group::GroupId;
use nullspace_structs::timestamp::NanoTimestamp;

use crate::config::Config;
use crate::database::DATABASE;
use crate::identity::Identity;
use crate::storage::load_gbk;
use crate::transport::get_server_client;

use super::groups::refresh_group_state;

pub async fn send_group(
    ctx: &AnyCtx<Config>,
    group_id: &GroupId,
    event: Event,
) -> anyhow::Result<NanoTimestamp> {
    let db = ctx.get(DATABASE);
    let identity = Identity::load(&mut *db.acquire().await?).await?;
    refresh_group_state(ctx, *group_id).await?;
    let loaded = load_gbk(&mut *db.acquire().await?, *group_id).await?;
    let gbk = loaded.gbk;
    let server = get_server_client(ctx, &loaded.server_name).await?;

    // Sign the event bytes with the device key
    let event_bytes = bcs::to_bytes(&event)?;
    let signed = DeviceSigned::sign_bytes(
        Bytes::from(event_bytes),
        identity.username.clone(),
        identity.device_secret.public().signing_public(),
        &identity.device_secret,
    );
    let signed_bytes = bcs::to_bytes(&signed)?;

    // Symmetrically encrypt with the group key
    let sym_key = gbk.symmetric_key();
    let nonce: [u8; 24] = rand::random();
    let ciphertext = sym_key
        .encrypt(nonce, &signed_bytes, &[])
        .map_err(|_| anyhow::anyhow!("group message encryption failed"))?;

    // Prepend nonce to ciphertext
    let mut payload = Vec::with_capacity(24 + ciphertext.len());
    payload.extend_from_slice(&nonce);
    payload.extend_from_slice(&ciphertext);

    let mailbox_id = gbk.mailbox_key().mailbox_id();
    let received_at = server
        .mailbox_send(mailbox_id, Blob(Bytes::from(payload)), 0)
        .await?
        .map_err(|err| anyhow::anyhow!(err.to_string()))?;
    Ok(received_at)
}
