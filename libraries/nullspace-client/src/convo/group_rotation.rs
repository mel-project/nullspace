use std::collections::BTreeSet;
use std::time::Duration;

use anyctx::AnyCtx;
use bytes::Bytes;
use nullspace_crypt::signing::{Signable, Signature, SigningPublic};
use nullspace_structs::Blob;
use nullspace_structs::e2ee::{DeviceSigned, HeaderEncrypted};
use nullspace_structs::event::{Event, EventRecipient, TAG_ROTATION_HINT};
use nullspace_structs::group::{GroupBearerKey, GroupId, GroupRotation};
use nullspace_structs::server::ServerName;
use nullspace_structs::timestamp::NanoTimestamp;

use crate::config::Config;
use crate::database::DATABASE;
use crate::identity::Identity;
use crate::net::get_auth_token;
use crate::net::get_server_client;

/// Admin rotation submit loop.
///
/// Every hour, for each group where this device is an admin, roll the dice
/// and maybe submit a new GBK rotation. The expected interval is ~1 rotation
/// per day per group (with a single admin).
///
/// This loop never reads or writes the local GBK table — it only talks to
/// the server. The recv loop discovers and adopts rotations via hints.
pub(super) async fn group_rotation_loop(ctx: &AnyCtx<Config>) {
    loop {
        if let Err(err) = group_rotation_loop_once(ctx).await {
            tracing::error!(error = %err, "group rotation loop error");
        }
        tokio::time::sleep(Duration::from_secs(3600)).await;
    }
}

async fn group_rotation_loop_once(ctx: &AnyCtx<Config>) -> anyhow::Result<()> {
    let db = ctx.get(DATABASE);

    let rows = sqlx::query_as::<_, (Vec<u8>, i64, Vec<u8>, String)>(
        "SELECT group_id, MAX(rotation_index) as max_idx, gbk, server_name \
         FROM group_keys GROUP BY group_id",
    )
    .fetch_all(&mut *db.acquire().await?)
    .await?;

    for (gid_bytes, max_idx, gbk_bytes, sn) in rows {
        let gid_arr: [u8; 16] = gid_bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid group_id length"))?;
        let group_id = GroupId::from_bytes(gid_arr);
        let current_index = max_idx as u64;
        let server_name = ServerName::parse(sn)?;
        let server = get_server_client(ctx, &server_name).await?;

        // Fetch the current rotation to get admin_set
        let current_rotation = match server.group_get(group_id, current_index).await? {
            Ok(Some(rot)) => rot,
            Ok(None) | Err(_) => continue,
        };

        let old_gbk: GroupBearerKey = bcs::from_bytes(&gbk_bytes)?;
        if let Err(err) = maybe_submit_rotation(
            ctx,
            group_id,
            current_index,
            &current_rotation.new_admin_set,
            &server_name,
            &old_gbk,
        )
        .await
        {
            tracing::warn!(group = %group_id, error = %err, "failed to submit rotation");
        }
    }

    Ok(())
}

/// Roll the dice; if selected, generate a new GBK and submit it.
async fn maybe_submit_rotation(
    ctx: &AnyCtx<Config>,
    group_id: GroupId,
    current_index: u64,
    admin_set: &BTreeSet<SigningPublic>,
    server_name: &ServerName,
    old_gbk: &GroupBearerKey,
) -> anyhow::Result<()> {
    let db = ctx.get(DATABASE);
    let identity = Identity::load(&mut *db.acquire().await?).await?;
    let device_pk = identity.device_secret.public().signing_public();

    if !admin_set.contains(&device_pk) {
        return Ok(());
    }

    // p = 1/(24*n_admins) per hour → ~1 rotation/day
    let n_admins = admin_set.len().max(1) as f64;
    let p = 1.0 / (24.0 * n_admins);
    if rand::random::<f64>() >= p {
        return Ok(());
    }

    tracing::info!(group = %group_id, index = current_index + 1, "submitting GBK rotation");

    let new_gbk = GroupBearerKey::generate(group_id, server_name.clone());
    let gbk_bytes = bcs::to_bytes(&new_gbk)?;
    let gbk_encrypted =
        HeaderEncrypted::encrypt_bytes(&gbk_bytes, [identity.medium_sk_current.public_key()])
            .map_err(|e| anyhow::anyhow!(e))?;

    let mut rotation = GroupRotation {
        group_id,
        index: current_index + 1,
        signer: device_pk,
        new_admin_set: admin_set.clone(),
        gbk_rotation: gbk_encrypted,
        signature: Signature::from_bytes([0u8; 64]),
    };
    rotation.sign(&identity.device_secret);

    let server = get_server_client(ctx, server_name).await?;

    // Submit — AccessDenied means another admin raced us, which is fine
    match server.group_update(rotation).await? {
        Ok(()) => {}
        Err(e) => {
            tracing::debug!(group = %group_id, error = %e, "rotation rejected (likely race)");
            return Ok(());
        }
    }

    // Create the new mailbox (only submitter knows the key at this point)
    let auth = get_auth_token(ctx).await?;
    server
        .mailbox_create(auth, new_gbk.mailbox_key())
        .await?
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;

    // Hint the old mailbox so members check the registry promptly
    send_rotation_hint(ctx, &identity, group_id, old_gbk).await?;

    Ok(())
}

async fn send_rotation_hint(
    ctx: &AnyCtx<Config>,
    identity: &Identity,
    group_id: GroupId,
    gbk: &GroupBearerKey,
) -> anyhow::Result<()> {
    let event = Event {
        sender: identity.username.clone(),
        recipient: EventRecipient::Group(group_id),
        sent_at: NanoTimestamp::now(),
        after: None,
        tag: TAG_ROTATION_HINT,
        body: Bytes::new(),
    };
    let event_bytes = bcs::to_bytes(&event)?;
    let signed = DeviceSigned::sign_bytes(
        Bytes::from(event_bytes),
        identity.username.clone(),
        identity.device_secret.public().signing_public(),
        &identity.device_secret,
    );
    let signed_bytes = bcs::to_bytes(&signed)?;

    let sym_key = gbk.symmetric_key();
    let nonce: [u8; 24] = rand::random();
    let ciphertext = sym_key
        .encrypt(nonce, &signed_bytes, &[])
        .map_err(|_| anyhow::anyhow!("rotation hint encryption failed"))?;

    let mut payload = Vec::with_capacity(24 + ciphertext.len());
    payload.extend_from_slice(&nonce);
    payload.extend_from_slice(&ciphertext);

    let server = get_server_client(ctx, &gbk.server).await?;
    let mailbox_id = gbk.mailbox_key().mailbox_id();
    server
        .mailbox_send(mailbox_id, Blob(Bytes::from(payload)), 0)
        .await?
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;

    Ok(())
}
