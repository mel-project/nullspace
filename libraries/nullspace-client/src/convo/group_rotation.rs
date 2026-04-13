use std::collections::BTreeSet;
use std::time::Duration;

use crate::config::Config;
use crate::database::DATABASE;
use crate::identity::Identity;
use crate::net::{get_auth_token, get_server_client};
use crate::users::get_user_info;
use anyctx::AnyCtx;
use bytes::Bytes;
use nullspace_crypt::dh::DhPublic;
use nullspace_crypt::hash::BcsHashExt;
use nullspace_crypt::signing::{Signable, Signature, SigningPublic};
use nullspace_structs::Blob;
use nullspace_structs::e2ee::{DeviceSigned, HeaderEncrypted};
use nullspace_structs::event::{Event, EventRecipient, TAG_ROTATION_HINT};
use nullspace_structs::group::{
    GroupBearerKey, GroupId, GroupRoster, GroupRotation, GroupRotationPayload, encrypt_roster,
};
use nullspace_structs::timestamp::NanoTimestamp;

use super::groups::{load_gbk, load_roster};

/// Admin rotation submit loop.
///
/// Every hour, for each group where this device is an admin, roll the dice
/// and maybe submit a new GBK rotation. The expected interval is ~1 rotation
/// per day per group (with a single admin).
pub async fn group_rotation_loop(ctx: &AnyCtx<Config>) {
    loop {
        if let Err(err) = group_rotation_loop_once(ctx).await {
            tracing::error!(error = %err, "group rotation loop error");
        }
        tokio::time::sleep(Duration::from_secs(3600)).await;
    }
}

async fn group_rotation_loop_once(ctx: &AnyCtx<Config>) -> anyhow::Result<()> {
    let db = ctx.get(DATABASE);
    let identity = Identity::load(&mut *db.acquire().await?).await?;
    let device_pk = identity.device_secret.public().signing_public();

    let rows = sqlx::query_as::<_, (Vec<u8>, Vec<u8>)>(
        "SELECT group_id, admin_set \
         FROM group_keys k WHERE rotation_index = \
           (SELECT MAX(rotation_index) FROM group_keys WHERE group_id = k.group_id)",
    )
    .fetch_all(&mut *db.acquire().await?)
    .await?;

    for (gid_bytes, admin_set_bytes) in rows {
        let gid_arr: [u8; 16] = gid_bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid group_id length"))?;
        let group_id = GroupId::from_bytes(gid_arr);

        let admin_set: BTreeSet<SigningPublic> = bcs::from_bytes(&admin_set_bytes)?;
        if !admin_set.contains(&device_pk) {
            continue;
        }

        // p = 1/(24*n_admins) per hour -> ~1 rotation/day
        let n_admins = admin_set.len().max(1) as f64;
        let p = 1.0 / (24.0 * n_admins);
        if rand::random::<f64>() >= p {
            continue;
        }

        // Load the roster and submit rotation with full payload
        let roster = match load_roster(&mut *db.acquire().await?, group_id).await {
            Ok((_, roster)) => roster,
            Err(err) => {
                tracing::warn!(group = %group_id, error = %err, "no roster for rotation");
                continue;
            }
        };

        if let Err(err) = submit_rotation(ctx, &identity, group_id, &roster).await {
            tracing::warn!(group = %group_id, error = %err, "failed to submit rotation");
        }
    }

    Ok(())
}

/// Submit a new GBK rotation encrypted to all members in the roster.
pub async fn submit_rotation(
    ctx: &AnyCtx<Config>,
    identity: &Identity,
    group_id: GroupId,
    roster: &GroupRoster,
) -> anyhow::Result<()> {
    let db = ctx.get(DATABASE);
    let loaded = load_gbk(&mut *db.acquire().await?, group_id).await?;
    let prev_rotation_hash = loaded.rotation_hash;
    let old_gbk = loaded.gbk;
    let server_name = &loaded.server_name;
    let device_pk = identity.device_secret.public().signing_public();

    tracing::info!(group = %group_id, "submitting GBK rotation");

    let new_gbk = GroupBearerKey::generate(group_id, server_name.clone());

    // Collect medium keys for all members and admin device keys
    let (all_medium_keys, new_admin_set) = member_devices(ctx, roster).await?;

    let payload = GroupRotationPayload {
        gbk: new_gbk.clone(),
    };
    let payload_bytes = bcs::to_bytes(&payload)?;
    let payload_encrypted = HeaderEncrypted::encrypt_bytes(&payload_bytes, all_medium_keys)
        .map_err(|e| anyhow::anyhow!(e))?;
    let roster_encrypted = encrypt_roster(&new_gbk, roster)?;

    let mut rotation = GroupRotation {
        group_id,
        prev_hash: Some(prev_rotation_hash),
        signer: device_pk,
        new_admin_set,
        gbk_rotation: payload_encrypted,
        roster_encrypted,
        signature: Signature::from_bytes([0u8; 64]),
    };
    rotation.sign(&identity.device_secret);

    let server = get_server_client(ctx, server_name).await?;

    match server.group_update(rotation.clone()).await? {
        Ok(()) => {}
        Err(e) => {
            tracing::debug!(group = %group_id, error = %e, "rotation rejected (likely race)");
            return Ok(());
        }
    }

    if roster.members.is_empty() {
        tracing::info!(
            group = %group_id,
            "rotation left the group with no members; new epoch is intentionally unreachable"
        );
    } else {
        let auth = get_auth_token(ctx).await?;
        server
            .mailbox_create(auth, new_gbk.mailbox_key())
            .await?
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    }

    send_rotation_hint(ctx, identity, group_id, &old_gbk).await?;

    Ok(())
}

/// Look up all members' medium-term DH keys and derive the admin device key set.
///
/// Returns (all_medium_keys, admin_device_keys).
async fn member_devices(
    ctx: &AnyCtx<Config>,
    roster: &GroupRoster,
) -> anyhow::Result<(Vec<DhPublic>, BTreeSet<SigningPublic>)> {
    let mut all_medium_keys = Vec::new();
    let mut admin_device_keys = BTreeSet::new();

    for (username, state) in &roster.members {
        let user_info = get_user_info(ctx, username).await?;

        // Collect medium keys for encryption
        for device_pk in &user_info.devices {
            let device_hash = device_pk.bcs_hash();
            if let Some(medium_pk) = user_info.medium_pks.get(&device_hash) {
                if medium_pk.verify(*device_pk).is_ok() {
                    all_medium_keys.push(medium_pk.medium_pk.clone());
                }
            }
        }

        // Collect admin device keys for new_admin_set
        if state.is_admin {
            for device_pk in &user_info.devices {
                admin_device_keys.insert(*device_pk);
            }
        }
    }

    Ok((all_medium_keys, admin_device_keys))
}

async fn send_rotation_hint(
    ctx: &AnyCtx<Config>,
    identity: &Identity,
    group_id: GroupId,
    gbk: &GroupBearerKey,
) -> anyhow::Result<()> {
    let event = Event::default()
        .sender(identity.username.clone())
        .recipient(EventRecipient::Group(group_id))
        .sent_at(NanoTimestamp::now())
        .tag(TAG_ROTATION_HINT)
        .body(Bytes::new());
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
