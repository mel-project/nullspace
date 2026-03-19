use std::collections::{BTreeMap, BTreeSet};

use anyctx::AnyCtx;
use anyhow::Context;
use nullspace_crypt::hash::{BcsHashExt, Hash};
use nullspace_crypt::signing::Signable;
use nullspace_structs::Blob;
use nullspace_structs::event::Event;
use nullspace_structs::mailbox::MailboxId;
use nullspace_structs::server::SignedMediumPk;
use nullspace_structs::timestamp::NanoTimestamp;
use nullspace_structs::username::UserName;
use tracing::warn;

use crate::config::Config;
use crate::database::DATABASE;
use crate::identity::Identity;
use crate::users::{UserInfo, get_user_info};

use super::device_crypt::sign_and_encrypt;

pub(super) async fn send_dm(
    ctx: &AnyCtx<Config>,
    peer: &UserName,
    event: Event,
) -> anyhow::Result<NanoTimestamp> {
    let db = ctx.get(DATABASE);
    let identity = Identity::load(&mut *db.acquire().await?).await?;

    let peer_received_at = send_dm_once(ctx, &identity, peer, &event).await?;
    let self_received_at = if identity.username != *peer {
        send_dm_once(ctx, &identity, &identity.username, &event).await?
    } else {
        peer_received_at
    };
    Ok(self_received_at)
}

async fn send_dm_once(
    ctx: &AnyCtx<Config>,
    identity: &Identity,
    target: &UserName,
    event: &Event,
) -> anyhow::Result<NanoTimestamp> {
    let peer = get_user_info(ctx, target).await?;
    let recipients = recipients_from_peer(peer.as_ref())?;
    let target_mailbox = fetch_peer_mailbox_id(peer.as_ref()).await?;

    let event_bytes = bcs::to_bytes(event)?;
    let body = sign_and_encrypt(identity, &event_bytes, recipients)?;

    let received_at = peer
        .server
        .mailbox_send(target_mailbox, Blob(body), 0)
        .await?
        .map_err(|err| anyhow::anyhow!(err.to_string()))?;
    Ok(received_at)
}

async fn fetch_peer_mailbox_id(peer: &UserInfo) -> anyhow::Result<MailboxId> {
    let profile = peer
        .server
        .profile(peer.username.clone())
        .await?
        .map_err(|err| anyhow::anyhow!(err.to_string()))?
        .context("target profile not found")?;

    if !peer
        .devices
        .iter()
        .any(|device_pk| profile.verify(*device_pk).is_ok())
    {
        anyhow::bail!("target profile signature is invalid");
    }

    Ok(profile.dm_mailbox)
}

fn collect_recipients(
    username: &UserName,
    devices: &BTreeSet<nullspace_crypt::signing::SigningPublic>,
    medium_pks: &BTreeMap<Hash, SignedMediumPk>,
) -> anyhow::Result<Vec<nullspace_crypt::dh::DhPublic>> {
    let mut recipients = Vec::new();
    for device_pk in devices {
        let device_hash = device_pk.bcs_hash();
        let Some(medium_pk) = medium_pks.get(&device_hash) else {
            warn!(username = %username, device_hash = %device_hash, "missing medium-term key");
            continue;
        };
        if medium_pk.verify(*device_pk).is_err() {
            warn!(username = %username, device_hash = %device_hash, "invalid medium-term key signature");
            continue;
        }
        recipients.push(medium_pk.medium_pk.clone());
    }
    if recipients.is_empty() {
        anyhow::bail!("no medium-term keys available for {username}");
    }
    Ok(recipients)
}

fn recipients_from_peer(peer: &UserInfo) -> anyhow::Result<Vec<nullspace_crypt::dh::DhPublic>> {
    collect_recipients(&peer.username, &peer.devices, &peer.medium_pks)
}
