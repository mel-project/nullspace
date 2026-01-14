use std::collections::BTreeMap;

use anyhow::Context;
use bytes::Bytes;
use smol_str::SmolStr;
use tracing::warn;
use xirtam_crypt::hash::BcsHashExt;
use xirtam_crypt::signing::Signable;
use xirtam_structs::Blob;
use xirtam_structs::certificate::DevicePublic;
use xirtam_structs::envelope::Envelope;
use xirtam_structs::gateway::{AuthToken, GatewayClient, GatewayName, MailboxId, SignedMediumPk};
use xirtam_structs::handle::Handle;
use xirtam_structs::msg_content::MessageContent;
use xirtam_structs::timestamp::NanoTimestamp;

use crate::config::Config;
use crate::database::{
    DATABASE, DbNotify, ensure_mailbox_state, load_mailbox_after, update_mailbox_after,
};
use crate::directory::DIR_CLIENT;
use crate::identity::Identity;
use crate::long_poll::LONG_POLLER;
use crate::peer::{PeerInfo, get_peer_info};

pub async fn send_loop(ctx: &anyctx::AnyCtx<Config>) {
    loop {
        if let Err(err) = send_loop_once(ctx).await {
            tracing::error!(error = %err, "dm send loop error");
        }
    }
}

pub async fn recv_loop(ctx: &anyctx::AnyCtx<Config>) {
    loop {
        if let Err(err) = recv_loop_once(ctx).await {
            tracing::error!(error = %err, "dm recv loop error");
        }
    }
}

async fn send_dm(
    ctx: &anyctx::AnyCtx<Config>,
    pending: &PendingDm,
) -> anyhow::Result<NanoTimestamp> {
    let db = ctx.get(DATABASE);
    let identity = Identity::load(db).await?;
    let sent_at = NanoTimestamp::now();
    let content = MessageContent {
        recipient: pending.peer.clone(),
        sent_at,
        mime: pending.mime.clone(),
        body: pending.body.clone(),
    };
    let message = Blob {
        kind: Blob::V1_MESSAGE_CONTENT.into(),
        inner: Bytes::from(bcs::to_bytes(&content)?),
    };

    let _peer_received_at = send_dm_once(ctx, &identity, &pending.peer, &message).await?;
    let self_received_at = if identity.handle != pending.peer {
        send_dm_once(ctx, &identity, &identity.handle, &message).await?
    } else {
        _peer_received_at
    };
    Ok(self_received_at)
}

async fn send_loop_once(ctx: &anyctx::AnyCtx<Config>) -> anyhow::Result<()> {
    let db = ctx.get(DATABASE);
    let mut notify = DbNotify::new();
    loop {
        let Some(pending) = next_pending_dm(db).await? else {
            notify.wait_for_change().await;
            continue;
        };
        let received_at = send_dm(ctx, &pending).await?;
        mark_message_sent(db, pending.id, received_at).await?;
        DbNotify::touch();
    }
}

pub async fn queue_dm(
    db: &sqlx::SqlitePool,
    sender: &Handle,
    peer: &Handle,
    mime: &SmolStr,
    body: &Bytes,
) -> anyhow::Result<i64> {
    let row = sqlx::query_as::<_, (i64,)>(
        "INSERT INTO dm_messages (peer_handle, sender_handle, mime, body, received_at) \
         VALUES (?, ?, ?, ?, NULL) \
         RETURNING id",
    )
    .bind(peer.as_str())
    .bind(sender.as_str())
    .bind(mime.as_str())
    .bind(body.to_vec())
    .fetch_one(db)
    .await?;
    Ok(row.0)
}

async fn mark_message_sent(
    db: &sqlx::SqlitePool,
    id: i64,
    received_at: NanoTimestamp,
) -> anyhow::Result<()> {
    let result = sqlx::query("UPDATE dm_messages SET received_at = ? WHERE id = ?")
        .bind(received_at.0 as i64)
        .bind(id)
        .execute(db)
        .await;
    match result {
        Ok(_) => Ok(()),
        Err(err) if is_unique_violation(&err) => {
            sqlx::query("DELETE FROM dm_messages WHERE id = ?")
                .bind(id)
                .execute(db)
                .await?;
            Ok(())
        }
        Err(err) => Err(err.into()),
    }
}

fn is_unique_violation(err: &sqlx::Error) -> bool {
    match err {
        sqlx::Error::Database(db_err) => db_err.code().as_deref() == Some("2067"),
        _ => false,
    }
}

async fn recv_loop_once(ctx: &anyctx::AnyCtx<Config>) -> anyhow::Result<()> {
    let db = ctx.get(DATABASE);
    let identity = Identity::load(db).await?;
    let my_info = get_peer_info(ctx, &identity.handle).await?;
    let gateway = my_info.gateway.clone();
    let auth = device_auth(gateway.as_ref(), &identity).await?;
    let mailbox = MailboxId::direct(&identity.handle);
    ensure_mailbox_state(db, &my_info.gateway_name, mailbox, NanoTimestamp(0)).await?;
    let mut after = load_mailbox_after(db, &my_info.gateway_name, mailbox).await?;
    let poller = ctx.get(LONG_POLLER);
    loop {
        let entry = match poller.recv(gateway.clone(), auth, mailbox, after).await {
            Ok(entry) => entry,
            Err(err) => {
                tracing::warn!(error = %err, "mailbox recv error");
                continue;
            }
        };
        after = entry.received_at;
        if let Err(err) =
            process_mailbox_entry(ctx, &my_info.gateway_name, mailbox, entry).await
        {
            tracing::warn!(error = %err, "failed to process mailbox entry");
        }
        // notify once to prevent thrashing
        DbNotify::touch();
    }
}

async fn send_dm_once(
    ctx: &anyctx::AnyCtx<Config>,
    identity: &Identity,
    target: &Handle,
    message: &Blob,
) -> anyhow::Result<NanoTimestamp> {
    let peer = get_peer_info(ctx, target).await?;
    let own_gateway = own_gateway_name(ctx, identity).await?;
    let recipients = recipients_from_peer(peer.as_ref())?;

    let auth = if peer.gateway_name == own_gateway {
        device_auth(peer.gateway.as_ref(), identity).await?
    } else {
        AuthToken::anonymous()
    };
    let envelope = Envelope::encrypt_message(
        message,
        identity.handle.clone(),
        identity.cert_chain.clone(),
        &identity.device_secret,
        recipients,
    )
    .map_err(|_| anyhow::anyhow!("failed to encrypt DM for {target}"))?;
    let received_at = send_envelope(
        peer.gateway.as_ref(),
        auth,
        MailboxId::direct(target),
        envelope,
    )
    .await?;
    Ok(received_at)
}

fn collect_recipients(
    handle: &Handle,
    chain: &[xirtam_structs::certificate::DeviceCertificate],
    medium_pks: &BTreeMap<xirtam_crypt::hash::Hash, SignedMediumPk>,
) -> anyhow::Result<Vec<(DevicePublic, xirtam_crypt::dh::DhPublic)>> {
    let mut recipients = Vec::new();
    for cert in chain {
        let device_hash = cert.pk.bcs_hash();
        let Some(medium_pk) = medium_pks.get(&device_hash) else {
            warn!(handle = %handle, device_hash = %device_hash, "missing medium-term key");
            continue;
        };
        if medium_pk.verify(cert.pk.signing_public()).is_err() {
            warn!(handle = %handle, device_hash = %device_hash, "invalid medium-term key signature");
            continue;
        }
        recipients.push((cert.pk.clone(), medium_pk.medium_pk.clone()));
    }
    if recipients.is_empty() {
        anyhow::bail!("no medium-term keys available for {handle}");
    }
    Ok(recipients)
}

fn recipients_from_peer(
    peer: &PeerInfo,
) -> anyhow::Result<Vec<(DevicePublic, xirtam_crypt::dh::DhPublic)>> {
    collect_recipients(&peer.handle, &peer.certs, &peer.medium_pks)
}

async fn device_auth(client: &GatewayClient, identity: &Identity) -> anyhow::Result<AuthToken> {
    client
        .v1_device_auth(identity.handle.clone(), identity.cert_chain.clone())
        .await?
        .map_err(|err| anyhow::anyhow!(err.to_string()))
}

async fn own_gateway_name(
    ctx: &anyctx::AnyCtx<Config>,
    identity: &Identity,
) -> anyhow::Result<xirtam_structs::gateway::GatewayName> {
    let dir = ctx.get(DIR_CLIENT);
    let descriptor = dir
        .get_handle_descriptor(&identity.handle)
        .await?
        .context("identity handle not in directory")?;
    Ok(descriptor.gateway_name)
}

async fn send_envelope(
    client: &GatewayClient,
    auth: AuthToken,
    mailbox: MailboxId,
    envelope: Envelope,
) -> anyhow::Result<NanoTimestamp> {
    let message = Blob {
        kind: Blob::V1_DIRECT_MESSAGE.into(),
        inner: Bytes::from(bcs::to_bytes(&envelope)?),
    };
    client
        .v1_mailbox_send(auth, mailbox, message)
        .await?
        .map_err(|err| anyhow::anyhow!(err.to_string()))
}

async fn process_mailbox_entry(
    ctx: &anyctx::AnyCtx<Config>,
    gateway_name: &GatewayName,
    mailbox: MailboxId,
    entry: xirtam_structs::gateway::MailboxEntry,
) -> anyhow::Result<()> {
    let db = ctx.get(DATABASE);
    let dir = ctx.get(DIR_CLIENT);
    let identity = Identity::load(db).await?;
    update_mailbox_after(db, gateway_name, mailbox, entry.received_at).await?;
    let message = entry.message;
    if message.kind != Blob::V1_DIRECT_MESSAGE {
        warn!(kind = %message.kind, "ignoring non-dm mailbox entry");
        return Ok(());
    }
    let envelope: Envelope = bcs::from_bytes(&message.inner)?;
    let device_pk = identity.device_secret.public();
    let device_hash = device_pk.bcs_hash();
    let header_count = envelope.headers.len();
    let has_header = envelope.headers.contains_key(&device_hash);
    tracing::debug!(
        received_at = entry.received_at.0,
        header_count,
        has_header,
        device_hash = %device_hash,
        "dm envelope received",
    );
    let decrypted = match envelope.decrypt_message(&device_pk, &identity.medium_sk_current) {
        Ok(decrypted) => {
            tracing::debug!("dm decrypt with current medium key ok");
            decrypted
        }
        Err(err) => {
            tracing::debug!(error = %err, "dm decrypt with current medium key failed");
            match envelope.decrypt_message(&device_pk, &identity.medium_sk_prev) {
                Ok(decrypted) => {
                    tracing::debug!("dm decrypt with previous medium key ok");
                    decrypted
                }
                Err(err) => {
                    tracing::warn!(error = %err, "dm decrypt with previous medium key failed");
                    return Err(anyhow::anyhow!("failed to decrypt envelope"));
                }
            }
        }
    };
    let sender_handle = decrypted.handle().clone();
    let sender_descriptor = dir
        .get_handle_descriptor(&sender_handle)
        .await?
        .context("sender handle not in directory")?;
    let message = decrypted
        .verify(sender_descriptor.root_cert_hash)
        .map_err(|_| anyhow::anyhow!("failed to verify envelope"))?;
    if message.kind != Blob::V1_MESSAGE_CONTENT {
        warn!(kind = %message.kind, "ignoring non-message-content dm");
        return Ok(());
    }
    let content: MessageContent = bcs::from_bytes(&message.inner)?;
    if content.recipient != identity.handle && sender_handle != identity.handle {
        warn!(
            sender = %sender_handle,
            recipient = %content.recipient,
            "ignoring dm with mismatched recipient",
        );
        return Ok(());
    }
    let peer_handle = if sender_handle == identity.handle {
        content.recipient.clone()
    } else {
        sender_handle.clone()
    };
    let mut tx = db.begin().await?;
    sqlx::query(
        "INSERT OR IGNORE INTO dm_messages \
         (peer_handle, sender_handle, mime, body, received_at) \
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(peer_handle.as_str())
    .bind(sender_handle.as_str())
    .bind(content.mime.as_str())
    .bind(content.body.to_vec())
    .bind(entry.received_at.0 as i64)
    .execute(tx.as_mut())
    .await?;
    sqlx::query(
        "UPDATE mailbox_state SET after_timestamp = ? \
         WHERE gateway_name = ? AND mailbox_id = ?",
    )
    .bind(entry.received_at.0 as i64)
    .bind(gateway_name.as_str())
    .bind(mailbox.to_bytes().to_vec())
    .execute(tx.as_mut())
    .await?;
    tx.commit().await?;
    Ok(())
}

struct PendingDm {
    id: i64,
    peer: Handle,
    mime: SmolStr,
    body: Bytes,
}

async fn next_pending_dm(db: &sqlx::SqlitePool) -> anyhow::Result<Option<PendingDm>> {
    let row = sqlx::query_as::<_, (i64, String, String, Vec<u8>)>(
        "SELECT id, peer_handle, mime, body \
         FROM dm_messages \
         WHERE received_at IS NULL \
         ORDER BY id \
         LIMIT 1",
    )
    .fetch_optional(db)
    .await?;
    let Some((id, peer_handle, mime, body)) = row else {
        return Ok(None);
    };
    let peer = Handle::parse(peer_handle).context("invalid peer handle in dm_messages")?;
    Ok(Some(PendingDm {
        id,
        peer,
        mime: SmolStr::new(mime),
        body: Bytes::from(body),
    }))
}
