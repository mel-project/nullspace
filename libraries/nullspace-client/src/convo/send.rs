use std::collections::BTreeMap;
use std::time::Duration;

use anyctx::AnyCtx;
use anyhow::Context;
use bytes::Bytes;
use nullspace_crypt::hash::{BcsHashExt, Hash};
use nullspace_crypt::signing::Signable;
use nullspace_structs::Blob;
use nullspace_structs::certificate::CertificateChain;
use nullspace_structs::e2ee::{DeviceSigned, HeaderEncrypted};
use nullspace_structs::event::EventPayload;
use nullspace_structs::event::{Event, Recipient};
use nullspace_structs::group::GroupMessage;
use nullspace_structs::server::{AuthToken, MailboxId, SignedMediumPk};
use nullspace_structs::timestamp::NanoTimestamp;
use nullspace_structs::username::UserName;
use smol_str::SmolStr;
use tracing::warn;

use crate::database::{DATABASE, DbNotify, ensure_convo_id};
use crate::identity::Identity;
use crate::retry::retry_backoff;
use crate::user_info::{UserInfo, get_user_info};
use crate::{attachments::store_attachment_root, config::Config};

use super::dm_common::own_server_name;
use super::group::{load_group, send_to_group_mailbox};
use super::{ConvoId, parse_convo_id};

pub async fn queue_message(
    tx: &mut sqlx::SqliteConnection,
    convo_id: &ConvoId,
    sender: &UserName,
    mime: &SmolStr,
    body: &Bytes,
) -> anyhow::Result<i64> {
    let counterparty = convo_id.counterparty();
    let convo_id = ensure_convo_id(&mut *tx, convo_id.convo_type(), &counterparty).await?;
    let sent_at = NanoTimestamp::now();
    let row = sqlx::query_as::<_, (i64,)>(
        "INSERT INTO convo_messages \
         (convo_id, sender_username, mime, body, sent_at, received_at) \
         VALUES (?, ?, ?, ?, ?, NULL) \
         RETURNING id",
    )
    .bind(convo_id)
    .bind(sender.as_str())
    .bind(mime.as_str())
    .bind(body.to_vec())
    .bind(sent_at.0 as i64)
    .fetch_one(&mut *tx)
    .await?;
    if mime == nullspace_structs::fragment::FragmentRoot::mime() {
        if let Ok(root) = serde_json::from_slice::<nullspace_structs::fragment::FragmentRoot>(body)
        {
            let _ = store_attachment_root(&mut *tx, sender, &root).await;
        }
    }
    Ok(row.0)
}

pub async fn send_loop(ctx: &AnyCtx<Config>) {
    loop {
        if let Err(err) = send_loop_once(ctx).await {
            tracing::error!(error = %err, "convo send loop error");
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

async fn send_loop_once(ctx: &AnyCtx<Config>) -> anyhow::Result<()> {
    let db = ctx.get(DATABASE);
    let mut notify = DbNotify::new();
    loop {
        let Some(pending) = next_pending_message(db).await? else {
            notify.wait_for_change().await;
            continue;
        };
        let convo_id = match parse_convo_id(&pending.convo_type, &pending.counterparty) {
            Some(convo_id) => convo_id,
            None => {
                let err = anyhow::anyhow!("invalid convo entry");
                let mut conn = db.acquire().await?;
                mark_message_failed(&mut *conn, pending.id, &err).await?;
                DbNotify::touch();
                continue;
            }
        };
        let ctx = ctx.clone();
        match retry_backoff(async move || {
            send_message(
                ctx.clone(),
                &convo_id,
                &pending.mime,
                &pending.body,
                pending.sent_at,
            )
            .await
        })
        .await
        {
            Ok(received_at) => {
                let mut conn = db.acquire().await?;
                mark_message_sent(&mut *conn, pending.id, received_at).await?;
            }
            Err(err) => {
                tracing::warn!(error = %err, "failed to send convo message");
                let mut conn = db.acquire().await?;
                mark_message_failed(&mut *conn, pending.id, &err).await?;
            }
        }
        DbNotify::touch();
    }
}

struct PendingMessage {
    id: i64,
    convo_type: String,
    counterparty: String,
    mime: SmolStr,
    body: Bytes,
    sent_at: NanoTimestamp,
}

async fn next_pending_message(db: &sqlx::SqlitePool) -> anyhow::Result<Option<PendingMessage>> {
    let row = sqlx::query_as::<_, (i64, String, String, String, Vec<u8>, i64)>(
        "SELECT m.id, c.convo_type, c.convo_counterparty, m.mime, m.body, m.sent_at \
         FROM convo_messages m \
         JOIN convos c ON m.convo_id = c.id \
         WHERE m.received_at IS NULL AND m.send_error IS NULL \
         ORDER BY m.id \
         LIMIT 1",
    )
    .fetch_optional(db)
    .await?;
    let Some((id, convo_type, counterparty, mime, body, sent_at)) = row else {
        return Ok(None);
    };
    Ok(Some(PendingMessage {
        id,
        convo_type,
        counterparty,
        mime: SmolStr::new(mime),
        body: Bytes::from(body),
        sent_at: NanoTimestamp(sent_at as u64),
    }))
}

async fn send_message(
    ctx: AnyCtx<Config>,
    convo_id: &ConvoId,
    mime: &SmolStr,
    body: &Bytes,
    sent_at: NanoTimestamp,
) -> anyhow::Result<NanoTimestamp> {
    match convo_id {
        ConvoId::Direct { peer } => send_dm(&ctx, peer, mime, body, sent_at).await,
        ConvoId::Group { group_id } => {
            send_group_message(&ctx, *group_id, mime, body, sent_at).await
        }
    }
}

async fn send_dm(
    ctx: &AnyCtx<Config>,
    peer: &UserName,
    mime: &SmolStr,
    body: &Bytes,
    sent_at: NanoTimestamp,
) -> anyhow::Result<NanoTimestamp> {
    let db = ctx.get(DATABASE);
    let identity = Identity::load(db).await?;
    let content = Event {
        recipient: Recipient::User(peer.clone()),
        sent_at,
        mime: mime.clone(),
        body: body.clone(),
    };
    let message = Blob {
        kind: Blob::V1_MESSAGE_CONTENT.into(),
        inner: Bytes::from(bcs::to_bytes(&content)?),
    };

    let peer_received_at = send_dm_once(ctx, &identity, peer, &message).await?;
    let self_received_at = if identity.username != *peer {
        send_dm_once(ctx, &identity, &identity.username, &message).await?
    } else {
        peer_received_at
    };
    Ok(self_received_at)
}

async fn send_dm_once(
    ctx: &AnyCtx<Config>,
    identity: &Identity,
    target: &UserName,
    message: &Blob,
) -> anyhow::Result<NanoTimestamp> {
    let peer = get_user_info(ctx, target).await?;
    let own_server = own_server_name(ctx, identity).await?;
    let recipients = recipients_from_peer(peer.as_ref())?;

    let auth = if peer.server_name == own_server {
        super::dm_common::device_auth(ctx).await?
    } else {
        AuthToken::anonymous()
    };
    let signed = DeviceSigned::sign_blob(
        message,
        identity.username.clone(),
        identity.cert_chain.clone(),
        &identity.device_secret,
    )?;
    let signed_bytes = bcs::to_bytes(&signed)?;
    let encrypted = HeaderEncrypted::encrypt_bytes(&signed_bytes, recipients)
        .map_err(|_| anyhow::anyhow!("failed to encrypt DM for {target}"))?;
    let message = Blob {
        kind: Blob::V1_DIRECT_MESSAGE.into(),
        inner: Bytes::from(bcs::to_bytes(&encrypted)?),
    };
    let received_at = peer
        .server
        .v1_mailbox_send(auth, MailboxId::direct(target), message, 0)
        .await?
        .map_err(|err| anyhow::anyhow!(err.to_string()))?;
    Ok(received_at)
}

async fn send_group_message(
    ctx: &AnyCtx<Config>,
    group_id: nullspace_structs::group::GroupId,
    mime: &SmolStr,
    body: &Bytes,
    sent_at: NanoTimestamp,
) -> anyhow::Result<NanoTimestamp> {
    let db = ctx.get(DATABASE);
    let identity = Identity::load(db).await?;
    let group = load_group(db, group_id).await?.context("group not found")?;
    let content = Event {
        recipient: Recipient::Group(group.group_id),
        sent_at,
        mime: mime.clone(),
        body: body.clone(),
    };
    let group_message = GroupMessage::encrypt_message(
        &content,
        identity.username.clone(),
        identity.cert_chain.clone(),
        &identity.device_secret,
        &group.group_key_current,
    )
    .map_err(|_| anyhow::anyhow!("failed to encrypt group message"))?;
    let blob = Blob {
        kind: Blob::V1_GROUP_MESSAGE.into(),
        inner: Bytes::from(bcs::to_bytes(&group_message)?),
    };
    send_to_group_mailbox(
        ctx,
        &group,
        MailboxId::group_messages(&group.group_id),
        blob,
    )
    .await
}

fn collect_recipients(
    username: &UserName,
    chains: &BTreeMap<Hash, CertificateChain>,
    medium_pks: &BTreeMap<Hash, SignedMediumPk>,
) -> anyhow::Result<Vec<nullspace_crypt::dh::DhPublic>> {
    let mut recipients = Vec::new();
    for (device_hash, chain) in chains {
        let cert = chain.last_device();
        let cert_hash = cert.pk.bcs_hash();
        if &cert_hash != device_hash {
            warn!(
                username = %username,
                device_hash = %device_hash,
                cert_hash = %cert_hash,
                "device certificate hash mismatch"
            );
            continue;
        }
        let Some(medium_pk) = medium_pks.get(device_hash) else {
            warn!(username = %username, device_hash = %device_hash, "missing medium-term key");
            continue;
        };
        if medium_pk.verify(cert.pk.signing_public()).is_err() {
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
    collect_recipients(&peer.username, &peer.device_chains, &peer.medium_pks)
}

async fn mark_message_sent(
    tx: &mut sqlx::SqliteConnection,
    id: i64,
    received_at: NanoTimestamp,
) -> anyhow::Result<()> {
    sqlx::query("UPDATE convo_messages SET received_at = ? WHERE id = ?")
        .bind(received_at.0 as i64)
        .bind(id)
        .execute(&mut *tx)
        .await?;
    Ok(())
}

async fn mark_message_failed(
    tx: &mut sqlx::SqliteConnection,
    id: i64,
    err: &anyhow::Error,
) -> anyhow::Result<()> {
    let synth_received_at = NanoTimestamp::now();
    sqlx::query("UPDATE convo_messages SET send_error = ?, received_at = ? WHERE id = ?")
        .bind(err.to_string())
        .bind(synth_received_at.0 as i64)
        .bind(id)
        .execute(&mut *tx)
        .await?;
    Ok(())
}
