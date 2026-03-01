use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use anyctx::AnyCtx;
use anyhow::Context;
use bytes::Bytes;
use nullspace_crypt::hash::{BcsHashExt, Hash};
use nullspace_crypt::signing::Signable;
use nullspace_structs::Blob;
use nullspace_structs::event::{Event, MessagePayload, TAG_MESSAGE};
use nullspace_structs::mailbox::MailboxId;
use nullspace_structs::server::SignedMediumPk;
use nullspace_structs::timestamp::NanoTimestamp;
use nullspace_structs::username::UserName;
use tracing::warn;

use crate::convo::{NewThreadEvent, ensure_thread_id, insert_thread_event};
use crate::database::{DATABASE, DbNotify};
use crate::events::emit_event;
use crate::identity::Identity;
use crate::retry_backoff;
use crate::user_info::{UserInfo, get_user_info};
use crate::{attachments::store_attachment_root, config::Config};

use super::device_crypt::sign_and_encrypt;

use super::{ConvoId, ThreadEventsRow, parse_convo_id};

pub async fn queue_message(
    tx: &mut sqlx::SqliteConnection,
    convo_id: &ConvoId,
    sender: &UserName,
    event_tag: u16,
    event_body: &Bytes,
) -> anyhow::Result<i64> {
    let peer = match convo_id {
        ConvoId::Direct { peer } => peer.clone(),
        ConvoId::Group { .. } => anyhow::bail!("groups are disabled"),
    };

    let counterparty = convo_id.counterparty();
    let thread_id = ensure_thread_id(&mut *tx, convo_id.convo_type(), &counterparty).await?;
    let sent_at = NanoTimestamp::now();

    let event_after = load_latest_thread_hash(&mut *tx, thread_id).await?;
    let event = Event {
        recipient: peer,
        sent_at,
        after: event_after,
        tag: event_tag,
        body: event_body.clone(),
    };
    let event_hash = event.hash();

    let id = insert_thread_event(
        &mut *tx,
        &NewThreadEvent {
            thread_id,
            sender: sender.as_str(),
            event_tag,
            event_body,
            event_after: event.after.as_ref(),
            event_hash: &event_hash,
            sent_at,
            received_at: None,
        },
    )
    .await?
    .expect("queue_message insert should never conflict");

    store_message_attachments(tx, event_tag, event_body).await?;
    Ok(id)
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
        let Some(pending) = next_pending_message(&mut *db.acquire().await?).await? else {
            notify.wait_for_change().await;
            continue;
        };
        let convo_id = match parse_convo_id(&pending.thread_kind, &pending.counterparty) {
            Some(convo_id) => convo_id,
            None => {
                let err = anyhow::anyhow!("invalid convo entry");
                let mut conn = db.acquire().await?;
                mark_message_failed(&mut conn, pending.id, &err).await?;
                continue;
            }
        };

        let convo_id_emit = convo_id.clone();
        let send_ctx = ctx.clone();
        let pending_for_send = pending.clone();
        match retry_backoff(async move || {
            send_message(&send_ctx, &convo_id, &pending_for_send).await
        })
        .await
        {
            Ok(received_at) => {
                let mut conn = db.acquire().await?;
                mark_message_sent(&mut conn, pending.id, received_at).await?;
            }
            Err(err) => {
                tracing::warn!(error = %err, "failed to send convo message");
                let mut conn = db.acquire().await?;
                mark_message_failed(&mut conn, pending.id, &err).await?;
            }
        }
        emit_event(ctx, crate::internal::Event::ConvoUpdated { convo_id: convo_id_emit });
    }
}

#[derive(Clone)]
struct PendingMessage {
    id: i64,
    thread_kind: String,
    counterparty: String,
    event_tag: u16,
    event_body: Bytes,
    event_after: Option<Hash>,
    sent_at: NanoTimestamp,
}

#[derive(sqlx::FromRow)]
struct PendingMessageRow {
    #[sqlx(flatten)]
    event: ThreadEventsRow,
    thread_kind: String,
    thread_counterparty: String,
}

async fn next_pending_message(
    db: &mut sqlx::SqliteConnection,
) -> anyhow::Result<Option<PendingMessage>> {
    let row = sqlx::query_as::<_, PendingMessageRow>(
        "SELECT e.*, t.thread_kind, t.thread_counterparty \
         FROM thread_events e \
         JOIN event_threads t ON e.thread_id = t.id \
         WHERE e.received_at IS NULL AND e.send_error IS NULL \
         ORDER BY e.id \
         LIMIT 1",
    )
    .fetch_optional(&mut *db)
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };

    Ok(Some(PendingMessage {
        id: row.event.id,
        thread_kind: row.thread_kind,
        counterparty: row.thread_counterparty,
        event_tag: u16::try_from(row.event.event_tag).context("invalid event tag")?,
        event_body: Bytes::from(row.event.event_body),
        event_after: row.event.event_after.map(bytes_to_hash).transpose()?,
        sent_at: NanoTimestamp(row.event.sent_at as u64),
    }))
}

async fn send_message(
    ctx: &AnyCtx<Config>,
    convo_id: &ConvoId,
    pending: &PendingMessage,
) -> anyhow::Result<NanoTimestamp> {
    match convo_id {
        ConvoId::Direct { peer } => {
            let event = Event {
                recipient: peer.clone(),
                sent_at: pending.sent_at,
                after: pending.event_after,
                tag: pending.event_tag,
                body: pending.event_body.clone(),
            };
            send_dm(ctx, peer, event).await
        }
        ConvoId::Group { .. } => anyhow::bail!("groups are disabled"),
    }
}

async fn send_dm(
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

async fn mark_message_sent(
    tx: &mut sqlx::SqliteConnection,
    id: i64,
    received_at: NanoTimestamp,
) -> anyhow::Result<()> {
    sqlx::query("UPDATE thread_events SET received_at = ? WHERE id = ?")
        .bind(received_at.0 as i64)
        .bind(id)
        .execute(&mut *tx)
        .await?;
    Ok(())
}

async fn load_latest_thread_hash(
    tx: &mut sqlx::SqliteConnection,
    thread_id: i64,
) -> anyhow::Result<Option<Hash>> {
    let row = sqlx::query_scalar::<_, Vec<u8>>(
        "SELECT event_hash FROM thread_events \
         WHERE thread_id = ? AND send_error IS NULL \
         ORDER BY id DESC \
         LIMIT 1",
    )
    .bind(thread_id)
    .fetch_optional(&mut *tx)
    .await?;
    row.map(bytes_to_hash).transpose()
}

async fn mark_message_failed(
    tx: &mut sqlx::SqliteConnection,
    id: i64,
    err: &anyhow::Error,
) -> anyhow::Result<()> {
    let synth_received_at = NanoTimestamp::now();
    sqlx::query("UPDATE thread_events SET send_error = ?, received_at = ? WHERE id = ?")
        .bind(err.to_string())
        .bind(synth_received_at.0 as i64)
        .bind(id)
        .execute(&mut *tx)
        .await?;
    Ok(())
}

pub(super) async fn store_message_attachments(
    tx: &mut sqlx::SqliteConnection,
    event_tag: u16,
    event_body: &Bytes,
) -> anyhow::Result<()> {
    if event_tag != TAG_MESSAGE {
        return Ok(());
    }
    let payload: MessagePayload = bcs::from_bytes(event_body)?;
    for attachment in payload.attachments {
        if let Err(err) = store_attachment_root(&mut *tx, &attachment).await {
            warn!(error = %err, "failed to store outgoing attachment root");
        }
    }
    for image in payload.images {
        if let Err(err) = store_attachment_root(&mut *tx, &image.inner).await {
            warn!(error = %err, "failed to store outgoing image attachment root");
        }
    }
    Ok(())
}

fn bytes_to_hash(value: Vec<u8>) -> anyhow::Result<Hash> {
    let raw: [u8; 32] = value
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid hash length"))?;
    Ok(Hash::from_bytes(raw))
}
