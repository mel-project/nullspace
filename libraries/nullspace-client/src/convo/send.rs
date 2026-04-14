use std::time::Duration;

use anyctx::AnyCtx;
use anyhow::Context;
use bytes::Bytes;
use nullspace_crypt::hash::Hash;
use nullspace_structs::event::{Event, EventRecipient, MessagePayload, TAG_MESSAGE};
use nullspace_structs::timestamp::NanoTimestamp;
use nullspace_structs::username::UserName;
use tracing::warn;

use crate::convo::{NewThreadEvent, ensure_thread_id, insert_thread_event};
use crate::database::{DATABASE, DbNotify};
use crate::events::emit_event;
use crate::retry::retry_backoff;
use crate::{attachments::store_attachment_root, config::Config};

use super::dm_send::send_dm;
use super::group_send::send_group;
use super::{ConvoId, ThreadEventsRow, parse_convo_id};

pub async fn queue_message(
    tx: &mut sqlx::SqliteConnection,
    convo_id: &ConvoId,
    sender: &UserName,
    event_tag: u16,
    event_body: &Bytes,
) -> anyhow::Result<i64> {
    let recipient = match convo_id {
        ConvoId::Direct { peer } => EventRecipient::Dm(peer.clone()),
        ConvoId::Group { group_id } => EventRecipient::Group(*group_id),
    };

    let counterparty = convo_id.counterparty();
    let thread_id = ensure_thread_id(&mut *tx, convo_id.convo_type(), &counterparty).await?;
    let sent_at = NanoTimestamp::now();

    let event_after = load_latest_committed_thread_hash(&mut *tx, thread_id, None).await?;
    let mut event = Event::default()
        .sender(sender.clone())
        .recipient(recipient)
        .sent_at(sent_at)
        .tag(event_tag)
        .body(event_body.clone());
    if let Some(after) = event_after {
        event = event.after(after);
    }
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
                mark_message_failed(&mut conn, &pending, &err).await?;
                continue;
            }
        };

        let convo_id_emit = convo_id.clone();
        let send_ctx = ctx.clone();
        let mut pending_for_send = pending.clone();
        let mut conn = db.acquire().await?;
        prepare_pending_message_for_send(&mut conn, &convo_id, &mut pending_for_send).await?;
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
                mark_message_failed(&mut conn, &pending, &err).await?;
            }
        }
        emit_event(
            ctx,
            crate::internal::Event::ConvoUpdated {
                convo_id: convo_id_emit,
            },
        );
    }
}

#[derive(Clone)]
struct PendingMessage {
    id: i64,
    thread_id: i64,
    thread_kind: String,
    counterparty: String,
    sender: UserName,
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
        thread_id: row.event.thread_id,
        thread_kind: row.thread_kind,
        counterparty: row.thread_counterparty,
        sender: UserName::parse(&row.event.sender_username).context("invalid sender username")?,
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
            let mut event = Event::default()
                .sender(pending.sender.clone())
                .recipient(EventRecipient::Dm(peer.clone()))
                .sent_at(pending.sent_at)
                .tag(pending.event_tag)
                .body(pending.event_body.clone());
            if let Some(after) = pending.event_after {
                event = event.after(after);
            }
            send_dm(ctx, peer, event).await
        }
        ConvoId::Group { group_id } => {
            let mut event = Event::default()
                .sender(pending.sender.clone())
                .recipient(EventRecipient::Group(*group_id))
                .sent_at(pending.sent_at)
                .tag(pending.event_tag)
                .body(pending.event_body.clone());
            if let Some(after) = pending.event_after {
                event = event.after(after);
            }
            send_group(ctx, group_id, event).await
        }
    }
}

async fn prepare_pending_message_for_send(
    tx: &mut sqlx::SqliteConnection,
    convo_id: &ConvoId,
    pending: &mut PendingMessage,
) -> anyhow::Result<()> {
    let event_after =
        load_latest_committed_thread_hash(&mut *tx, pending.thread_id, Some(pending.id)).await?;
    let recipient = match convo_id {
        ConvoId::Direct { peer } => EventRecipient::Dm(peer.clone()),
        ConvoId::Group { group_id } => EventRecipient::Group(*group_id),
    };
    let mut event = Event::default()
        .sender(pending.sender.clone())
        .recipient(recipient)
        .sent_at(pending.sent_at)
        .tag(pending.event_tag)
        .body(pending.event_body.clone());
    if let Some(after) = event_after {
        event = event.after(after);
    }
    let event_hash = event.hash();
    sqlx::query("UPDATE thread_events SET event_after = ?, event_hash = ? WHERE id = ?")
        .bind(event.after.map(|hash| hash.to_bytes().to_vec()))
        .bind(event_hash.to_bytes().to_vec())
        .bind(pending.id)
        .execute(&mut *tx)
        .await?;
    pending.event_after = event.after;
    Ok(())
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

async fn load_latest_committed_thread_hash(
    tx: &mut sqlx::SqliteConnection,
    thread_id: i64,
    exclude_id: Option<i64>,
) -> anyhow::Result<Option<Hash>> {
    let row = sqlx::query_scalar::<_, Vec<u8>>(
        "SELECT event_hash FROM thread_events \
         WHERE thread_id = ? AND send_error IS NULL AND received_at IS NOT NULL AND (? IS NULL OR id != ?) \
         ORDER BY received_at DESC, id DESC \
         LIMIT 1",
    )
    .bind(thread_id)
    .bind(exclude_id)
    .bind(exclude_id)
    .fetch_optional(&mut *tx)
    .await?;
    row.map(bytes_to_hash).transpose()
}

async fn mark_message_failed(
    tx: &mut sqlx::SqliteConnection,
    pending: &PendingMessage,
    err: &anyhow::Error,
) -> anyhow::Result<()> {
    let synth_received_at = NanoTimestamp::now();
    sqlx::query("UPDATE thread_events SET send_error = ?, received_at = ? WHERE id = ?")
        .bind(err.to_string())
        .bind(synth_received_at.0 as i64)
        .bind(pending.id)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "UPDATE thread_events \
         SET send_error = ?, received_at = ? \
         WHERE thread_id = ? AND id > ? AND received_at IS NULL AND send_error IS NULL",
    )
    .bind(format!("earlier draft send failed: {err}"))
    .bind(synth_received_at.0 as i64)
    .bind(pending.thread_id)
    .bind(pending.id)
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
    let payload: MessagePayload = super::decode_event_body(event_body)?;
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
