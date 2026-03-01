use std::time::Duration;

use anyctx::AnyCtx;
use nullspace_structs::event::Event;
use nullspace_structs::mailbox::{MailboxEntry, MailboxId};
use nullspace_structs::server::ServerName;

use crate::auth_tokens::get_auth_token;
use crate::config::Config;
use crate::convo::{NewThreadEvent, THREAD_KIND_DIRECT, ensure_thread_id, insert_thread_event};
use crate::database::DATABASE;
use crate::events::emit_event;
use crate::identity::Identity;
use crate::long_poll::LONG_POLLER;
use crate::mailbox::{load_mailbox_after, update_mailbox_after};
use crate::server::{get_server_client, own_server_name};

use super::device_crypt::decrypt_and_verify;
use super::send::store_message_attachments;

pub(super) async fn dm_recv_loop(ctx: &AnyCtx<Config>) {
    loop {
        if let Err(err) = dm_recv_loop_once(ctx).await {
            tracing::error!(error = %err, "dm recv loop error");
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

async fn dm_recv_loop_once(ctx: &AnyCtx<Config>) -> anyhow::Result<()> {
    let db = ctx.get(DATABASE);
    // let mut conn = db.acquire().await?;
    let identity = Identity::load(&mut *db.acquire().await?).await?;
    let server_name = own_server_name(ctx, &identity).await?;
    let server = get_server_client(ctx, &server_name).await?;
    let auth = get_auth_token(ctx).await?;
    let mailbox = identity.dm_mailbox_id();
    server
        .mailbox_create(auth, identity.dm_mailbox_key)
        .await?
        .map_err(|err| anyhow::anyhow!(err.to_string()))?;

    let mut after = load_mailbox_after(&mut *db.acquire().await?, &server_name, mailbox).await?;
    let poller = ctx.get(LONG_POLLER);
    loop {
        let entry = match poller
            .recv(server_name.clone(), identity.dm_mailbox_key, mailbox, after)
            .await
        {
            Ok(entry) => entry,
            Err(err) => {
                tracing::warn!(error = %err, "mailbox recv error");
                continue;
            }
        };
        after = entry.received_at;
        match process_mailbox_entry(ctx, &server_name, mailbox, entry).await {
            Ok(Some(convo_id)) => {
                emit_event(ctx, crate::internal::Event::ConvoUpdated { convo_id });
            }
            Ok(None) => {}
            Err(err) => {
                tracing::warn!(error = %err, "failed to process mailbox entry");
            }
        }
    }
}

async fn process_mailbox_entry(
    ctx: &AnyCtx<Config>,
    server_name: &ServerName,
    mailbox: MailboxId,
    entry: MailboxEntry,
) -> anyhow::Result<Option<super::ConvoId>> {
    let db = ctx.get(DATABASE);
    let identity = Identity::load(&mut *db.acquire().await?).await?;
    update_mailbox_after(
        &mut *db.acquire().await?,
        server_name,
        mailbox,
        entry.received_at,
    )
    .await?;

    let verified = decrypt_and_verify(ctx, &identity, &entry.body.0).await?;
    let event: Event = bcs::from_bytes(&verified.payload)?;

    if event.recipient != identity.username && verified.sender != identity.username {
        tracing::warn!(
            sender = %verified.sender,
            recipient = %event.recipient,
            "ignoring dm with mismatched recipient",
        );
        return Ok(None);
    }

    let peer_username = if verified.sender == identity.username {
        event.recipient.clone()
    } else {
        verified.sender.clone()
    };

    let mut conn = db.acquire().await?;
    let thread_id = ensure_thread_id(&mut conn, THREAD_KIND_DIRECT, peer_username.as_str()).await?;
    let is_valid_link = validate_event_link(&mut conn, thread_id, event.after).await?;
    if !is_valid_link {
        tracing::warn!(
            sender = %verified.sender,
            event_after = ?event.after,
            "could not find the event this event is supposed to be after, but accepting regardless",
        );
    }

    let event_hash = event.hash();
    let inserted = insert_thread_event(
        &mut conn,
        &NewThreadEvent {
            thread_id,
            sender: verified.sender.as_str(),
            event_tag: event.tag,
            event_body: &event.body,
            event_after: event.after.as_ref(),
            event_hash: &event_hash,
            sent_at: event.sent_at,
            received_at: Some(entry.received_at),
        },
    )
    .await?;

    if inserted.is_some() {
        store_message_attachments(&mut conn, event.tag, &event.body).await?;
        Ok(Some(super::ConvoId::Direct {
            peer: peer_username,
        }))
    } else {
        Ok(None)
    }
}

async fn validate_event_link(
    conn: &mut sqlx::SqliteConnection,
    thread_id: i64,
    event_after: Option<nullspace_crypt::hash::Hash>,
) -> anyhow::Result<bool> {
    match event_after {
        Some(prev_hash) => {
            let exists = sqlx::query_scalar::<_, i64>(
                "SELECT 1 FROM thread_events WHERE thread_id = ? AND event_hash = ? LIMIT 1",
            )
            .bind(thread_id)
            .bind(prev_hash.to_bytes().to_vec())
            .fetch_optional(&mut *conn)
            .await?;
            Ok(exists.is_some())
        }
        None => {
            let has_any = sqlx::query_scalar::<_, i64>(
                "SELECT 1 FROM thread_events WHERE thread_id = ? LIMIT 1",
            )
            .bind(thread_id)
            .fetch_optional(&mut *conn)
            .await?;
            Ok(has_any.is_none())
        }
    }
}

