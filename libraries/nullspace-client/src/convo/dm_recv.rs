use std::time::Duration;

use anyctx::AnyCtx;
use nullspace_crypt::signing::SigningPublic;
use nullspace_structs::e2ee::{DeviceSigned, HeaderEncrypted};
use nullspace_structs::event::Event;
use nullspace_structs::server::{MailboxId, ServerName};
use nullspace_structs::timestamp::NanoTimestamp;

use crate::config::Config;
use crate::database::{
    DATABASE, DbNotify, ensure_mailbox_state, ensure_thread_id, load_mailbox_after,
    update_mailbox_after,
};
use crate::identity::Identity;
use crate::long_poll::LONG_POLLER;
use crate::server::get_server_client;

use super::dm_common::{device_auth, refresh_own_server_name};
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
    let identity = Identity::load(db).await?;
    let server_name = match refresh_own_server_name(ctx, db, &identity).await {
        Ok(name) => name,
        Err(err) => match identity.server_name.clone() {
            Some(name) => {
                tracing::warn!(error = %err, "failed to refresh server name");
                name
            }
            None => return Err(err),
        },
    };
    let server = get_server_client(ctx, &server_name).await?;
    let auth = device_auth(ctx).await?;
    let mailbox = identity.dm_mailbox_id();

    server
        .mailbox_create(auth, identity.dm_mailbox_key)
        .await?
        .map_err(|err| anyhow::anyhow!(err.to_string()))?;

    ensure_mailbox_state(db, &server_name, mailbox, NanoTimestamp(0)).await?;
    let mut after = load_mailbox_after(db, &server_name, mailbox).await?;
    let poller = ctx.get(LONG_POLLER);
    loop {
        let entry = match poller
            .recv(server.clone(), identity.dm_mailbox_key, mailbox, after)
            .await
        {
            Ok(entry) => entry,
            Err(err) => {
                tracing::warn!(error = %err, "mailbox recv error");
                continue;
            }
        };
        after = entry.received_at;
        if let Err(err) = process_mailbox_entry(ctx, &server_name, mailbox, entry).await {
            tracing::warn!(error = %err, "failed to process mailbox entry");
        }
        DbNotify::touch();
    }
}

async fn process_mailbox_entry(
    ctx: &AnyCtx<Config>,
    server_name: &ServerName,
    mailbox: MailboxId,
    entry: nullspace_structs::server::MailboxEntry,
) -> anyhow::Result<()> {
    let db = ctx.get(DATABASE);
    let identity = Identity::load(db).await?;
    update_mailbox_after(db, server_name, mailbox, entry.received_at).await?;

    let encrypted: HeaderEncrypted = bcs::from_bytes(&entry.body.0)?;
    let decrypted = match encrypted.decrypt_bytes(&identity.medium_sk_current) {
        Ok(decrypted) => decrypted,
        Err(err) => {
            tracing::debug!(error = %err, "dm decrypt with current medium key failed");
            encrypted.decrypt_bytes(&identity.medium_sk_prev)?
        }
    };

    let signed: DeviceSigned = bcs::from_bytes(&decrypted)?;
    let sender_username = signed.sender().clone();
    let sender_descriptor = crate::user_info::get_user_descriptor(ctx, &sender_username).await?;
    ensure_sender_device_allowed(&sender_descriptor, signed.sender_device_pk())?;
    let payload = signed
        .verify_bytes()
        .map_err(|_| anyhow::anyhow!("failed to verify device-signed message"))?;
    let event: Event = bcs::from_bytes(&payload)?;

    if event.recipient != identity.username && sender_username != identity.username {
        tracing::warn!(
            sender = %sender_username,
            recipient = %event.recipient,
            "ignoring dm with mismatched recipient",
        );
        return Ok(());
    }

    let peer_username = if sender_username == identity.username {
        event.recipient.clone()
    } else {
        sender_username.clone()
    };

    let mut conn = db.acquire().await?;
    let thread_id = ensure_thread_id(&mut *conn, "direct", peer_username.as_str()).await?;
    let is_valid_link = validate_event_link(&mut conn, thread_id, event.after).await?;
    if !is_valid_link {
        tracing::warn!(
            sender = %sender_username,
            event_after = ?event.after,
            "could not find the event this event is supposed to be after, but accepting regardless",
        );
    }

    let event_hash = event.hash();
    let inserted = sqlx::query(
        "INSERT OR IGNORE INTO thread_events \
         (thread_id, sender_username, event_tag, event_body, event_after, event_hash, sent_at, received_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(thread_id)
    .bind(sender_username.as_str())
    .bind(i64::from(event.tag))
    .bind(event.body.to_vec())
    .bind(event.after.map(|hash| hash.to_bytes().to_vec()))
    .bind(event_hash.to_bytes().to_vec())
    .bind(event.sent_at.0 as i64)
    .bind(entry.received_at.0 as i64)
    .execute(&mut *conn)
    .await?
    .rows_affected();

    if inserted > 0 {
        store_message_attachments(&mut conn, &sender_username, event.tag, &event.body).await?;
    }
    Ok(())
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

fn ensure_sender_device_allowed(
    sender_descriptor: &nullspace_structs::username::UserDescriptor,
    sender_device_pk: SigningPublic,
) -> anyhow::Result<()> {
    if !sender_descriptor.devices.contains(&sender_device_pk) {
        anyhow::bail!("sender device not found in directory state");
    }
    Ok(())
}
