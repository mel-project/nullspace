use std::time::Duration;

use anyctx::AnyCtx;
use nullspace_crypt::hash::BcsHashExt;
use nullspace_crypt::signing::SigningPublic;
use nullspace_structs::Blob;
use nullspace_structs::e2ee::{DeviceSigned, HeaderEncrypted};
use nullspace_structs::event::{Event, EventPayload, Recipient};
use nullspace_structs::server::{MailboxId, ServerName};
use nullspace_structs::timestamp::{NanoTimestamp, Timestamp};
use tracing::warn;

use crate::database::{
    DATABASE, DbNotify, ensure_convo_id, ensure_mailbox_state, load_mailbox_after,
    update_mailbox_after,
};
use crate::identity::Identity;
use crate::long_poll::LONG_POLLER;
use crate::server::get_server_client;
use crate::{attachments::store_attachment_root, config::Config};

use super::dm_common::{device_auth, refresh_own_server_name};

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
    let mailbox = MailboxId::direct(&identity.username);
    ensure_mailbox_state(db, &server_name, mailbox, NanoTimestamp(0)).await?;
    let mut after = load_mailbox_after(db, &server_name, mailbox).await?;
    let poller = ctx.get(LONG_POLLER);
    loop {
        let entry = match poller.recv(server.clone(), auth, mailbox, after).await {
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
        // notify once to prevent thrashing
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
    let message = entry.message;
    if message.kind != Blob::V1_DIRECT_MESSAGE {
        warn!(kind = %message.kind, "ignoring non-dm mailbox entry");
        return Ok(());
    }
    let encrypted: HeaderEncrypted = bcs::from_bytes(&message.inner)?;
    let header_count = encrypted.headers.len();
    let current_mpk = identity.medium_sk_current.public_key();
    let current_mpk_hash = current_mpk.bcs_hash().to_bytes();
    let current_mpk_short = [current_mpk_hash[0], current_mpk_hash[1]];
    let has_header = encrypted
        .headers
        .iter()
        .any(|header| header.receiver_mpk_short == current_mpk_short);
    tracing::debug!(
        received_at = entry.received_at.0,
        header_count,
        has_header,
        "dm header-encrypted message received",
    );
    let decrypted = match encrypted.decrypt_bytes(&identity.medium_sk_current) {
        Ok(decrypted) => {
            tracing::debug!("dm decrypt with current medium key ok");
            decrypted
        }
        Err(err) => {
            tracing::debug!(error = %err, "dm decrypt with current medium key failed");
            match encrypted.decrypt_bytes(&identity.medium_sk_prev) {
                Ok(decrypted) => {
                    tracing::debug!("dm decrypt with previous medium key ok");
                    decrypted
                }
                Err(err) => {
                    tracing::warn!(error = %err, "dm decrypt with previous medium key failed");
                    return Err(anyhow::anyhow!(
                        "failed to decrypt header-encrypted message"
                    ));
                }
            }
        }
    };
    let signed: DeviceSigned = bcs::from_bytes(&decrypted)?;
    let sender_username = signed.sender().clone();
    let sender_descriptor = ctx
        .get(crate::directory::DIR_CLIENT)
        .get_user_descriptor(&sender_username)
        .await?
        .ok_or_else(|| anyhow::anyhow!("sender username not in directory"))?;
    ensure_sender_device_allowed(&sender_descriptor, signed.sender_device_pk())?;
    let message = signed
        .verify_blob()
        .map_err(|_| anyhow::anyhow!("failed to verify device-signed message"))?;
    if message.kind != Blob::V1_MESSAGE_CONTENT {
        warn!(kind = %message.kind, "ignoring non-message-content dm");
        return Ok(());
    }
    let content: Event = bcs::from_bytes(&message.inner)?;
    let recipient = match content.recipient {
        Recipient::User(username) => username,
        Recipient::Group(group_id) => {
            warn!(
                sender = %sender_username,
                group = %group_id,
                "ignoring dm with group recipient",
            );
            return Ok(());
        }
    };
    if recipient != identity.username && sender_username != identity.username {
        warn!(
            sender = %sender_username,
            recipient = %recipient,
            "ignoring dm with mismatched recipient",
        );
        return Ok(());
    }
    let peer_username = if sender_username == identity.username {
        recipient.clone()
    } else {
        sender_username.clone()
    };
    let mut conn = db.acquire().await?;
    if content.mime == nullspace_structs::fragment::Attachment::mime()
        && let Ok(root) =
            serde_json::from_slice::<nullspace_structs::fragment::Attachment>(&content.body)
    {
        let _ = store_attachment_root(&mut conn, &sender_username, &root).await;
    }
    let convo_id = ensure_convo_id(&mut *conn, "direct", peer_username.as_str()).await?;
    sqlx::query(
        "INSERT OR IGNORE INTO convo_messages \
         (convo_id, sender_username, mime, body, sent_at, received_at) \
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(convo_id)
    .bind(sender_username.as_str())
    .bind(content.mime.as_str())
    .bind(content.body.to_vec())
    .bind(content.sent_at.0 as i64)
    .bind(entry.received_at.0 as i64)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

fn ensure_sender_device_allowed(
    sender_descriptor: &nullspace_structs::username::UserDescriptor,
    sender_device_pk: SigningPublic,
) -> anyhow::Result<()> {
    let sender_hash = sender_device_pk.bcs_hash();
    let Some(device) = sender_descriptor.devices.get(&sender_hash) else {
        anyhow::bail!("sender device not found in directory state");
    };
    if !device.active || device.is_expired(Timestamp::now().0) {
        anyhow::bail!("sender device is inactive or expired");
    }
    Ok(())
}
