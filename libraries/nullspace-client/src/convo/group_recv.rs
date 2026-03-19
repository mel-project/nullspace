use std::time::Duration;

use anyctx::AnyCtx;
use nullspace_crypt::signing::Signable;
use nullspace_structs::e2ee::DeviceSigned;
use nullspace_structs::event::{Event, EventRecipient, TAG_ROTATION_HINT};
use nullspace_structs::group::{GroupBearerKey, GroupId};
use nullspace_structs::mailbox::MailboxEntry;
use nullspace_structs::server::ServerName;
use tokio::task::JoinSet;

use crate::net::get_auth_token;
use crate::config::Config;
use crate::convo::{ConvoId, NewThreadEvent, ensure_thread_id, insert_thread_event};
use crate::database::{DATABASE, DbNotify};
use crate::events::emit_event;
use super::groups::store_gbk;
use crate::identity::Identity;
use crate::net::LONG_POLLER;
use crate::net::{load_mailbox_after, update_mailbox_after};
use crate::net::get_server_client;

use super::send::store_message_attachments;

pub(super) async fn group_recv_loop(ctx: &AnyCtx<Config>) {
    loop {
        if let Err(err) = group_recv_loop_once(ctx).await {
            tracing::error!(error = %err, "group recv loop error");
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

/// A row from the group_keys table representing an active GBK to poll.
#[derive(Clone, PartialEq, Eq, sqlx::FromRow)]
struct ActiveGroupKey {
    group_id: Vec<u8>,
    rotation_index: i64,
    gbk: Vec<u8>,
    server_name: String,
}

/// Load the last 2 GBKs per group (current + previous for overlap).
async fn load_active_keys(
    conn: &mut sqlx::SqliteConnection,
) -> anyhow::Result<Vec<ActiveGroupKey>> {
    Ok(sqlx::query_as::<_, ActiveGroupKey>(
        "SELECT group_id, rotation_index, gbk, server_name FROM group_keys k \
         WHERE rotation_index >= \
           (SELECT MAX(k2.rotation_index) - 1 FROM group_keys k2 WHERE k2.group_id = k.group_id)",
    )
    .fetch_all(&mut *conn)
    .await?)
}

async fn group_recv_loop_once(ctx: &AnyCtx<Config>) -> anyhow::Result<()> {
    let db = ctx.get(DATABASE);
    let rows = load_active_keys(&mut *db.acquire().await?).await?;

    if rows.is_empty() {
        return Ok(());
    }

    let snapshot = rows.clone();
    let mut join_set = JoinSet::new();

    for row in rows {
        let gid_arr: [u8; 16] = row
            .group_id
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid group_id length"))?;
        let group_id = GroupId::from_bytes(gid_arr);
        let rotation_index = row.rotation_index as u64;
        let gbk = bcs::from_bytes::<GroupBearerKey>(&row.gbk)?;
        let server_name = ServerName::parse(row.server_name)?;
        let ctx = ctx.clone();
        join_set.spawn(async move {
            poll_single_group(&ctx, group_id, rotation_index, gbk, server_name).await
        });
    }

    // Restart only when the group_keys table actually changes
    let ctx_notify = ctx.clone();
    join_set.spawn(async move {
        let db = ctx_notify.get(DATABASE);
        let mut notify = DbNotify::new();
        loop {
            let current = load_active_keys(&mut *db.acquire().await?).await?;
            if current != snapshot {
                return Ok(());
            }
            notify.wait_for_change().await;
        }
    });

    // Wait for any task to complete — JoinSet aborts the rest on drop
    let result = join_set.join_next().await;
    match result {
        Some(Ok(inner)) => inner,
        Some(Err(err)) => Err(err.into()),
        None => Ok(()),
    }
}

async fn poll_single_group(
    ctx: &AnyCtx<Config>,
    group_id: GroupId,
    rotation_index: u64,
    gbk: GroupBearerKey,
    server_name: ServerName,
) -> anyhow::Result<()> {
    let db = ctx.get(DATABASE);
    let server = get_server_client(ctx, &server_name).await?;
    let auth = get_auth_token(ctx).await?;
    let mailbox_key = gbk.mailbox_key();
    let mailbox_id = mailbox_key.mailbox_id();

    server
        .mailbox_create(auth, mailbox_key)
        .await?
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;

    let mut after = load_mailbox_after(&mut *db.acquire().await?, &server_name, mailbox_id).await?;
    let poller = ctx.get(LONG_POLLER);

    loop {
        let entry = match poller
            .recv(server_name.clone(), mailbox_key, mailbox_id, after)
            .await
        {
            Ok(entry) => entry,
            Err(err) => {
                tracing::warn!(error = %err, group = %group_id, "group mailbox recv error");
                continue;
            }
        };
        after = entry.received_at;
        match process_group_entry(ctx, group_id, &gbk, &server_name, mailbox_id, entry).await {
            Ok(ProcessResult::Message(convo_id)) => {
                emit_event(ctx, crate::internal::Event::ConvoUpdated { convo_id });
            }
            Ok(ProcessResult::RotationHint) => {
                // Check registry for the new rotation and adopt it inline
                if let Err(err) =
                    check_and_adopt_rotation(ctx, group_id, rotation_index, &server_name).await
                {
                    tracing::warn!(error = %err, group = %group_id, "failed to adopt rotation after hint");
                }
                // Restart the loop regardless — DbNotify from store_gbk will
                // wake group_recv_loop_once if adoption succeeded
                return Ok(());
            }
            Ok(ProcessResult::Skip) => {}
            Err(err) => {
                tracing::warn!(error = %err, group = %group_id, "failed to process group entry");
            }
        }
    }
}

/// After receiving a rotation hint, check the server for the next rotation
/// index and adopt it if present.
async fn check_and_adopt_rotation(
    ctx: &AnyCtx<Config>,
    group_id: GroupId,
    current_index: u64,
    server_name: &ServerName,
) -> anyhow::Result<()> {
    let server = get_server_client(ctx, server_name).await?;

    let new_rotation = match server.group_get(group_id, current_index + 1).await? {
        Ok(Some(rot)) => rot,
        Ok(None) => {
            tracing::debug!(group = %group_id, "hint received but no new rotation found yet");
            return Ok(());
        }
        Err(e) => anyhow::bail!("group_get failed: {e}"),
    };

    tracing::info!(group = %group_id, index = current_index + 1, "adopting new rotation");

    new_rotation
        .verify(new_rotation.signer)
        .map_err(|_| anyhow::anyhow!("rotation signature verification failed"))?;

    let db = ctx.get(DATABASE);
    let identity = Identity::load(&mut *db.acquire().await?).await?;

    let gbk_bytes = new_rotation
        .gbk_rotation
        .decrypt_bytes(&identity.medium_sk_current)
        .or_else(|_| {
            new_rotation
                .gbk_rotation
                .decrypt_bytes(&identity.medium_sk_prev)
        })
        .map_err(|_| anyhow::anyhow!("failed to decrypt GBK rotation (not a recipient?)"))?;

    let new_gbk: GroupBearerKey = bcs::from_bytes(&gbk_bytes)?;

    let auth = get_auth_token(ctx).await?;
    server
        .mailbox_create(auth, new_gbk.mailbox_key())
        .await?
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;

    let mut conn = db.acquire().await?;
    store_gbk(
        &mut conn,
        group_id,
        &new_gbk,
        server_name,
        new_rotation.index,
    )
    .await?;

    tracing::info!(group = %group_id, index = new_rotation.index, "adopted new GBK");
    Ok(())
}

enum ProcessResult {
    Message(ConvoId),
    RotationHint,
    Skip,
}

async fn process_group_entry(
    ctx: &AnyCtx<Config>,
    group_id: GroupId,
    gbk: &GroupBearerKey,
    server_name: &ServerName,
    mailbox_id: nullspace_structs::mailbox::MailboxId,
    entry: MailboxEntry,
) -> anyhow::Result<ProcessResult> {
    let db = ctx.get(DATABASE);
    update_mailbox_after(
        &mut *db.acquire().await?,
        server_name,
        mailbox_id,
        entry.received_at,
    )
    .await?;

    // Strip 24-byte nonce prefix, then AEAD decrypt
    let raw = &entry.body.0;
    if raw.len() < 24 {
        anyhow::bail!("group message too short (no nonce)");
    }
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&raw[..24]);
    let ciphertext = &raw[24..];

    let sym_key = gbk.symmetric_key();
    let signed_bytes = sym_key
        .decrypt(nonce, ciphertext, &[])
        .map_err(|_| anyhow::anyhow!("group message decryption failed"))?;

    // Verify device signature
    let signed: DeviceSigned = bcs::from_bytes(&signed_bytes)?;
    let sender = signed.sender().clone();
    let descriptor = crate::users::get_user_descriptor(ctx, &sender).await?;
    if !descriptor.devices.contains(&signed.sender_device_pk()) {
        anyhow::bail!("group message sender device not in directory");
    }
    let event_bytes = signed
        .verify_bytes()
        .map_err(|_| anyhow::anyhow!("group message device signature failed"))?;

    let event: Event = bcs::from_bytes(&event_bytes)?;

    // Validate context — must target this exact group
    match &event.recipient {
        EventRecipient::Group(gid) if *gid == group_id => {}
        EventRecipient::Group(gid) => {
            anyhow::bail!("group id mismatch: expected {group_id}, got {gid}");
        }
        EventRecipient::Dm(_) => {
            anyhow::bail!("DM event arriving in group mailbox (context mismatch)");
        }
    }

    if event.sender != sender {
        tracing::warn!(
            event_sender = %event.sender,
            verified_sender = %sender,
            "ignoring group event with sender mismatch",
        );
        return Ok(ProcessResult::Skip);
    }

    // Handle rotation hints — don't insert, just signal restart
    if event.tag == TAG_ROTATION_HINT {
        tracing::info!(group = %group_id, "received rotation hint");
        return Ok(ProcessResult::RotationHint);
    }

    let convo_id = ConvoId::Group { group_id };
    let mut conn = db.acquire().await?;
    let thread_id =
        ensure_thread_id(&mut conn, convo_id.convo_type(), &convo_id.counterparty()).await?;

    let event_hash = event.hash();
    let inserted = insert_thread_event(
        &mut conn,
        &NewThreadEvent {
            thread_id,
            sender: sender.as_str(),
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
        Ok(ProcessResult::Message(convo_id))
    } else {
        Ok(ProcessResult::Skip)
    }
}
