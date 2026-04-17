use std::time::Duration;

use anyctx::AnyCtx;
use nullspace_structs::e2ee::DeviceSigned;
use nullspace_structs::event::{
    Event, EventRecipient, GroupPermissionChange, GroupSettingsChange, GroupUnban,
    TAG_GROUP_PERMISSION_CHANGE, TAG_GROUP_SETTINGS_CHANGE, TAG_GROUP_UNBAN, TAG_JOIN_REQUEST,
    TAG_LEAVE_REQUEST, TAG_ROTATION_HINT,
};
use nullspace_structs::group::{GroupBearerKey, GroupId, MemberState};
use nullspace_structs::mailbox::MailboxEntry;
use nullspace_structs::server::ServerName;
use tokio::task::JoinSet;

use crate::api::Event as ApiEvent;
use crate::config::Config;
use crate::database::{DATABASE, DbNotify};
use crate::events::emit_event;
use crate::storage::{
    NewThreadEvent, ensure_thread_id, insert_thread_event, load_mailbox_after, load_roster,
    replace_current_roster, thread_accepts_event_link, update_mailbox_after,
};
use crate::transport::LONG_POLLER;

use super::ConvoId;
use super::groups::refresh_group_state;
use super::send::store_message_attachments;

pub async fn group_recv_loop(ctx: &AnyCtx<Config>) {
    loop {
        if let Err(err) = group_recv_loop_once(ctx).await {
            tracing::error!(error = %err, "group recv loop error");
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

#[derive(Clone, PartialEq, Eq, sqlx::FromRow)]
struct ActiveGroupKey {
    group_id: Vec<u8>,
    rotation_index: i64,
    gbk: Vec<u8>,
    server_name: String,
}

async fn load_active_keys(
    conn: &mut sqlx::SqliteConnection,
) -> anyhow::Result<Vec<ActiveGroupKey>> {
    Ok(sqlx::query_as::<_, ActiveGroupKey>(
        "SELECT group_id, rotation_index, gbk, server_name FROM group_keys",
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

    match join_set.join_next().await {
        Some(Ok(result)) => result,
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
    let mailbox_key = gbk.mailbox_key();
    let mailbox_id = mailbox_key.mailbox_id();

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
                emit_event(ctx, ApiEvent::ConvoUpdated { convo_id });
            }
            Ok(ProcessResult::RotationHint) => {
                match refresh_group_state(ctx, group_id).await {
                    Ok(true) => emit_event(
                        ctx,
                        ApiEvent::ConvoUpdated {
                            convo_id: ConvoId::Group { group_id },
                        },
                    ),
                    Ok(false) => tracing::debug!(
                        group = %group_id,
                        rotation_index,
                        "rotation hint received but no newer rotation found"
                    ),
                    Err(err) => tracing::warn!(
                        error = %err,
                        group = %group_id,
                        "failed to refresh group state after hint"
                    ),
                }
                return Ok(());
            }
            Ok(ProcessResult::Skip) => {}
            Err(err) => {
                tracing::warn!(error = %err, group = %group_id, "failed to process group entry");
            }
        }
    }
}

enum ProcessResult {
    Message(ConvoId),
    RotationHint,
    Skip,
}

enum MessageAuthorization {
    Accept,
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

    if event.tag == TAG_ROTATION_HINT {
        tracing::info!(group = %group_id, "received rotation hint");
        return Ok(ProcessResult::RotationHint);
    }

    let convo_id = ConvoId::Group { group_id };
    let mut conn = db.acquire().await?;
    let thread_id =
        ensure_thread_id(&mut conn, convo_id.convo_type(), &convo_id.counterparty()).await?;
    if !thread_accepts_event_link(&mut conn, thread_id, event.after.as_ref()).await? {
        tracing::warn!(
            sender = %sender,
            event_after = ?event.after,
            group = %group_id,
            "dropping group event with unknown event parent",
        );
        return Ok(ProcessResult::Skip);
    }
    drop(conn);

    if let Some(result) =
        try_apply_roster_event(ctx, group_id, thread_id, &sender, &event, entry.received_at).await?
    {
        return Ok(result);
    }

    match authorize_regular_event(ctx, group_id, &sender).await? {
        MessageAuthorization::Accept => {}
        MessageAuthorization::Skip => return Ok(ProcessResult::Skip),
    }

    let mut conn = db.acquire().await?;
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

async fn authorize_regular_event(
    ctx: &AnyCtx<Config>,
    group_id: GroupId,
    sender: &nullspace_structs::username::UserName,
) -> anyhow::Result<MessageAuthorization> {
    let db = ctx.get(DATABASE);
    let mut conn = db.acquire().await?;
    let (_, roster) = match load_roster(&mut conn, group_id).await {
        Ok(roster) => roster,
        Err(err) => {
            tracing::warn!(group = %group_id, error = %err, "no roster for received group event");
            return Ok(MessageAuthorization::Skip);
        }
    };

    if roster.banned.contains(sender) {
        tracing::warn!(group = %group_id, sender = %sender, "banned user sent group event");
        return Ok(MessageAuthorization::Skip);
    }

    match roster.members.get(sender) {
        Some(member) if member.is_muted => {
            tracing::warn!(group = %group_id, sender = %sender, "muted user sent group event");
            Ok(MessageAuthorization::Skip)
        }
        Some(_) => Ok(MessageAuthorization::Accept),
        None => {
            tracing::warn!(group = %group_id, sender = %sender, "non-member sent regular group event");
            Ok(MessageAuthorization::Skip)
        }
    }
}

async fn try_apply_roster_event(
    ctx: &AnyCtx<Config>,
    group_id: GroupId,
    thread_id: i64,
    sender: &nullspace_structs::username::UserName,
    event: &Event,
    received_at: nullspace_structs::timestamp::NanoTimestamp,
) -> anyhow::Result<Option<ProcessResult>> {
    let tag = event.tag;
    if !matches!(
        tag,
        TAG_GROUP_PERMISSION_CHANGE
            | TAG_GROUP_SETTINGS_CHANGE
            | TAG_GROUP_UNBAN
            | TAG_JOIN_REQUEST
            | TAG_LEAVE_REQUEST
    ) {
        return Ok(None);
    }

    let db = ctx.get(DATABASE);
    let mut conn = db.acquire().await?;
    let (rotation_index, mut roster) = match load_roster(&mut conn, group_id).await {
        Ok(roster) => roster,
        Err(err) => {
            tracing::warn!(group = %group_id, error = %err, "no roster to apply admin action");
            return Ok(Some(ProcessResult::Skip));
        }
    };

    let sender_is_admin = roster
        .members
        .get(sender)
        .is_some_and(|member| member.is_admin);
    let sender_is_member = roster.members.contains_key(sender);
    if tag == TAG_JOIN_REQUEST {
        if roster.banned.contains(sender) {
            tracing::warn!(group = %group_id, sender = %sender, "banned user sent join request");
            return Ok(Some(ProcessResult::Skip));
        }
    } else if tag == TAG_LEAVE_REQUEST {
        if !sender_is_member {
            tracing::warn!(group = %group_id, sender = %sender, "non-member sent leave request");
            return Ok(Some(ProcessResult::Skip));
        }
    } else if !sender_is_admin {
        tracing::warn!(group = %group_id, sender = %sender, "non-admin sent admin action");
        return Ok(Some(ProcessResult::Skip));
    }

    apply_roster_delta(&mut roster, sender, event)?;
    replace_current_roster(&mut conn, group_id, rotation_index, &roster).await?;

    let event_hash = event.hash();
    insert_thread_event(
        &mut conn,
        &NewThreadEvent {
            thread_id,
            sender: sender.as_str(),
            event_tag: event.tag,
            event_body: &event.body,
            event_after: event.after.as_ref(),
            event_hash: &event_hash,
            sent_at: event.sent_at,
            received_at: Some(received_at),
        },
    )
    .await?;

    emit_event(
        ctx,
        ApiEvent::ConvoUpdated {
            convo_id: ConvoId::Group { group_id },
        },
    );
    Ok(Some(ProcessResult::Skip))
}

fn apply_roster_delta(
    roster: &mut nullspace_structs::group::GroupRoster,
    sender: &nullspace_structs::username::UserName,
    event: &Event,
) -> anyhow::Result<()> {
    match event.tag {
        TAG_GROUP_PERMISSION_CHANGE => {
            let change: GroupPermissionChange = event.decode_body()?;
            if let Some(member) = roster.members.get_mut(&change.username) {
                member.is_muted = change.muted;
            }
            Ok(())
        }
        TAG_GROUP_SETTINGS_CHANGE => {
            let change: GroupSettingsChange = event.decode_body()?;
            roster.metadata.title = change.title.clone();
            roster.metadata.description = change.description.clone();
            roster.settings.new_members_muted = change.new_members_muted;
            roster.settings.allow_new_members_to_see_history =
                change.allow_new_members_to_see_history;
            Ok(())
        }
        TAG_GROUP_UNBAN => {
            let change: GroupUnban = event.decode_body()?;
            roster.banned.remove(&change.username);
            Ok(())
        }
        TAG_JOIN_REQUEST => {
            roster.members.entry(sender.clone()).or_insert(MemberState {
                is_admin: false,
                is_muted: roster.settings.new_members_muted,
            });
            Ok(())
        }
        TAG_LEAVE_REQUEST => {
            roster.members.remove(sender);
            Ok(())
        }
        _ => Ok(()),
    }
}
