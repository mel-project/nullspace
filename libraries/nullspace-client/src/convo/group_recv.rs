use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use anyctx::AnyCtx;
use anyhow::Context;
use futures_concurrency::future::Race;
use nullspace_structs::Blob;
use nullspace_structs::event::{Event, EventPayload, Recipient};
use nullspace_structs::group::{GroupId, GroupManageMsg, GroupMessage};
use nullspace_structs::server::MailboxId;
use nullspace_structs::timestamp::NanoTimestamp;
use tracing::warn;

use crate::database::{
    DATABASE, DbNotify, ensure_convo_id, ensure_mailbox_state, load_mailbox_after,
    update_mailbox_after,
};
use crate::long_poll::LONG_POLLER;
use crate::server::get_server_client;
use crate::{attachments::store_attachment_root, config::Config};

use super::ConvoId;
use super::group::{GroupRecord, load_group, load_groups};
use super::rekey::process_group_rekey_entry;
use super::roster::GroupRoster;

#[derive(Clone, Copy)]
enum GroupMailboxKind {
    Messages,
    Management,
}

type GroupRecvResult = (
    GroupMailboxKind,
    MailboxId,
    nullspace_structs::server::MailboxEntry,
);

pub(super) async fn group_recv_loop(ctx: &AnyCtx<Config>) {
    let mut tasks = scopeguard::guard(
        BTreeMap::<ConvoId, tokio::task::JoinHandle<()>>::new(),
        |tasks| {
            for (_, handle) in tasks {
                handle.abort();
            }
        },
    );
    let mut notify = DbNotify::new();
    loop {
        if let Err(err) = sync_group_tasks(ctx, &mut *tasks).await {
            tracing::warn!(error = %err, "failed to sync group recv tasks");
        }
        notify.wait_for_change().await;
    }
}

async fn sync_group_tasks(
    ctx: &AnyCtx<Config>,
    tasks: &mut BTreeMap<ConvoId, tokio::task::JoinHandle<()>>,
) -> anyhow::Result<()> {
    tasks.retain(|_, handle| !handle.is_finished());
    let db = ctx.get(DATABASE);
    let groups = load_groups(db).await?;
    let mut live: BTreeSet<ConvoId> = BTreeSet::new();
    for group in groups {
        let convo_id = ConvoId::Group {
            group_id: group.group_id,
        };
        live.insert(convo_id.clone());
        if !tasks.contains_key(&convo_id) {
            let ctx = ctx.clone();
            let group_id = group.group_id;
            let handle = tokio::spawn(async move {
                group_recv_task(ctx, group_id).await;
            });
            tasks.insert(convo_id, handle);
        }
    }
    tasks.retain(|convo_id, handle| {
        if live.contains(convo_id) {
            true
        } else {
            handle.abort();
            false
        }
    });
    Ok(())
}

async fn group_recv_task(ctx: AnyCtx<Config>, group_id: GroupId) {
    loop {
        let db = ctx.get(DATABASE);
        let group = match load_group(db, group_id).await {
            Ok(Some(group)) => group,
            Ok(None) => return,
            Err(err) => {
                tracing::warn!(error = %err, group = ?group_id, "failed to load group");
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }
        };
        if let Err(err) = group_recv_once(&ctx, &group).await {
            tracing::warn!(error = %err, group = ?group.group_id, "group recv error");
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }
}

async fn group_recv_once(ctx: &AnyCtx<Config>, group: &GroupRecord) -> anyhow::Result<()> {
    let db = ctx.get(DATABASE);
    let poller = ctx.get(LONG_POLLER);
    let message_box = MailboxId::group_messages(&group.group_id);
    let manage_box = MailboxId::group_management(&group.group_id);
    ensure_mailbox_state(db, &group.server_name, message_box, NanoTimestamp(0)).await?;
    ensure_mailbox_state(db, &group.server_name, manage_box, NanoTimestamp(0)).await?;
    let message_after = load_mailbox_after(db, &group.server_name, message_box).await?;
    let manage_after = load_mailbox_after(db, &group.server_name, manage_box).await?;
    let server = get_server_client(ctx, &group.server_name).await?;
    let token = group.token;
    let server_messages = server.clone();
    let server_manage = server.clone();
    let message_fut = async {
        let entry = poller
            .clone()
            .recv(server_messages, token, message_box, message_after)
            .await?;
        Ok::<_, anyhow::Error>((GroupMailboxKind::Messages, message_box, entry))
    };
    let manage_fut = async {
        let entry = poller
            .clone()
            .recv(server_manage, token, manage_box, manage_after)
            .await?;
        Ok::<_, anyhow::Error>((GroupMailboxKind::Management, manage_box, entry))
    };
    let (kind, mailbox, entry): GroupRecvResult = (message_fut, manage_fut).race().await?;

    update_mailbox_after(db, &group.server_name, mailbox, entry.received_at).await?;
    let result = match kind {
        GroupMailboxKind::Messages => process_group_message_entry(ctx, group, entry).await,
        GroupMailboxKind::Management => process_group_management_entry(ctx, group, entry).await,
    };
    if let Err(err) = result {
        warn!(error = %err, group = ?group.group_id, "failed to process group entry");
    } else {
        DbNotify::touch();
    }
    Ok(())
}

async fn process_group_message_entry(
    ctx: &AnyCtx<Config>,
    group: &GroupRecord,
    entry: nullspace_structs::server::MailboxEntry,
) -> anyhow::Result<()> {
    let db = ctx.get(DATABASE);
    let message = entry.message;
    if message.kind == Blob::V1_GROUP_REKEY {
        return process_group_rekey_entry(ctx, group, &message).await;
    }
    if message.kind != Blob::V1_GROUP_MESSAGE {
        warn!(kind = %message.kind, "ignoring non-group message");
        return Ok(());
    }
    let group_message: GroupMessage = bcs::from_bytes(&message.inner)?;
    let signed = match group_message.decrypt_message(&group.group_key_current) {
        Ok(signed) => signed,
        Err(_) => group_message.decrypt_message(&group.group_key_prev)?,
    };
    let sender = signed.sender().clone();
    let sender_descriptor = ctx
        .get(crate::directory::DIR_CLIENT)
        .get_user_descriptor(&sender)
        .await?
        .context("sender username not in directory")?;
    let content_bytes = signed
        .verify_bytes(sender_descriptor.root_cert_hash)
        .map_err(|_| anyhow::anyhow!("failed to verify group message"))?;
    let content: Event = bcs::from_bytes(&content_bytes)?;
    let recipient = match content.recipient {
        Recipient::Group(group_id) => group_id,
        Recipient::User(username) => {
            warn!(sender = %sender, recipient = %username, "ignoring group message to user");
            return Ok(());
        }
    };
    if recipient != group.group_id {
        warn!(group = ?group.group_id, recipient = ?recipient, "group recipient mismatch");
        return Ok(());
    }
    let mut conn = db.acquire().await?;
    if content.mime == nullspace_structs::fragment::FragmentRoot::mime() {
        if let Ok(root) =
            serde_json::from_slice::<nullspace_structs::fragment::FragmentRoot>(&content.body)
        {
            let _ = store_attachment_root(&mut conn, &sender, &root).await;
        }
    }
    let convo_id = ensure_convo_id(&mut *conn, "group", &group.group_id.to_string()).await?;
    sqlx::query(
        "INSERT OR IGNORE INTO convo_messages \
         (convo_id, sender_username, mime, body, sent_at, received_at) \
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(convo_id)
    .bind(sender.as_str())
    .bind(content.mime.as_str())
    .bind(content.body.to_vec())
    .bind(content.sent_at.0 as i64)
    .bind(entry.received_at.0 as i64)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

async fn process_group_management_entry(
    ctx: &AnyCtx<Config>,
    group: &GroupRecord,
    entry: nullspace_structs::server::MailboxEntry,
) -> anyhow::Result<()> {
    let message = entry.message;
    if message.kind != Blob::V1_GROUP_MESSAGE {
        warn!(kind = %message.kind, "ignoring non-management message");
        return Ok(());
    }
    let group_message: GroupMessage = bcs::from_bytes(&message.inner)?;
    let signed = group_message.decrypt_message(&group.descriptor.management_key)?;
    let sender = signed.sender().clone();
    let sender_descriptor = ctx
        .get(crate::directory::DIR_CLIENT)
        .get_user_descriptor(&sender)
        .await?
        .context("sender username not in directory")?;
    let content_bytes = signed
        .verify_bytes(sender_descriptor.root_cert_hash)
        .map_err(|_| anyhow::anyhow!("failed to verify management message"))?;
    let content: Event = bcs::from_bytes(&content_bytes)?;
    let recipient = match content.recipient {
        Recipient::Group(group_id) => group_id,
        Recipient::User(username) => {
            warn!(sender = %sender, recipient = %username, "ignoring management to user");
            return Ok(());
        }
    };
    if recipient != group.group_id {
        warn!(group = ?group.group_id, recipient = ?recipient, "management recipient mismatch");
        return Ok(());
    }
    if content.mime != GroupManageMsg::mime() {
        warn!(mime = %content.mime, "ignoring non-group-manage mime");
        return Ok(());
    }
    let manage: GroupManageMsg = serde_json::from_slice(&content.body)?;
    let db = ctx.get(DATABASE);
    let mut tx = db.begin().await?;
    let roster =
        GroupRoster::load(&mut tx, group.group_id, group.descriptor.init_admin.clone()).await?;
    let changed = roster
        .apply_manage_message(&mut tx, &sender, manage)
        .await?;
    tx.commit().await?;
    if changed {
        DbNotify::touch();
    }
    Ok(())
}
