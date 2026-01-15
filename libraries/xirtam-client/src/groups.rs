use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use anyctx::AnyCtx;
use anyhow::Context;
use bytes::Bytes;
use rand::Rng;
use smol_str::SmolStr;
use tracing::warn;
use xirtam_crypt::aead::AeadKey;
use xirtam_crypt::hash::{BcsHashExt, Hash};
use xirtam_crypt::signing::Signable;
use xirtam_structs::Blob;
use xirtam_structs::certificate::DevicePublic;
use xirtam_structs::envelope::Envelope;
use xirtam_structs::server::{AuthToken, ServerName, MailboxAcl, MailboxId, SignedMediumPk};
use xirtam_structs::group::{
    GroupDescriptor, GroupId, GroupInviteMsg, GroupManageMsg, GroupMessage,
};
use xirtam_structs::username::UserName;
use xirtam_structs::msg_content::{MessageContent, MessagePayload};
use xirtam_structs::timestamp::{NanoTimestamp, Timestamp};

use futures_concurrency::future::Race;

use crate::Config;

mod roster;
use crate::database::{
    DATABASE, DbNotify, ensure_mailbox_state, load_mailbox_after, update_mailbox_after,
};
use crate::dm::queue_dm;
use crate::server::get_server_client;
use crate::identity::Identity;
use crate::long_poll::LONG_POLLER;
use crate::peer::get_peer_info;
pub use roster::{GroupRoster, RosterMember};

const GROUP_REKEY_MEAN_SECS: f64 = 60.0 * 60.0;

#[derive(Clone)]
pub struct GroupRecord {
    pub group_id: GroupId,
    pub descriptor: GroupDescriptor,
    pub server_name: ServerName,
    pub token: AuthToken,
    pub group_key_current: AeadKey,
    pub group_key_prev: AeadKey,
}

#[derive(Clone)]
struct PendingGroupMessage {
    id: i64,
    group_id: GroupId,
    mime: SmolStr,
    body: Bytes,
}

#[derive(Clone, Copy)]
enum GroupMailboxKind {
    Messages,
    Management,
}

type GroupRecvResult = (
    GroupId,
    ServerName,
    GroupMailboxKind,
    MailboxId,
    xirtam_structs::server::MailboxEntry,
);
type GroupRecvFuture = Pin<Box<dyn Future<Output = anyhow::Result<GroupRecvResult>> + Send>>;

pub async fn group_send_loop(ctx: &AnyCtx<Config>) {
    loop {
        if let Err(err) = group_send_loop_once(ctx).await {
            tracing::error!(error = %err, "group send loop error");
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

pub async fn group_recv_loop(ctx: &AnyCtx<Config>) {
    loop {
        if let Err(err) = group_recv_loop_once(ctx).await {
            tracing::error!(error = %err, "group recv loop error");
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

pub async fn group_rekey_loop(ctx: &AnyCtx<Config>) {
    loop {
        let wait = sample_rekey_interval();
        tokio::time::sleep(wait).await;
        if let Err(err) = group_rekey_loop_once(ctx).await {
            tracing::warn!(error = %err, "group rekey loop error");
        }
    }
}

pub async fn create_group(
    ctx: &AnyCtx<Config>,
    server_name: ServerName,
) -> anyhow::Result<GroupId> {
    let db = ctx.get(DATABASE);
    let identity = Identity::load(db).await?;
    let dir = ctx.get(crate::directory::DIR_CLIENT);
    let user_descriptor = dir
        .get_user_descriptor(&identity.username)
        .await?
        .context("identity username not in directory")?;
    if user_descriptor.server_name != server_name {
        anyhow::bail!("group server must match username server");
    }

    let descriptor = GroupDescriptor {
        nonce: Hash::random(),
        init_admin: identity.username.clone(),
        created_at: Timestamp::now(),
        server: server_name.clone(),
        management_key: AeadKey::random(),
    };
    let group_id = descriptor.id();
    let group_key = AeadKey::random();
    let token = AuthToken::random();

    let server = get_server_client(ctx, &server_name).await?;
    let auth = server
        .v1_device_auth(identity.username.clone(), identity.cert_chain.clone())
        .await?
        .map_err(|err| anyhow::anyhow!(err.to_string()))?;
    server
        .v1_register_group(auth, group_id)
        .await?
        .map_err(|err| anyhow::anyhow!(err.to_string()))?;
    let acl = MailboxAcl {
        token_hash: token.bcs_hash(),
        can_edit_acl: true,
        can_send: true,
        can_recv: true,
    };
    server
        .v1_mailbox_acl_edit(auth, MailboxId::group_messages(&group_id), acl.clone())
        .await?
        .map_err(|err| anyhow::anyhow!(err.to_string()))?;
    server
        .v1_mailbox_acl_edit(auth, MailboxId::group_management(&group_id), acl)
        .await?
        .map_err(|err| anyhow::anyhow!(err.to_string()))?;

    let mut tx = db.begin().await?;
    sqlx::query(
        "INSERT INTO groups \
         (group_id, descriptor, server_name, token, group_key_current, group_key_prev, roster_version) \
         VALUES (?, ?, ?, ?, ?, ?, 0)",
    )
    .bind(group_id.as_bytes().to_vec())
    .bind(bcs::to_bytes(&descriptor)?)
    .bind(server_name.as_str())
    .bind(bcs::to_bytes(&token)?)
    .bind(bcs::to_bytes(&group_key)?)
    .bind(bcs::to_bytes(&group_key)?)
    .execute(tx.as_mut())
    .await?;
    let roster = GroupRoster::load(tx.as_mut(), group_id, identity.username.clone()).await?;
    let _ = roster.list(tx.as_mut()).await?;
    tx.commit().await?;

    ensure_mailbox_state(
        db,
        &server_name,
        MailboxId::group_management(&group_id),
        NanoTimestamp(0),
    )
    .await?;
    ensure_mailbox_state(
        db,
        &server_name,
        MailboxId::group_messages(&group_id),
        NanoTimestamp::now(),
    )
    .await?;
    DbNotify::touch();
    Ok(group_id)
}

pub async fn invite(ctx: &AnyCtx<Config>, group_id: GroupId, username: UserName) -> anyhow::Result<()> {
    let db = ctx.get(DATABASE);
    let identity = Identity::load(db).await?;
    if username == identity.username {
        anyhow::bail!("cannot invite self");
    }
    let group = load_group(db, group_id).await?.context("group not found")?;
    let invite_token = AuthToken::random();
    let acl = MailboxAcl {
        token_hash: invite_token.bcs_hash(),
        can_edit_acl: false,
        can_send: true,
        can_recv: true,
    };
    let server = get_server_client(ctx, &group.server_name).await?;
    server
        .v1_mailbox_acl_edit(
            group.token,
            MailboxId::group_messages(&group.group_id),
            acl.clone(),
        )
        .await?
        .map_err(|err| anyhow::anyhow!(err.to_string()))?;
    server
        .v1_mailbox_acl_edit(
            group.token,
            MailboxId::group_management(&group.group_id),
            acl,
        )
        .await?
        .map_err(|err| anyhow::anyhow!(err.to_string()))?;

    let manage = GroupManageMsg::InviteSent(username.clone());
    send_management_message(ctx, &identity, &group, manage).await?;

    let invite = GroupInviteMsg {
        descriptor: group.descriptor.clone(),
        group_key: group.group_key_current.clone(),
        token: invite_token,
    };
    let content = MessageContent::from_json_payload(username.clone(), NanoTimestamp::now(), &invite)?;
    queue_dm(db, &identity.username, &username, &content.mime, &content.body).await?;
    DbNotify::touch();
    Ok(())
}

pub async fn accept_invite(ctx: &AnyCtx<Config>, invite_id: i64) -> anyhow::Result<GroupId> {
    let db = ctx.get(DATABASE);
    let identity = Identity::load(db).await?;
    let row = sqlx::query_as::<_, (String, String, Vec<u8>)>(
        "SELECT sender_username, mime, body FROM dm_messages WHERE id = ?",
    )
    .bind(invite_id)
    .fetch_optional(db)
    .await?
    .context("invite not found")?;
    let (_sender_username, mime, body) = row;
    if mime != GroupInviteMsg::mime() {
        anyhow::bail!("message is not a group invite");
    }
    let invite: GroupInviteMsg = serde_json::from_slice(&body)?;
    let descriptor = invite.descriptor.clone();
    let group_id = descriptor.id();
    let group_key = invite.group_key.clone();
    let token = invite.token;

    let mut tx = db.begin().await?;
    let existing = sqlx::query_as::<_, (i64,)>("SELECT 1 FROM groups WHERE group_id = ?")
        .bind(group_id.as_bytes().to_vec())
        .fetch_optional(tx.as_mut())
        .await?;
    if existing.is_none() {
        sqlx::query(
            "INSERT INTO groups \
             (group_id, descriptor, server_name, token, group_key_current, group_key_prev, roster_version) \
             VALUES (?, ?, ?, ?, ?, ?, 0)",
        )
        .bind(group_id.as_bytes().to_vec())
        .bind(bcs::to_bytes(&descriptor)?)
        .bind(descriptor.server.as_str())
        .bind(bcs::to_bytes(&token)?)
        .bind(bcs::to_bytes(&group_key)?)
        .bind(bcs::to_bytes(&group_key)?)
        .execute(tx.as_mut())
        .await?;
    }
    let roster = GroupRoster::load(tx.as_mut(), group_id, descriptor.init_admin.clone()).await?;
    let _changed = roster
        .apply_manage_message(
            tx.as_mut(),
            &identity.username,
            GroupManageMsg::InviteAccepted,
        )
        .await?;
    tx.commit().await?;

    ensure_mailbox_state(
        db,
        &descriptor.server,
        MailboxId::group_management(&group_id),
        NanoTimestamp(0),
    )
    .await?;
    ensure_mailbox_state(
        db,
        &descriptor.server,
        MailboxId::group_messages(&group_id),
        NanoTimestamp::now(),
    )
    .await?;

    let group = load_group(db, group_id)
        .await?
        .context("group not found after invite accept")?;
    send_management_message(ctx, &identity, &group, GroupManageMsg::InviteAccepted).await?;

    DbNotify::touch();
    Ok(group_id)
}

pub async fn queue_group_message(
    db: &sqlx::SqlitePool,
    group_id: &GroupId,
    sender: &UserName,
    mime: &SmolStr,
    body: &Bytes,
) -> anyhow::Result<i64> {
    let row = sqlx::query_as::<_, (i64,)>(
        "INSERT INTO group_messages (group_id, sender_username, mime, body, received_at) \
         VALUES (?, ?, ?, ?, NULL) \
         RETURNING id",
    )
    .bind(group_id.as_bytes().to_vec())
    .bind(sender.as_str())
    .bind(mime.as_str())
    .bind(body.to_vec())
    .fetch_one(db)
    .await?;
    Ok(row.0)
}

pub async fn load_group(
    db: &sqlx::SqlitePool,
    group_id: GroupId,
) -> anyhow::Result<Option<GroupRecord>> {
    let row = sqlx::query_as::<_, (Vec<u8>, Vec<u8>, String, Vec<u8>, Vec<u8>, Vec<u8>)>(
        "SELECT group_id, descriptor, server_name, token, group_key_current, group_key_prev \
         FROM groups WHERE group_id = ?",
    )
    .bind(group_id.as_bytes().to_vec())
    .fetch_optional(db)
    .await?;
    let Some((group_id_bytes, descriptor, server_name, token, key_current, key_prev)) = row else {
        return Ok(None);
    };
    let group_id = GroupId::from_bytes(
        group_id_bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid group_id bytes"))?,
    );
    let descriptor: GroupDescriptor = bcs::from_bytes(&descriptor)?;
    let token: AuthToken = bcs::from_bytes(&token)?;
    let group_key_current: AeadKey = bcs::from_bytes(&key_current)?;
    let group_key_prev: AeadKey = bcs::from_bytes(&key_prev)?;
    Ok(Some(GroupRecord {
        group_id,
        descriptor,
        server_name: ServerName::parse(server_name)?,
        token,
        group_key_current,
        group_key_prev,
    }))
}

pub async fn load_groups(db: &sqlx::SqlitePool) -> anyhow::Result<Vec<GroupRecord>> {
    let rows = sqlx::query_as::<_, (Vec<u8>, Vec<u8>, String, Vec<u8>, Vec<u8>, Vec<u8>)>(
        "SELECT group_id, descriptor, server_name, token, group_key_current, group_key_prev \
         FROM groups",
    )
    .fetch_all(db)
    .await?;
    let mut out = Vec::with_capacity(rows.len());
    for (group_id_bytes, descriptor, server_name, token, key_current, key_prev) in rows {
        let group_id = GroupId::from_bytes(
            group_id_bytes
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid group_id bytes"))?,
        );
        let descriptor: GroupDescriptor = bcs::from_bytes(&descriptor)?;
        let token: AuthToken = bcs::from_bytes(&token)?;
        let group_key_current: AeadKey = bcs::from_bytes(&key_current)?;
        let group_key_prev: AeadKey = bcs::from_bytes(&key_prev)?;
        out.push(GroupRecord {
            group_id,
            descriptor,
            server_name: ServerName::parse(server_name)?,
            token,
            group_key_current,
            group_key_prev,
        });
    }
    Ok(out)
}

async fn group_send_loop_once(ctx: &AnyCtx<Config>) -> anyhow::Result<()> {
    let db = ctx.get(DATABASE);
    let mut notify = DbNotify::new();
    loop {
        let Some(pending) = next_pending_group_message(db).await? else {
            notify.wait_for_change().await;
            continue;
        };
        let received_at = send_group_message(ctx, &pending).await?;
        mark_group_message_sent(db, pending.id, received_at).await?;
        DbNotify::touch();
    }
}

async fn group_recv_loop_once(ctx: &AnyCtx<Config>) -> anyhow::Result<()> {
    let db = ctx.get(DATABASE);
    let groups = load_groups(db).await?;
    if groups.is_empty() {
        let mut notify = DbNotify::new();
        notify.wait_for_change().await;
        return Ok(());
    }
    let poller = ctx.get(LONG_POLLER);
    let mut futs: Vec<GroupRecvFuture> = Vec::new();
    for group in groups {
        let message_box = MailboxId::group_messages(&group.group_id);
        let manage_box = MailboxId::group_management(&group.group_id);
        ensure_mailbox_state(db, &group.server_name, message_box, NanoTimestamp(0)).await?;
        ensure_mailbox_state(db, &group.server_name, manage_box, NanoTimestamp(0)).await?;
        let message_after = load_mailbox_after(db, &group.server_name, message_box).await?;
        let manage_after = load_mailbox_after(db, &group.server_name, manage_box).await?;
        let server = get_server_client(ctx, &group.server_name).await?;
        let poller_messages = poller.clone();
        let server_messages = server.clone();
        let server_name = group.server_name.clone();
        let token = group.token;
        let group_id = group.group_id;
        futs.push(Box::pin(async move {
            let entry = poller_messages
                .recv(server_messages, token, message_box, message_after)
                .await?;
            Ok::<_, anyhow::Error>((
                group_id,
                server_name,
                GroupMailboxKind::Messages,
                message_box,
                entry,
            ))
        }));

        let poller = poller.clone();
        let server_name = group.server_name.clone();
        let token = group.token;
        let group_id = group.group_id;
        futs.push(Box::pin(async move {
            let entry = poller
                .recv(server, token, manage_box, manage_after)
                .await?;
            Ok::<_, anyhow::Error>((
                group_id,
                server_name,
                GroupMailboxKind::Management,
                manage_box,
                entry,
            ))
        }));
    }

    let (group_id, server_name, kind, mailbox, entry) = futs.race().await?;
    update_mailbox_after(db, &server_name, mailbox, entry.received_at).await?;
    let Some(group) = load_group(db, group_id).await? else {
        return Ok(());
    };
    let result = match kind {
        GroupMailboxKind::Messages => process_group_message_entry(ctx, &group, entry).await,
        GroupMailboxKind::Management => process_group_management_entry(ctx, &group, entry).await,
    };
    if let Err(err) = result {
        warn!(error = %err, group = ?group.group_id, "failed to process group entry");
    } else {
        DbNotify::touch();
    }
    Ok(())
}

async fn group_rekey_loop_once(ctx: &AnyCtx<Config>) -> anyhow::Result<()> {
    let db = ctx.get(DATABASE);
    let identity = Identity::load(db).await?;
    let groups = load_groups(db).await?;
    for group in groups {
        let mut tx = db.begin().await?;
        let roster = GroupRoster::load(
            tx.as_mut(),
            group.group_id,
            group.descriptor.init_admin.clone(),
        )
        .await?;
        let members = roster.list(tx.as_mut()).await?;
        tx.commit().await?;
        let admin_count = members
            .iter()
            .filter(|member| member.is_admin && member.is_active())
            .count() as u64;
        if admin_count == 0 {
            continue;
        }
        if !members
            .iter()
            .any(|member| member.username == identity.username && member.is_admin && member.is_active())
        {
            continue;
        }
        let roll: f64 = rand::random();
        if roll <= 1.0 / admin_count as f64 {
            if let Err(err) = send_group_rekey(ctx, &identity, &group).await {
                warn!(error = %err, group = ?group.group_id, "group rekey failed");
            }
        }
    }
    Ok(())
}

async fn send_group_message(
    ctx: &AnyCtx<Config>,
    pending: &PendingGroupMessage,
) -> anyhow::Result<NanoTimestamp> {
    let db = ctx.get(DATABASE);
    let identity = Identity::load(db).await?;
    let group = load_group(db, pending.group_id)
        .await?
        .context("group not found")?;
    let content = MessageContent {
        recipient: UserName::placeholder(),
        sent_at: NanoTimestamp::now(),
        mime: pending.mime.clone(),
        body: pending.body.clone(),
    };
    let message = Blob {
        kind: Blob::V1_MESSAGE_CONTENT.into(),
        inner: Bytes::from(bcs::to_bytes(&content)?),
    };
    let group_message = GroupMessage::encrypt_message(
        group.group_id.clone(),
        &message,
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

async fn send_management_message(
    ctx: &AnyCtx<Config>,
    identity: &Identity,
    group: &GroupRecord,
    manage: GroupManageMsg,
) -> anyhow::Result<NanoTimestamp> {
    let content =
        MessageContent::from_json_payload(UserName::placeholder(), NanoTimestamp::now(), &manage)?;
    let message = Blob {
        kind: Blob::V1_MESSAGE_CONTENT.into(),
        inner: Bytes::from(bcs::to_bytes(&content)?),
    };
    let group_message = GroupMessage::encrypt_message(
        group.group_id.clone(),
        &message,
        identity.username.clone(),
        identity.cert_chain.clone(),
        &identity.device_secret,
        &group.descriptor.management_key,
    )
    .map_err(|_| anyhow::anyhow!("failed to encrypt management message"))?;
    let blob = Blob {
        kind: Blob::V1_GROUP_MESSAGE.into(),
        inner: Bytes::from(bcs::to_bytes(&group_message)?),
    };
    send_to_group_mailbox(
        ctx,
        group,
        MailboxId::group_management(&group.group_id),
        blob,
    )
    .await
}

async fn send_group_rekey(
    ctx: &AnyCtx<Config>,
    identity: &Identity,
    group: &GroupRecord,
) -> anyhow::Result<()> {
    let recipients = collect_group_recipients(ctx, group).await?;
    let new_key = AeadKey::random();
    let key_blob = Blob {
        kind: Blob::V1_AEAD_KEY.into(),
        inner: Bytes::from(new_key.to_bytes().to_vec()),
    };
    let envelope = Envelope::encrypt_message(
        &key_blob,
        identity.username.clone(),
        identity.cert_chain.clone(),
        &identity.device_secret,
        recipients,
    )
    .map_err(|_| anyhow::anyhow!("failed to encrypt group rekey"))?;
    let outer = Blob {
        kind: Blob::V1_GROUP_REKEY.into(),
        inner: Bytes::from(bcs::to_bytes(&envelope)?),
    };
    send_to_group_mailbox(
        ctx,
        group,
        MailboxId::group_messages(&group.group_id),
        outer,
    )
    .await?;
    let db = ctx.get(DATABASE);
    sqlx::query("UPDATE groups SET group_key_prev = ?, group_key_current = ? WHERE group_id = ?")
        .bind(bcs::to_bytes(&group.group_key_current)?)
        .bind(bcs::to_bytes(&new_key)?)
        .bind(group.group_id.as_bytes().to_vec())
        .execute(db)
        .await?;
    DbNotify::touch();
    Ok(())
}

async fn send_to_group_mailbox(
    ctx: &AnyCtx<Config>,
    group: &GroupRecord,
    mailbox: MailboxId,
    message: Blob,
) -> anyhow::Result<NanoTimestamp> {
    let server = get_server_client(ctx, &group.server_name).await?;
    server
        .v1_mailbox_send(group.token, mailbox, message)
        .await?
        .map_err(|err| anyhow::anyhow!(err.to_string()))
}

async fn process_group_message_entry(
    ctx: &AnyCtx<Config>,
    group: &GroupRecord,
    entry: xirtam_structs::server::MailboxEntry,
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
    if signed.group != group.group_id {
        warn!(group = ?group.group_id, "group id mismatch in message");
        return Ok(());
    }
    let sender = signed.sender.clone();
    let sender_descriptor = ctx
        .get(crate::directory::DIR_CLIENT)
        .get_user_descriptor(&sender)
        .await?
        .context("sender username not in directory")?;
    let message = signed
        .verify(sender_descriptor.root_cert_hash)
        .map_err(|_| anyhow::anyhow!("failed to verify group message"))?;
    if message.kind != Blob::V1_MESSAGE_CONTENT {
        warn!(kind = %message.kind, "ignoring non-message-content group message");
        return Ok(());
    }
    let content: MessageContent = bcs::from_bytes(&message.inner)?;
    let mut tx = db.begin().await?;
    sqlx::query(
        "INSERT OR IGNORE INTO group_messages \
         (group_id, sender_username, mime, body, received_at) \
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(group.group_id.as_bytes().to_vec())
    .bind(sender.as_str())
    .bind(content.mime.as_str())
    .bind(content.body.to_vec())
    .bind(entry.received_at.0 as i64)
    .execute(tx.as_mut())
    .await?;
    tx.commit().await?;
    Ok(())
}

async fn process_group_management_entry(
    ctx: &AnyCtx<Config>,
    group: &GroupRecord,
    entry: xirtam_structs::server::MailboxEntry,
) -> anyhow::Result<()> {
    let message = entry.message;
    if message.kind != Blob::V1_GROUP_MESSAGE {
        warn!(kind = %message.kind, "ignoring non-management message");
        return Ok(());
    }
    let group_message: GroupMessage = bcs::from_bytes(&message.inner)?;
    let signed = group_message.decrypt_message(&group.descriptor.management_key)?;
    if signed.group != group.group_id {
        warn!(group = ?group.group_id, "group id mismatch in management");
        return Ok(());
    }
    let sender = signed.sender.clone();
    let sender_descriptor = ctx
        .get(crate::directory::DIR_CLIENT)
        .get_user_descriptor(&sender)
        .await?
        .context("sender username not in directory")?;
    let message = signed
        .verify(sender_descriptor.root_cert_hash)
        .map_err(|_| anyhow::anyhow!("failed to verify management message"))?;
    if message.kind != Blob::V1_MESSAGE_CONTENT {
        warn!(kind = %message.kind, "ignoring non-message-content management");
        return Ok(());
    }
    let content: MessageContent = bcs::from_bytes(&message.inner)?;
    if content.mime != GroupManageMsg::mime() {
        warn!(mime = %content.mime, "ignoring non-group-manage mime");
        return Ok(());
    }
    let manage: GroupManageMsg = serde_json::from_slice(&content.body)?;
    let db = ctx.get(DATABASE);
    let mut tx = db.begin().await?;
    let roster = GroupRoster::load(
        tx.as_mut(),
        group.group_id,
        group.descriptor.init_admin.clone(),
    )
    .await?;
    let changed = roster
        .apply_manage_message(tx.as_mut(), &sender, manage)
        .await?;
    tx.commit().await?;
    if changed {
        DbNotify::touch();
    }
    Ok(())
}

async fn process_group_rekey_entry(
    ctx: &AnyCtx<Config>,
    group: &GroupRecord,
    message: &Blob,
) -> anyhow::Result<()> {
    let db = ctx.get(DATABASE);
    let identity = Identity::load(db).await?;
    let envelope: Envelope = bcs::from_bytes(&message.inner)?;
    let device_pk = identity.device_secret.public();
    let decrypted = match envelope.decrypt_message(&device_pk, &identity.medium_sk_current) {
        Ok(decrypted) => decrypted,
        Err(_) => envelope.decrypt_message(&device_pk, &identity.medium_sk_prev)?,
    };
    let sender_username = decrypted.username().clone();
    let mut tx = db.begin().await?;
    let roster = GroupRoster::load(
        tx.as_mut(),
        group.group_id,
        group.descriptor.init_admin.clone(),
    )
    .await?;
    let sender_member = roster.get(tx.as_mut(), &sender_username).await?;
    tx.commit().await?;
    if !sender_member
        .as_ref()
        .is_some_and(|member| member.is_admin && member.is_active())
    {
        warn!(sender = %sender_username, "ignoring group rekey from non-admin");
        return Ok(());
    }
    let sender_descriptor = ctx
        .get(crate::directory::DIR_CLIENT)
        .get_user_descriptor(&sender_username)
        .await?
        .context("sender username not in directory")?;
    let inner = decrypted
        .verify(sender_descriptor.root_cert_hash)
        .map_err(|_| anyhow::anyhow!("failed to verify rekey envelope"))?;
    if inner.kind != Blob::V1_AEAD_KEY {
        warn!(kind = %inner.kind, "ignoring non-rekey envelope payload");
        return Ok(());
    }
    if inner.inner.len() != 32 {
        warn!(len = inner.inner.len(), "invalid rekey length");
        return Ok(());
    }
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&inner.inner);
    let new_key = AeadKey::from_bytes(key_bytes);
    sqlx::query("UPDATE groups SET group_key_prev = ?, group_key_current = ? WHERE group_id = ?")
        .bind(bcs::to_bytes(&group.group_key_current)?)
        .bind(bcs::to_bytes(&new_key)?)
        .bind(group.group_id.as_bytes().to_vec())
        .execute(db)
        .await?;
    DbNotify::touch();
    Ok(())
}

async fn next_pending_group_message(
    db: &sqlx::SqlitePool,
) -> anyhow::Result<Option<PendingGroupMessage>> {
    let row = sqlx::query_as::<_, (i64, Vec<u8>, String, Vec<u8>)>(
        "SELECT id, group_id, mime, body \
         FROM group_messages \
         WHERE received_at IS NULL \
         ORDER BY id \
         LIMIT 1",
    )
    .fetch_optional(db)
    .await?;
    let Some((id, group_id, mime, body)) = row else {
        return Ok(None);
    };
    let group_id = GroupId::from_bytes(
        group_id
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid group_id bytes"))?,
    );
    Ok(Some(PendingGroupMessage {
        id,
        group_id,
        mime: SmolStr::new(mime),
        body: Bytes::from(body),
    }))
}

async fn mark_group_message_sent(
    db: &sqlx::SqlitePool,
    id: i64,
    received_at: NanoTimestamp,
) -> anyhow::Result<()> {
    let result = sqlx::query("UPDATE group_messages SET received_at = ? WHERE id = ?")
        .bind(received_at.0 as i64)
        .bind(id)
        .execute(db)
        .await;
    match result {
        Ok(_) => Ok(()),
        Err(err) if is_unique_violation(&err) => {
            sqlx::query("DELETE FROM group_messages WHERE id = ?")
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

async fn collect_group_recipients(
    ctx: &AnyCtx<Config>,
    group: &GroupRecord,
) -> anyhow::Result<Vec<(DevicePublic, xirtam_crypt::dh::DhPublic)>> {
    let mut recipients = Vec::new();
    let db = ctx.get(DATABASE);
    let mut tx = db.begin().await?;
    let roster = GroupRoster::load(
        tx.as_mut(),
        group.group_id,
        group.descriptor.init_admin.clone(),
    )
    .await?;
    let members = roster.list(tx.as_mut()).await?;
    tx.commit().await?;
    for member in members.into_iter().filter(RosterMember::is_active) {
        let username = member.username;
        let peer = get_peer_info(ctx, &username).await?;
        recipients.extend(collect_recipients(&username, &peer.certs, &peer.medium_pks)?);
    }
    if recipients.is_empty() {
        anyhow::bail!("no recipients available for group");
    }
    Ok(recipients)
}

fn collect_recipients(
    username: &UserName,
    chain: &[xirtam_structs::certificate::DeviceCertificate],
    medium_pks: &BTreeMap<xirtam_crypt::hash::Hash, SignedMediumPk>,
) -> anyhow::Result<Vec<(DevicePublic, xirtam_crypt::dh::DhPublic)>> {
    let mut recipients = Vec::new();
    for cert in chain {
        let device_hash = cert.pk.bcs_hash();
        let Some(medium_pk) = medium_pks.get(&device_hash) else {
            warn!(username = %username, device_hash = %device_hash, "missing medium-term key");
            continue;
        };
        if medium_pk.verify(cert.pk.signing_public()).is_err() {
            warn!(username = %username, device_hash = %device_hash, "invalid medium-term key signature");
            continue;
        }
        recipients.push((cert.pk.clone(), medium_pk.medium_pk.clone()));
    }
    Ok(recipients)
}

fn sample_rekey_interval() -> Duration {
    let mut rng = rand::thread_rng();
    let u: f64 = rng.gen_range(f64::MIN_POSITIVE..=1.0);
    let secs = -u.ln() * GROUP_REKEY_MEAN_SECS;
    Duration::from_secs_f64(secs)
}
