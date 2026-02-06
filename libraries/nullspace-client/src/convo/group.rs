use anyctx::AnyCtx;
use anyhow::Context;
use bytes::Bytes;
use nullspace_crypt::aead::AeadKey;
use nullspace_crypt::hash::{BcsHashExt, Hash};
use nullspace_structs::Blob;
use nullspace_structs::event::{Event, EventPayload, Recipient};
use nullspace_structs::group::{
    GroupDescriptor, GroupId, GroupInviteMsg, GroupManageMsg, GroupMessage,
};
use nullspace_structs::server::{AuthToken, MailboxAcl, MailboxId, ServerName};
use nullspace_structs::timestamp::{NanoTimestamp, Timestamp};
use nullspace_structs::username::UserName;

use crate::config::Config;
use crate::database::{DATABASE, DbNotify, ensure_convo_id, ensure_mailbox_state};
use crate::identity::Identity;
use crate::server::get_server_client;
use crate::auth_tokens::get_auth_token;

use super::ConvoId;
use super::roster::GroupRoster;
use super::send::queue_message;

#[derive(Clone)]
pub struct GroupRecord {
    pub group_id: GroupId,
    pub descriptor: GroupDescriptor,
    pub server_name: ServerName,
    pub token: AuthToken,
    pub group_key_current: AeadKey,
    pub group_key_prev: AeadKey,
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
    let auth = get_auth_token(ctx).await?;
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
    let roster = GroupRoster::load(&mut tx, group_id, identity.username.clone()).await?;
    let _ = roster.list(&mut tx).await?;
    ensure_mailbox_state(
        tx.as_mut(),
        &server_name,
        MailboxId::group_management(&group_id),
        NanoTimestamp(0),
    )
    .await?;
    ensure_mailbox_state(
        tx.as_mut(),
        &server_name,
        MailboxId::group_messages(&group_id),
        NanoTimestamp::now(),
    )
    .await?;
    let _ = ensure_convo_id(tx.as_mut(), "group", &group_id.to_string()).await?;
    tx.commit().await?;
    DbNotify::touch();
    Ok(group_id)
}

pub async fn invite(
    ctx: &AnyCtx<Config>,
    group_id: GroupId,
    username: UserName,
) -> anyhow::Result<()> {
    let db = ctx.get(DATABASE);
    let identity = Identity::load(db).await?;
    if username == identity.username {
        anyhow::bail!("cannot invite self");
    }
    let dir = ctx.get(crate::directory::DIR_CLIENT);
    dir.get_user_descriptor(&username)
        .await?
        .context("username not in directory")?;
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
        created_at: NanoTimestamp::now(),
    };
    let content = Event::from_json_payload(
        Recipient::User(username.clone()),
        NanoTimestamp::now(),
        &invite,
    )?;
    let convo_id = ConvoId::Direct { peer: username.clone() };
    let mut conn = db.acquire().await?;
    queue_message(
        &mut conn,
        &convo_id,
        &identity.username,
        &content.mime,
        &content.body,
    )
    .await?;
    DbNotify::touch();
    Ok(())
}

pub async fn accept_invite(ctx: &AnyCtx<Config>, invite_id: i64) -> anyhow::Result<GroupId> {
    let db = ctx.get(DATABASE);
    let identity = Identity::load(db).await?;
    let row = sqlx::query_as::<_, (String, String, Vec<u8>)>(
        "SELECT m.sender_username, m.mime, m.body \
         FROM convo_messages m \
         JOIN convos c ON m.convo_id = c.id \
         WHERE c.convo_type = 'direct' AND m.id = ?",
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
    ensure_mailbox_state(
        tx.as_mut(),
        &descriptor.server,
        MailboxId::group_management(&group_id),
        NanoTimestamp(0),
    )
    .await?;
    ensure_mailbox_state(
        tx.as_mut(),
        &descriptor.server,
        MailboxId::group_messages(&group_id),
        invite.created_at,
    )
    .await?;
    let _ = ensure_convo_id(tx.as_mut(), "group", &group_id.to_string()).await?;
    tx.commit().await?;

    let group = load_group(db, group_id)
        .await?
        .context("group not found after invite accept")?;
    send_management_message(ctx, &identity, &group, GroupManageMsg::InviteAccepted).await?;

    DbNotify::touch();
    Ok(group_id)
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

async fn send_management_message(
    ctx: &AnyCtx<Config>,
    identity: &Identity,
    group: &GroupRecord,
    manage: GroupManageMsg,
) -> anyhow::Result<NanoTimestamp> {
    let content = Event::from_json_payload(
        Recipient::Group(group.group_id),
        NanoTimestamp::now(),
        &manage,
    )?;
    let group_message = GroupMessage::encrypt_message(
        &content,
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

pub(super) async fn send_to_group_mailbox(
    ctx: &AnyCtx<Config>,
    group: &GroupRecord,
    mailbox: MailboxId,
    message: Blob,
) -> anyhow::Result<NanoTimestamp> {
    let server = get_server_client(ctx, &group.server_name).await?;
    server
        .v1_mailbox_send(group.token, mailbox, message, 0)
        .await?
        .map_err(|err| anyhow::anyhow!(err.to_string()))
}
