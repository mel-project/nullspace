use anyctx::AnyCtx;
use nullspace_structs::event::{GroupInvitation, MessagePayload, TAG_MESSAGE};
use nullspace_structs::group::GroupId;

use crate::config::Config;
use crate::database::{DATABASE, DbNotify};
use crate::events::emit_event;
use crate::identity::Identity;
use nullspace_crypt::signing::Signable;

use crate::internal::{
    Event, GroupAction, GroupCapabilities, GroupCreateRequest, GroupRosterEntry, GroupSettings,
    GroupView, InternalRpcError, internal_err, map_anyhow_err,
};
use crate::net::get_server_client;

use super::{ConvoId, ConvoItem, ConvoSummary};

pub async fn convo_list_impl(ctx: &AnyCtx<Config>) -> Result<Vec<ConvoSummary>, InternalRpcError> {
    let db = ctx.get(DATABASE);
    super::queries::convo_list(&mut *db.acquire().await.map_err(internal_err)?)
        .await
        .map_err(internal_err)
}

pub async fn convo_history_impl(
    ctx: &AnyCtx<Config>,
    convo_id: ConvoId,
    before: Option<i64>,
    after: Option<i64>,
    limit: u16,
) -> Result<Vec<ConvoItem>, InternalRpcError> {
    let db = ctx.get(DATABASE);
    super::queries::convo_history(
        &mut *db.acquire().await.map_err(internal_err)?,
        convo_id,
        before,
        after,
        limit,
    )
    .await
    .map_err(internal_err)
}

pub async fn convo_send_impl(
    ctx: &AnyCtx<Config>,
    convo_id: ConvoId,
    message: MessagePayload,
) -> Result<i64, InternalRpcError> {
    let db = ctx.get(DATABASE);
    let identity = Identity::load(&mut *db.acquire().await.map_err(internal_err)?)
        .await
        .map_err(|_| InternalRpcError::NotReady)?;
    let body = super::encode_event_body(&message).map_err(internal_err)?;
    let mut conn = db.acquire().await.map_err(internal_err)?;
    let id =
        super::send::queue_message(&mut conn, &convo_id, &identity.username, TAG_MESSAGE, &body)
            .await
            .map_err(internal_err)?;
    DbNotify::touch();
    emit_event(ctx, Event::ConvoUpdated { convo_id });
    Ok(id)
}

pub async fn convo_mark_read_impl(
    ctx: &AnyCtx<Config>,
    convo_id: ConvoId,
    up_to_id: i64,
) -> Result<(), InternalRpcError> {
    let db = ctx.get(DATABASE);
    let affected = super::queries::mark_convo_read(
        &mut *db.acquire().await.map_err(internal_err)?,
        &convo_id,
        up_to_id,
    )
    .await
    .map_err(internal_err)?;
    if affected > 0 {
        emit_event(ctx, Event::ConvoUpdated { convo_id });
    }
    Ok(())
}

pub async fn group_create_impl(
    ctx: &AnyCtx<Config>,
    request: GroupCreateRequest,
) -> Result<GroupId, InternalRpcError> {
    let group_id = super::groups::group_create(ctx, request)
        .await
        .map_err(internal_err)?;
    emit_event(
        ctx,
        Event::ConvoUpdated {
            convo_id: ConvoId::Group { group_id },
        },
    );
    Ok(group_id)
}

pub async fn group_action_impl(
    ctx: &AnyCtx<Config>,
    group_id: GroupId,
    action: GroupAction,
) -> Result<(), InternalRpcError> {
    super::groups::group_action(ctx, group_id, action)
        .await
        .map_err(map_anyhow_err)?;
    emit_event(
        ctx,
        Event::ConvoUpdated {
            convo_id: ConvoId::Group { group_id },
        },
    );
    Ok(())
}

pub async fn group_view_impl(
    ctx: &AnyCtx<Config>,
    group_id: GroupId,
) -> Result<GroupView, InternalRpcError> {
    let db = ctx.get(DATABASE);
    let identity = Identity::load(&mut *db.acquire().await.map_err(internal_err)?)
        .await
        .map_err(internal_err)?;

    let (_, roster) =
        super::groups::load_roster(&mut *db.acquire().await.map_err(internal_err)?, group_id)
            .await
            .map_err(|_| InternalRpcError::NotFound)?;

    let server_name =
        super::groups::load_gbk(&mut *db.acquire().await.map_err(internal_err)?, group_id)
            .await
            .map_err(|_| InternalRpcError::NotFound)?
            .server_name;

    let my_member = roster.members.get(&identity.username);
    let am_admin = my_member.map_or(false, |m| m.is_admin);
    let am_muted = my_member.map_or(true, |m| m.is_muted);

    let capabilities = GroupCapabilities {
        can_send_messages: my_member.is_some() && !am_muted,
        can_share_invites: am_admin,
        can_edit_metadata: am_admin,
        can_manage_mutes: am_admin,
        can_manage_members: am_admin,
        can_manage_admins: am_admin,
        can_rotate_keys: am_admin,
        can_leave: my_member.is_some(),
    };

    let mut roster_entries: Vec<GroupRosterEntry> = roster
        .members
        .iter()
        .map(|(username, state)| GroupRosterEntry {
            username: username.clone(),
            is_admin: state.is_admin,
            is_muted: state.is_muted,
            is_banned: false,
        })
        .collect();
    for username in &roster.banned {
        roster_entries.push(GroupRosterEntry {
            username: username.clone(),
            is_admin: false,
            is_muted: false,
            is_banned: true,
        });
    }

    let display_title = roster
        .metadata
        .title
        .clone()
        .unwrap_or_else(|| format!("Group {}", group_id.short_id()));

    Ok(GroupView {
        group_id,
        display_title,
        title: roster.metadata.title,
        description: roster.metadata.description,
        server: server_name,
        capabilities,
        settings: GroupSettings {
            new_members_muted: roster.settings.new_members_muted,
            allow_new_members_to_see_history: roster.settings.allow_new_members_to_see_history,
        },
        roster: roster_entries,
    })
}

pub(super) async fn accept_group_invitation(
    ctx: &AnyCtx<Config>,
    invitation: &GroupInvitation,
) -> anyhow::Result<GroupId> {
    let db = ctx.get(DATABASE);
    let group_id = invitation.group_id;
    let server_name = invitation.gbk.server.clone();
    let invitation_rotation_index = invitation.rotation_index;
    let gbk = invitation.gbk.clone();

    // Fetch the rotation at the invitation index and decrypt the roster
    // using the GBK from the invitation.
    let server = get_server_client(ctx, &server_name).await?;

    let rotation = server
        .group_get(group_id, invitation_rotation_index)
        .await??
        .ok_or_else(|| anyhow::anyhow!("rotation not found on server"))?;

    rotation
        .verify(rotation.signer)
        .map_err(|_| anyhow::anyhow!("rotation signature verification failed"))?;

    let roster =
        nullspace_structs::group::decrypt_roster(&gbk, &rotation.roster_encrypted)
            .map_err(|err| anyhow::anyhow!(err))?;

    let rotation_hash = rotation.hash();

    // Store GBK and roster
    let mut tx = db.begin().await.map_err(internal_err)?;
    super::groups::store_gbk(
        &mut tx,
        group_id,
        &gbk,
        &server_name,
        invitation_rotation_index,
        &rotation.new_admin_set,
        &rotation_hash,
    )
    .await
    ?;
    super::groups::replace_current_roster(
        &mut tx,
        group_id,
        invitation_rotation_index,
        &roster,
    )
    .await
    ?;
    let convo_id = ConvoId::Group { group_id };
    super::ensure_thread_id(&mut tx, convo_id.convo_type(), &convo_id.counterparty())
        .await
        ?;
    tx.commit().await?;
    DbNotify::touch();
    Ok(group_id)
}
