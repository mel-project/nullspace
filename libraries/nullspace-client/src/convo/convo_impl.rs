use anyctx::AnyCtx;
use bytes::Bytes;
use nullspace_structs::event::{MessagePayload, TAG_MESSAGE};
use nullspace_structs::group::GroupId;

use crate::config::Config;
use crate::database::{DATABASE, DbNotify};
use crate::events::emit_event;
use crate::identity::Identity;
use nullspace_crypt::signing::Signable;
use nullspace_structs::group::GroupRotationPayload;
use nullspace_structs::server::ServerName;
use nullspace_structs::timestamp::NanoTimestamp;

use crate::internal::{
    Event, GroupAction, GroupCapabilities, GroupCreateRequest, GroupInvitationSummary,
    GroupRosterEntry, GroupSettings, GroupView, InternalRpcError, internal_err, map_anyhow_err,
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
    let body = Bytes::from(bcs::to_bytes(&message).map_err(internal_err)?);
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

pub async fn group_invitation_list_impl(
    ctx: &AnyCtx<Config>,
) -> Result<Vec<GroupInvitationSummary>, InternalRpcError> {
    let db = ctx.get(DATABASE);
    let rows = sqlx::query_as::<
        _,
        (
            i64,
            Vec<u8>,
            String,
            String,
            Option<String>,
            Option<String>,
            i64,
        ),
    >(
        "SELECT id, group_id, server_name, inviter_username, title, description, received_at \
         FROM group_invitations WHERE accepted = 0",
    )
    .fetch_all(&*db)
    .await
    .map_err(internal_err)?;

    let mut out = Vec::with_capacity(rows.len());
    for (id, gid_bytes, server, inviter, title, description, received_at) in rows {
        let gid_arr: [u8; 16] = gid_bytes
            .try_into()
            .map_err(|_| internal_err("invalid group_id"))?;
        let group_id = GroupId::from_bytes(gid_arr);
        let server = ServerName::parse(server).map_err(internal_err)?;
        let inviter =
            nullspace_structs::username::UserName::parse(inviter).map_err(internal_err)?;
        let display_title = title
            .clone()
            .unwrap_or_else(|| format!("Group {}", group_id.short_id()));
        out.push(GroupInvitationSummary {
            invitation_id: id,
            group_id,
            display_title,
            title,
            description,
            inviter,
            server,
            received_at: NanoTimestamp(received_at as u64),
        });
    }
    Ok(out)
}

pub async fn group_invitation_accept_impl(
    ctx: &AnyCtx<Config>,
    invitation_id: i64,
) -> Result<GroupId, InternalRpcError> {
    let db = ctx.get(DATABASE);
    let identity = Identity::load(&mut *db.acquire().await.map_err(internal_err)?)
        .await
        .map_err(internal_err)?;

    // Load invitation
    let row = sqlx::query_as::<_, (Vec<u8>, String, i64, Vec<u8>)>(
        "SELECT group_id, server_name, rotation_index, gbk \
         FROM group_invitations WHERE id = ? AND accepted = 0",
    )
    .bind(invitation_id)
    .fetch_optional(&*db)
    .await
    .map_err(internal_err)?
    .ok_or(InternalRpcError::NotFound)?;

    let gid_arr: [u8; 16] = row
        .0
        .try_into()
        .map_err(|_| internal_err("invalid group_id"))?;
    let group_id = GroupId::from_bytes(gid_arr);
    let server_name = ServerName::parse(row.1).map_err(internal_err)?;
    let invitation_rotation_index = row.2 as u64;
    let gbk: nullspace_structs::group::GroupBearerKey =
        bcs::from_bytes(&row.3).map_err(internal_err)?;

    // Fetch latest rotation from server to get the roster
    let server = get_server_client(ctx, &server_name)
        .await
        .map_err(internal_err)?;

    // Walk forward from the invitation's rotation to find the latest
    let mut current_index = invitation_rotation_index;
    let mut latest_payload: Option<GroupRotationPayload> = None;
    let mut prev_admin_set: std::collections::BTreeSet<nullspace_crypt::signing::SigningPublic> =
        std::collections::BTreeSet::new();
    let mut final_admin_set = prev_admin_set.clone();
    let mut prev_hash: Option<nullspace_crypt::hash::Hash> = None;
    let mut final_rotation_hash = nullspace_crypt::hash::Hash::digest(&[]);

    loop {
        let rotation = match server
            .group_get(group_id, current_index)
            .await
            .map_err(internal_err)?
        {
            Ok(Some(rot)) => rot,
            Ok(None) => break,
            Err(e) => return Err(internal_err(e)),
        };

        // Verify signature
        rotation
            .verify(rotation.signer)
            .map_err(|_| internal_err("rotation signature verification failed"))?;

        // Verify signer authorization (skip for the first entry in our walk,
        // since we don't have the previous admin set)
        if !prev_admin_set.is_empty() && !prev_admin_set.contains(&rotation.signer) {
            return Err(internal_err("rotation signer not in previous admin set"));
        }

        // Verify hash chain (skip for the first entry in our walk)
        if let Some(expected_prev) = prev_hash {
            match &rotation.prev_hash {
                Some(h) if *h != expected_prev => {
                    return Err(internal_err(
                        "rotation prev_hash does not match previous rotation hash",
                    ));
                }
                None => {
                    return Err(internal_err("rotation has no prev_hash"));
                }
                _ => {}
            }
        }

        // Try to decrypt the payload
        if let Ok(payload_bytes) = rotation
            .gbk_rotation
            .decrypt_bytes(&identity.medium_sk_current)
            .or_else(|_| {
                rotation
                    .gbk_rotation
                    .decrypt_bytes(&identity.medium_sk_prev)
            })
        {
            if let Ok(payload) = bcs::from_bytes::<GroupRotationPayload>(&payload_bytes) {
                latest_payload = Some(payload);
            }
        } else {
            // Can't decrypt — we were removed in a later rotation
            break;
        }

        prev_admin_set = rotation.new_admin_set.clone();
        final_admin_set = rotation.new_admin_set.clone();
        final_rotation_hash = rotation.hash();
        prev_hash = Some(final_rotation_hash);
        current_index += 1;
    }

    // Use the latest decryptable payload, or fall back to the invitation's GBK
    let (final_gbk, final_roster, final_index) = match latest_payload {
        Some(payload) => {
            let idx = current_index.saturating_sub(1);
            (payload.gbk, Some(payload.roster), idx)
        }
        None => (gbk, None, invitation_rotation_index),
    };

    // Store GBK and roster
    let mut tx = db.begin().await.map_err(internal_err)?;
    super::groups::store_gbk(
        &mut tx,
        group_id,
        &final_gbk,
        &server_name,
        final_index,
        &final_admin_set,
        &final_rotation_hash,
    )
    .await
    .map_err(internal_err)?;
    if let Some(roster) = &final_roster {
        super::groups::store_roster(&mut tx, group_id, final_index, roster)
            .await
            .map_err(internal_err)?;
    }
    let convo_id = ConvoId::Group { group_id };
    super::ensure_thread_id(&mut tx, convo_id.convo_type(), &convo_id.counterparty())
        .await
        .map_err(internal_err)?;
    tx.commit().await.map_err(internal_err)?;

    // Mark invitation as accepted
    sqlx::query("UPDATE group_invitations SET accepted = 1 WHERE id = ?")
        .bind(invitation_id)
        .execute(&*db)
        .await
        .map_err(internal_err)?;

    // Create mailbox
    let auth = crate::net::get_auth_token(ctx)
        .await
        .map_err(internal_err)?;
    server
        .mailbox_create(auth, final_gbk.mailbox_key())
        .await
        .map_err(internal_err)?
        .map_err(internal_err)?;

    emit_event(ctx, Event::ConvoUpdated { convo_id });
    Ok(group_id)
}
