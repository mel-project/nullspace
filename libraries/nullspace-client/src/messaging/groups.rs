use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use anyctx::AnyCtx;
use bytes::Bytes;
use nullspace_crypt::signing::{Signable, Signature};
use nullspace_structs::e2ee::HeaderEncrypted;
use nullspace_structs::event::{
    GroupInvitation, GroupPermissionChange, GroupSettingsChange, GroupUnban, TAG_GROUP_INVITATION,
    TAG_GROUP_PERMISSION_CHANGE, TAG_GROUP_SETTINGS_CHANGE, TAG_GROUP_UNBAN, TAG_LEAVE_REQUEST,
};
use nullspace_structs::group::{
    GroupBearerKey, GroupId, GroupMetadata, GroupRoster, GroupRosterSettings, GroupRotation,
    GroupRotationPayload, MemberState, encrypt_roster,
};
use crate::config::Config;
use crate::database::{DATABASE, DbNotify};
use crate::events::emit_event;
use crate::api::{GroupAction, GroupCreateRequest};
use crate::identity::{Identity, get_auth_token, own_server_name};
use crate::storage::{
    LoadedGbk, ensure_thread_id, load_gbk, load_roster, remove_local_group_state,
    replace_current_roster, store_gbk,
};
use crate::transport::get_server_client;

use super::group_rotation::submit_rotation;
use super::ConvoId;

pub async fn group_create(
    ctx: &AnyCtx<Config>,
    request: GroupCreateRequest,
) -> anyhow::Result<GroupId> {
    let db = ctx.get(DATABASE);
    let identity = Identity::load(&mut *db.acquire().await?).await?;
    let server_name = own_server_name(ctx, &identity).await?;
    let server = get_server_client(ctx, &server_name).await?;
    let auth = get_auth_token(ctx).await?;

    let group_id = GroupId::random();
    let gbk = GroupBearerKey::generate(group_id, server_name.clone());

    let mut members = BTreeMap::new();
    members.insert(
        identity.username.clone(),
        MemberState {
            is_admin: true,
            is_muted: false,
        },
    );
    let roster = GroupRoster {
        members,
        banned: BTreeSet::new(),
        metadata: GroupMetadata {
            title: request.title,
            description: request.description,
        },
        settings: GroupRosterSettings {
            new_members_muted: request.new_members_muted,
            allow_new_members_to_see_history: request.allow_new_members_to_see_history,
        },
    };

    let payload = GroupRotationPayload { gbk: gbk.clone() };
    let payload_bytes = bcs::to_bytes(&payload)?;
    let payload_encrypted =
        HeaderEncrypted::encrypt_bytes(&payload_bytes, [identity.medium_sk_current.public_key()])
            .map_err(|e| anyhow::anyhow!(e))?;
    let roster_encrypted = encrypt_roster(&gbk, &roster)?;

    let device_pk = identity.device_secret.public().signing_public();
    let mut admin_set = BTreeSet::new();
    admin_set.insert(device_pk);

    let mut rotation = GroupRotation {
        group_id,
        prev_hash: None,
        signer: device_pk,
        new_admin_set: admin_set.clone(),
        gbk_rotation: payload_encrypted,
        roster_encrypted,
        signature: Signature::from_bytes([0u8; 64]),
    };
    rotation.sign(&identity.device_secret);

    let rotation_hash = rotation.hash();

    server
        .group_create(auth, rotation)
        .await?
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;

    server
        .mailbox_create(auth, gbk.mailbox_key())
        .await?
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;

    let mut tx = db.begin().await?;
    store_gbk(
        &mut tx,
        group_id,
        &gbk,
        &server_name,
        0,
        &admin_set,
        &rotation_hash,
    )
    .await?;
    replace_current_roster(&mut tx, group_id, 0, &roster).await?;
    let convo_id = ConvoId::Group { group_id };
    ensure_thread_id(&mut tx, convo_id.convo_type(), &convo_id.counterparty()).await?;
    tx.commit().await?;

    DbNotify::touch();
    Ok(group_id)
}

pub async fn refresh_group_state(ctx: &AnyCtx<Config>, group_id: GroupId) -> anyhow::Result<bool> {
    let db = ctx.get(DATABASE);
    let identity = Identity::load(&mut *db.acquire().await?).await?;
    let mut loaded = load_gbk(&mut *db.acquire().await?, group_id).await?;
    let server = get_server_client(ctx, &loaded.server_name).await?;
    let mut changed = false;

    loop {
        let rotation = match server
            .group_get(group_id, loaded.rotation_index + 1)
            .await?
        {
            Ok(Some(rotation)) => rotation,
            Ok(None) => break,
            Err(err) => anyhow::bail!("group_get failed: {err}"),
        };

        rotation
            .verify(rotation.signer)
            .map_err(|_| anyhow::anyhow!("rotation signature verification failed"))?;

        if !loaded.admin_set.contains(&rotation.signer) {
            anyhow::bail!(
                "rotation signer {:?} not in previous admin set",
                rotation.signer
            );
        }
        match &rotation.prev_hash {
            Some(hash) if *hash == loaded.rotation_hash => {}
            Some(_) => anyhow::bail!("rotation prev_hash does not match stored rotation hash"),
            None => anyhow::bail!("rotation has no prev_hash"),
        }

        let payload_bytes = match rotation
            .gbk_rotation
            .decrypt_bytes(&identity.medium_sk_current)
            .or_else(|_| {
                rotation
                    .gbk_rotation
                    .decrypt_bytes(&identity.medium_sk_prev)
            }) {
            Ok(bytes) => bytes,
            Err(_) => {
                let mut tx = db.begin().await?;
                remove_local_group_state(&mut tx, group_id).await?;
                tx.commit().await?;
                DbNotify::touch();
                return Ok(true);
            }
        };

        let payload: GroupRotationPayload = bcs::from_bytes(&payload_bytes)?;
        if payload.gbk.group_id != group_id {
            anyhow::bail!("rotation payload group id mismatch");
        }
        if payload.gbk.server != loaded.server_name {
            anyhow::bail!("rotation payload server mismatch");
        }
        let roster =
            nullspace_structs::group::decrypt_roster(&payload.gbk, &rotation.roster_encrypted)?;

        let auth = get_auth_token(ctx).await?;
        server
            .mailbox_create(auth, payload.gbk.mailbox_key())
            .await?
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;

        let rotation_hash = rotation.hash();
        let next_index = loaded.rotation_index + 1;
        let mut tx = db.begin().await?;
        store_gbk(
            &mut tx,
            group_id,
            &payload.gbk,
            &payload.gbk.server,
            next_index,
            &rotation.new_admin_set,
            &rotation_hash,
        )
        .await?;
        replace_current_roster(&mut tx, group_id, next_index, &roster).await?;
        let convo_id = ConvoId::Group { group_id };
        ensure_thread_id(&mut tx, convo_id.convo_type(), &convo_id.counterparty()).await?;
        tx.commit().await?;

        loaded = LoadedGbk {
            rotation_index: next_index,
            gbk: payload.gbk,
            server_name: loaded.server_name.clone(),
            admin_set: rotation.new_admin_set,
            rotation_hash,
        };
        changed = true;
    }

    if changed {
        DbNotify::touch();
    }
    Ok(changed)
}

pub async fn group_refresh_loop(ctx: &AnyCtx<Config>) {
    loop {
        if let Err(err) = group_refresh_loop_once(ctx).await {
            tracing::error!(error = %err, "group refresh loop error");
        }
        tokio::time::sleep(Duration::from_secs(60)).await;
    }
}

async fn group_refresh_loop_once(ctx: &AnyCtx<Config>) -> anyhow::Result<()> {
    let db = ctx.get(DATABASE);
    let group_ids = sqlx::query_scalar::<_, Vec<u8>>("SELECT group_id FROM group_keys")
        .fetch_all(&*db)
        .await?;

    for gid_bytes in group_ids {
        let gid_arr: [u8; 16] = gid_bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid group_id length"))?;
        let group_id = GroupId::from_bytes(gid_arr);
        match refresh_group_state(ctx, group_id).await {
            Ok(true) => emit_event(
                ctx,
                crate::api::Event::ConvoUpdated {
                    convo_id: ConvoId::Group { group_id },
                },
            ),
            Ok(false) => {}
            Err(err) => {
                tracing::warn!(group = %group_id, error = %err, "failed to refresh group state")
            }
        }
    }

    Ok(())
}

/// Dispatch a group action. Rotation-requiring actions submit a new rotation.
/// Mailbox-event actions are queued through the normal send path. ShareInvite
/// DMs the current GBK.
pub async fn group_action(
    ctx: &AnyCtx<Config>,
    group_id: GroupId,
    action: GroupAction,
) -> anyhow::Result<()> {
    let _ = refresh_group_state(ctx, group_id).await?;

    let db = ctx.get(DATABASE);
    let identity = Identity::load(&mut *db.acquire().await?).await?;
    let (_, mut roster) = load_roster(&mut *db.acquire().await?, group_id).await?;

    let am_admin = roster
        .members
        .get(&identity.username)
        .is_some_and(|member| member.is_admin);

    let group_convo = ConvoId::Group { group_id };

    match action {
        GroupAction::ShareInvite { username } => {
            anyhow::ensure!(am_admin, "only admins can invite");
            anyhow::ensure!(!roster.banned.contains(&username), "user is banned");
            let loaded = load_gbk(&mut *db.acquire().await?, group_id).await?;
            let gbk = loaded.gbk;
            let invitation = GroupInvitation {
                group_id: gbk.group_id,
                gbk: gbk.clone(),
                rotation_index: loaded.rotation_index,
                title: roster.metadata.title.clone(),
                description: roster.metadata.description.clone(),
            };
            let body = super::encode_event_body(&invitation)?;
            let dm_convo = ConvoId::Direct {
                peer: username.clone(),
            };
            let mut conn = db.acquire().await?;
            super::send::queue_message(
                &mut conn,
                &dm_convo,
                &identity.username,
                TAG_GROUP_INVITATION,
                &body,
            )
            .await?;
        }

        GroupAction::SetAdmin { username, is_admin } => {
            anyhow::ensure!(am_admin, "only admins can change admin status");
            if let Some(member) = roster.members.get_mut(&username) {
                member.is_admin = is_admin;
            }
            submit_rotation(ctx, &identity, group_id, &roster).await?;
        }

        GroupAction::SetMemberMuted { username, muted } => {
            anyhow::ensure!(am_admin, "only admins can mute/unmute");
            let body = super::encode_event_body(&GroupPermissionChange { username, muted })?;
            let mut conn = db.acquire().await?;
            super::send::queue_message(
                &mut conn,
                &group_convo,
                &identity.username,
                TAG_GROUP_PERMISSION_CHANGE,
                &body,
            )
            .await?;
        }

        GroupAction::SetMetadata { title, description } => {
            anyhow::ensure!(am_admin, "only admins can change metadata");
            let body = super::encode_event_body(&GroupSettingsChange {
                title,
                description,
                new_members_muted: roster.settings.new_members_muted,
                allow_new_members_to_see_history: roster.settings.allow_new_members_to_see_history,
            })?;
            let mut conn = db.acquire().await?;
            super::send::queue_message(
                &mut conn,
                &group_convo,
                &identity.username,
                TAG_GROUP_SETTINGS_CHANGE,
                &body,
            )
            .await?;
        }

        GroupAction::SetNewMembersMuted { muted } => {
            anyhow::ensure!(am_admin, "only admins can change settings");
            let body = super::encode_event_body(&GroupSettingsChange {
                title: roster.metadata.title.clone(),
                description: roster.metadata.description.clone(),
                new_members_muted: muted,
                allow_new_members_to_see_history: roster.settings.allow_new_members_to_see_history,
            })?;
            let mut conn = db.acquire().await?;
            super::send::queue_message(
                &mut conn,
                &group_convo,
                &identity.username,
                TAG_GROUP_SETTINGS_CHANGE,
                &body,
            )
            .await?;
        }

        GroupAction::SetAllowNewMembersToSeeHistory { allow } => {
            anyhow::ensure!(am_admin, "only admins can change settings");
            let body = super::encode_event_body(&GroupSettingsChange {
                title: roster.metadata.title.clone(),
                description: roster.metadata.description.clone(),
                new_members_muted: roster.settings.new_members_muted,
                allow_new_members_to_see_history: allow,
            })?;
            let mut conn = db.acquire().await?;
            super::send::queue_message(
                &mut conn,
                &group_convo,
                &identity.username,
                TAG_GROUP_SETTINGS_CHANGE,
                &body,
            )
            .await?;
        }

        GroupAction::SetMemberDefaults {
            muted,
            allow_history,
        } => {
            anyhow::ensure!(am_admin, "only admins can change settings");
            let body = super::encode_event_body(&GroupSettingsChange {
                title: roster.metadata.title.clone(),
                description: roster.metadata.description.clone(),
                new_members_muted: muted,
                allow_new_members_to_see_history: allow_history,
            })?;
            let mut conn = db.acquire().await?;
            super::send::queue_message(
                &mut conn,
                &group_convo,
                &identity.username,
                TAG_GROUP_SETTINGS_CHANGE,
                &body,
            )
            .await?;
        }

        GroupAction::SetBanned { username, banned } => {
            anyhow::ensure!(am_admin, "only admins can ban/unban");
            if banned {
                roster.members.remove(&username);
                roster.banned.insert(username);
                submit_rotation(ctx, &identity, group_id, &roster).await?;
            } else {
                let body = super::encode_event_body(&GroupUnban {
                    username: username.clone(),
                })?;
                let mut conn = db.acquire().await?;
                super::send::queue_message(
                    &mut conn,
                    &group_convo,
                    &identity.username,
                    TAG_GROUP_UNBAN,
                    &body,
                )
                .await?;
            }
        }

        GroupAction::Leave => {
            if am_admin {
                roster.members.remove(&identity.username);
                submit_rotation(ctx, &identity, group_id, &roster).await?;
            } else {
                let body = Bytes::new();
                let mut conn = db.acquire().await?;
                super::send::queue_message(
                    &mut conn,
                    &group_convo,
                    &identity.username,
                    TAG_LEAVE_REQUEST,
                    &body,
                )
                .await?;
            }
        }
    }

    DbNotify::touch();
    Ok(())
}
