use std::collections::{BTreeMap, BTreeSet};

use anyctx::AnyCtx;
use bytes::Bytes;
use nullspace_crypt::hash::Hash;
use nullspace_crypt::signing::{Signable, Signature, SigningPublic};
use nullspace_structs::e2ee::HeaderEncrypted;
use nullspace_structs::event::{
    GroupInvitationBody, GroupMetadataChangeBody, GroupMuteChangeBody, GroupSettingsChangeBody,
    TAG_GROUP_INVITATION, TAG_GROUP_METADATA_CHANGE, TAG_GROUP_MUTE_CHANGE,
    TAG_GROUP_SETTINGS_CHANGE, TAG_LEAVE_REQUEST,
};
use nullspace_structs::group::{
    GroupBearerKey, GroupId, GroupMetadata, GroupRoster, GroupRosterSettings, GroupRotation,
    GroupRotationPayload, MemberState,
};
use nullspace_structs::server::ServerName;

use crate::config::Config;
use crate::database::DATABASE;
use crate::identity::Identity;
use crate::internal::{GroupAction, GroupCreateRequest};
use crate::net::{get_auth_token, get_server_client, own_server_name};

use super::group_rotation::submit_rotation;
use super::{ConvoId, ensure_thread_id};

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

    // Build initial roster with creator as sole admin
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

    let payload = GroupRotationPayload {
        gbk: gbk.clone(),
        roster: roster.clone(),
    };
    let payload_bytes = bcs::to_bytes(&payload)?;
    let payload_encrypted =
        HeaderEncrypted::encrypt_bytes(&payload_bytes, [identity.medium_sk_current.public_key()])
            .map_err(|e| anyhow::anyhow!(e))?;

    let device_pk = identity.device_secret.public().signing_public();
    let mut admin_set = BTreeSet::new();
    admin_set.insert(device_pk);

    let mut rotation = GroupRotation {
        group_id,
        prev_hash: None,
        signer: device_pk,
        new_admin_set: admin_set.clone(),
        gbk_rotation: payload_encrypted,
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

    // Store GBK, roster, and create thread atomically
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
    store_roster(&mut tx, group_id, 0, &roster).await?;
    let convo_id = ConvoId::Group { group_id };
    ensure_thread_id(&mut tx, convo_id.convo_type(), &convo_id.counterparty()).await?;
    tx.commit().await?;

    Ok(group_id)
}

pub async fn store_gbk(
    conn: &mut sqlx::SqliteConnection,
    group_id: GroupId,
    gbk: &GroupBearerKey,
    server_name: &ServerName,
    rotation_index: u64,
    admin_set: &BTreeSet<SigningPublic>,
    rotation_hash: &Hash,
) -> anyhow::Result<()> {
    let gid = group_id.to_bytes().to_vec();

    // Delete all but the most recent row so we keep at most 2 (prev + new)
    sqlx::query(
        "DELETE FROM group_keys WHERE group_id = ? AND rotation_index < \
         (SELECT MAX(rotation_index) FROM group_keys WHERE group_id = ?)",
    )
    .bind(&gid)
    .bind(&gid)
    .execute(&mut *conn)
    .await?;

    sqlx::query(
        "INSERT INTO group_keys (group_id, rotation_index, gbk, server_name, admin_set, rotation_hash) \
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(&gid)
    .bind(rotation_index as i64)
    .bind(bcs::to_bytes(gbk)?)
    .bind(server_name.as_str())
    .bind(bcs::to_bytes(admin_set)?)
    .bind(rotation_hash.to_bytes().to_vec())
    .execute(&mut *conn)
    .await?;
    Ok(())
}

pub async fn store_roster(
    conn: &mut sqlx::SqliteConnection,
    group_id: GroupId,
    rotation_index: u64,
    roster: &GroupRoster,
) -> anyhow::Result<()> {
    let gid = group_id.to_bytes().to_vec();
    let roster_bytes = bcs::to_bytes(roster)?;
    sqlx::query(
        "INSERT INTO group_rosters (group_id, rotation_index, roster) \
         VALUES (?, ?, ?) \
         ON CONFLICT(group_id) DO UPDATE SET \
           rotation_index = excluded.rotation_index, \
           roster = excluded.roster",
    )
    .bind(gid)
    .bind(rotation_index as i64)
    .bind(roster_bytes)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

pub async fn load_roster(
    conn: &mut sqlx::SqliteConnection,
    group_id: GroupId,
) -> anyhow::Result<(u64, GroupRoster)> {
    let row = sqlx::query_as::<_, (i64, Vec<u8>)>(
        "SELECT rotation_index, roster FROM group_rosters WHERE group_id = ?",
    )
    .bind(group_id.to_bytes().to_vec())
    .fetch_optional(&mut *conn)
    .await?
    .ok_or_else(|| anyhow::anyhow!("no roster found for group {group_id}"))?;
    let roster: GroupRoster = bcs::from_bytes(&row.1)?;
    Ok((row.0 as u64, roster))
}

/// Loaded state for the most recent GBK of a group.
pub struct LoadedGbk {
    pub rotation_index: u64,
    pub gbk: GroupBearerKey,
    pub server_name: ServerName,
    pub admin_set: BTreeSet<SigningPublic>,
    pub rotation_hash: Hash,
}

pub async fn load_gbk(
    conn: &mut sqlx::SqliteConnection,
    group_id: GroupId,
) -> anyhow::Result<LoadedGbk> {
    let row = sqlx::query_as::<_, (i64, Vec<u8>, String, Vec<u8>, Vec<u8>)>(
        "SELECT rotation_index, gbk, server_name, admin_set, rotation_hash FROM group_keys \
         WHERE group_id = ? ORDER BY rotation_index DESC LIMIT 1",
    )
    .bind(group_id.to_bytes().to_vec())
    .fetch_optional(&mut *conn)
    .await?
    .ok_or_else(|| anyhow::anyhow!("no GBK found for group {group_id}"))?;
    let gbk: GroupBearerKey = bcs::from_bytes(&row.1)?;
    let server_name = ServerName::parse(row.2)?;
    let admin_set: BTreeSet<SigningPublic> = bcs::from_bytes(&row.3)?;
    let hash_bytes: [u8; 32] = row
        .4
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid rotation_hash length"))?;
    let rotation_hash = Hash::from_bytes(hash_bytes);
    Ok(LoadedGbk {
        rotation_index: row.0 as u64,
        gbk,
        server_name,
        admin_set,
        rotation_hash,
    })
}

/// Dispatch a group action. Rotation-requiring actions (ban, admin leave) submit
/// a new rotation. Mailbox-event actions (admin changes, mutes, metadata) are
/// queued as events through the normal send path. ShareInvite DMs the GBK.
pub async fn group_action(
    ctx: &AnyCtx<Config>,
    group_id: GroupId,
    action: GroupAction,
) -> anyhow::Result<()> {
    let db = ctx.get(DATABASE);
    let identity = Identity::load(&mut *db.acquire().await?).await?;
    let (rotation_index, mut roster) = load_roster(&mut *db.acquire().await?, group_id).await?;
    let loaded = load_gbk(&mut *db.acquire().await?, group_id).await?;
    let gbk_rotation_index = loaded.rotation_index;
    let prev_rotation_hash = loaded.rotation_hash;
    let gbk = loaded.gbk;

    let am_admin = roster
        .members
        .get(&identity.username)
        .map_or(false, |m| m.is_admin);

    let group_convo = ConvoId::Group { group_id };

    match action {
        GroupAction::ShareInvite { username } => {
            anyhow::ensure!(am_admin, "only admins can invite");
            anyhow::ensure!(!roster.banned.contains(&username), "user is banned");
            let invitation = GroupInvitationBody {
                group_id: gbk.group_id,
                gbk: gbk.clone(),
                rotation_index: gbk_rotation_index,
                title: roster.metadata.title.clone(),
                description: roster.metadata.description.clone(),
            };
            let body = Bytes::from(bcs::to_bytes(&invitation)?);
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
            // Admin set changes require a rotation: the rotation's new_admin_set is the
            // authoritative record of who may sign the next rotation, so it must be updated
            // immediately rather than via an in-epoch event.
            submit_rotation(ctx, &identity, group_id, prev_rotation_hash, &roster, &gbk).await?;
        }

        GroupAction::SetMemberMuted { username, muted } => {
            anyhow::ensure!(am_admin, "only admins can mute/unmute");
            let body = Bytes::from(bcs::to_bytes(&GroupMuteChangeBody { username, muted })?);
            let mut conn = db.acquire().await?;
            super::send::queue_message(
                &mut conn,
                &group_convo,
                &identity.username,
                TAG_GROUP_MUTE_CHANGE,
                &body,
            )
            .await?;
        }

        GroupAction::SetMetadata { title, description } => {
            anyhow::ensure!(am_admin, "only admins can change metadata");
            let body = Bytes::from(bcs::to_bytes(&GroupMetadataChangeBody {
                title,
                description,
            })?);
            let mut conn = db.acquire().await?;
            super::send::queue_message(
                &mut conn,
                &group_convo,
                &identity.username,
                TAG_GROUP_METADATA_CHANGE,
                &body,
            )
            .await?;
        }

        GroupAction::SetNewMembersMuted { muted } => {
            anyhow::ensure!(am_admin, "only admins can change settings");
            let body = Bytes::from(bcs::to_bytes(&GroupSettingsChangeBody {
                new_members_muted: muted,
                allow_new_members_to_see_history: roster.settings.allow_new_members_to_see_history,
            })?);
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
            let body = Bytes::from(bcs::to_bytes(&GroupSettingsChangeBody {
                new_members_muted: roster.settings.new_members_muted,
                allow_new_members_to_see_history: allow,
            })?);
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
                submit_rotation(ctx, &identity, group_id, prev_rotation_hash, &roster, &gbk)
                    .await?;
            } else {
                roster.banned.remove(&username);
                store_roster(&mut *db.acquire().await?, group_id, rotation_index, &roster).await?;
            }
        }

        GroupAction::Leave => {
            if am_admin {
                roster.members.remove(&identity.username);
                submit_rotation(ctx, &identity, group_id, prev_rotation_hash, &roster, &gbk)
                    .await?;
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
                // Delete local group state
                sqlx::query("DELETE FROM group_keys WHERE group_id = ?")
                    .bind(group_id.to_bytes().to_vec())
                    .execute(&mut *conn)
                    .await?;
                sqlx::query("DELETE FROM group_rosters WHERE group_id = ?")
                    .bind(group_id.to_bytes().to_vec())
                    .execute(&mut *conn)
                    .await?;
            }
        }
    }

    crate::database::DbNotify::touch();
    Ok(())
}
