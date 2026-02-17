use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use anyctx::AnyCtx;
use bytes::Bytes;
use nullspace_crypt::aead::AeadKey;
use nullspace_crypt::dh::DhPublic;
use nullspace_crypt::hash::{BcsHashExt, Hash};
use nullspace_crypt::signing::{Signable, SigningPublic};
use nullspace_structs::Blob;
use nullspace_structs::e2ee::{DeviceSigned, HeaderEncrypted};
use nullspace_structs::server::{MailboxId, SignedMediumPk};
use nullspace_structs::username::UserName;
use rand::Rng;
use tracing::warn;

use crate::config::Config;
use crate::database::{DATABASE, DbNotify};
use crate::identity::Identity;
use crate::user_info::get_user_info;

use super::group::{GroupRecord, load_groups, send_to_group_mailbox};
use super::roster::{GroupRoster, RosterMember};

const GROUP_REKEY_MEAN_SECS: f64 = 3600.0;

pub(super) async fn group_rekey_loop(ctx: &AnyCtx<Config>) {
    loop {
        if let Err(err) = group_rekey_loop_once(ctx).await {
            tracing::warn!(error = %err, "group rekey loop error");
        }
        let wait = sample_rekey_interval();
        tokio::time::sleep(wait).await;
    }
}

async fn group_rekey_loop_once(ctx: &AnyCtx<Config>) -> anyhow::Result<()> {
    let db = ctx.get(DATABASE);
    let identity = Identity::load(db).await?;
    let groups = load_groups(db).await?;
    for group in groups {
        let mut conn = db.acquire().await?;
        let roster = GroupRoster::load(
            &mut conn,
            group.group_id,
            group.descriptor.init_admin.clone(),
        )
        .await?;
        let members = roster.list(&mut conn).await?;

        let admin_count = members
            .iter()
            .filter(|member| member.is_admin && member.is_active())
            .count() as u64;
        if admin_count == 0 {
            continue;
        }
        if !members.iter().any(|member| {
            member.username == identity.username && member.is_admin && member.is_active()
        }) {
            continue;
        }
        let roll: f64 = rand::random();
        if roll <= 1.0 / admin_count as f64 {
            if let Err(err) = send_group_rekey(ctx, &identity, &group).await {
                warn!(error = %err, group = ?group.group_id, "group rekey failed");
            }
            tracing::debug!(group = ?group.group_id, "group rekeyed");
        }
    }
    Ok(())
}

async fn send_group_rekey(
    ctx: &AnyCtx<Config>,
    identity: &Identity,
    group: &GroupRecord,
) -> anyhow::Result<()> {
    let recipients = collect_group_recipients(ctx, group).await?;
    let new_key = AeadKey::random();
    let key_bytes = new_key.to_bytes();
    let payload = bcs::to_bytes(&(group.group_id, key_bytes))?;
    let signed = DeviceSigned::sign_bytes(
        Bytes::from(payload),
        identity.username.clone(),
        identity.device_secret.public().signing_public(),
        &identity.device_secret,
    );
    let signed_bytes = bcs::to_bytes(&signed)?;
    let encrypted = HeaderEncrypted::encrypt_bytes(&signed_bytes, recipients)
        .map_err(|_| anyhow::anyhow!("failed to encrypt group rekey"))?;
    let outer = Blob {
        kind: Blob::V1_GROUP_REKEY.into(),
        inner: Bytes::from(bcs::to_bytes(&encrypted)?),
    };
    send_to_group_mailbox(
        ctx,
        group,
        MailboxId::group_messages(&group.group_id),
        outer,
    )
    .await?;
    Ok(())
}

async fn collect_group_recipients(
    ctx: &AnyCtx<Config>,
    group: &GroupRecord,
) -> anyhow::Result<Vec<DhPublic>> {
    let mut recipients = Vec::new();
    let mut handles = Vec::new();
    let db = ctx.get(DATABASE);
    let mut conn = db.acquire().await?;
    let roster = GroupRoster::load(
        &mut conn,
        group.group_id,
        group.descriptor.init_admin.clone(),
    )
    .await?;
    let members = roster.list(&mut conn).await?;
    for member in members.into_iter().filter(RosterMember::is_active) {
        let username = member.username;
        let peer = get_user_info(ctx, &username).await?;
        let user_recipients = collect_recipients(&username, &peer.devices, &peer.medium_pks)?;
        if !user_recipients.is_empty() {
            handles.push(username);
            recipients.extend(user_recipients);
        }
    }
    tracing::debug!(group = ?group.group_id, handles = ?handles, "rekey recipients");
    if recipients.is_empty() {
        anyhow::bail!("no recipients available for group");
    }
    Ok(recipients)
}

fn collect_recipients(
    username: &UserName,
    devices: &BTreeSet<SigningPublic>,
    medium_pks: &BTreeMap<Hash, SignedMediumPk>,
) -> anyhow::Result<Vec<DhPublic>> {
    let mut recipients = Vec::new();
    for device_pk in devices {
        let device_hash = device_pk.bcs_hash();
        let Some(medium_pk) = medium_pks.get(&device_hash) else {
            warn!(username = %username, device_hash = %device_hash, "missing medium-term key");
            continue;
        };
        if medium_pk.verify(*device_pk).is_err() {
            warn!(username = %username, device_hash = %device_hash, "invalid medium-term key signature");
            continue;
        }
        recipients.push(medium_pk.medium_pk.clone());
    }
    Ok(recipients)
}

pub(super) async fn process_group_rekey_entry(
    ctx: &AnyCtx<Config>,
    group: &GroupRecord,
    message: &Blob,
) -> anyhow::Result<()> {
    let db = ctx.get(DATABASE);
    let identity = Identity::load(db).await?;
    let encrypted: HeaderEncrypted = bcs::from_bytes(&message.inner)?;
    let decrypted = match encrypted.decrypt_bytes(&identity.medium_sk_current) {
        Ok(decrypted) => decrypted,
        Err(_) => encrypted.decrypt_bytes(&identity.medium_sk_prev)?,
    };
    let signed: DeviceSigned = bcs::from_bytes(&decrypted)?;
    let sender_username = signed.sender().clone();
    let mut conn = db.acquire().await?;
    let roster = GroupRoster::load(
        &mut conn,
        group.group_id,
        group.descriptor.init_admin.clone(),
    )
    .await?;
    let sender_member = roster.get(&mut conn, &sender_username).await?;
    if !sender_member
        .as_ref()
        .is_some_and(|member| member.is_admin && member.is_active())
    {
        warn!(sender = %sender_username, "ignoring group rekey from non-admin");
        return Ok(());
    }
    let sender_descriptor = crate::user_info::get_user_descriptor(ctx, &sender_username).await?;
    ensure_sender_device_allowed(&sender_descriptor, signed.sender_device_pk())?;
    let payload = signed
        .verify_bytes()
        .map_err(|_| anyhow::anyhow!("failed to verify device-signed rekey"))?;
    let (rekey_group, key_bytes): (nullspace_structs::group::GroupId, [u8; 32]) =
        bcs::from_bytes(&payload)?;
    if rekey_group != group.group_id {
        warn!(
            expected = %group.group_id,
            actual = %rekey_group,
            "ignoring rekey for different group"
        );
        return Ok(());
    }
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

fn ensure_sender_device_allowed(
    sender_descriptor: &nullspace_structs::username::UserDescriptor,
    sender_device_pk: SigningPublic,
) -> anyhow::Result<()> {
    if !sender_descriptor.devices.contains(&sender_device_pk) {
        anyhow::bail!("sender device not found in directory state");
    }
    Ok(())
}

fn sample_rekey_interval() -> Duration {
    let mut rng = rand::thread_rng();
    let u: f64 = rng.gen_range(f64::MIN_POSITIVE..=1.0);
    let secs = -u.ln() * GROUP_REKEY_MEAN_SECS;
    Duration::from_secs_f64(secs)
}
