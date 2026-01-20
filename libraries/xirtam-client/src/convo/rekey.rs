use std::collections::BTreeMap;
use std::time::Duration;

use anyctx::AnyCtx;
use anyhow::Context;
use bytes::Bytes;
use rand::Rng;
use tracing::warn;
use xirtam_crypt::aead::AeadKey;
use xirtam_crypt::dh::DhPublic;
use xirtam_crypt::hash::{BcsHashExt, Hash};
use xirtam_crypt::signing::Signable;
use xirtam_structs::Blob;
use xirtam_structs::certificate::CertificateChain;
use xirtam_structs::e2ee::{DeviceSigned, HeaderEncrypted};
use xirtam_structs::server::{MailboxId, SignedMediumPk};
use xirtam_structs::username::UserName;

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
    let key_blob = Blob {
        kind: Blob::V1_AEAD_KEY.into(),
        inner: Bytes::from(new_key.to_bytes().to_vec()),
    };
    let signed = DeviceSigned::sign_blob(
        &key_blob,
        identity.username.clone(),
        identity.cert_chain.clone(),
        &identity.device_secret,
    )?;
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
        let peer = get_user_info(ctx, &username).await?;
        let user_recipients =
            collect_recipients(&username, &peer.device_chains, &peer.medium_pks)?;
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
    chains: &BTreeMap<Hash, CertificateChain>,
    medium_pks: &BTreeMap<Hash, SignedMediumPk>,
) -> anyhow::Result<Vec<DhPublic>> {
    let mut recipients = Vec::new();
    for (device_hash, chain) in chains {
        let cert = chain.last_device();
        let cert_hash = cert.pk.bcs_hash();
        if &cert_hash != device_hash {
            warn!(
                username = %username,
                device_hash = %device_hash,
                cert_hash = %cert_hash,
                "device certificate hash mismatch"
            );
            continue;
        }
        let Some(medium_pk) = medium_pks.get(device_hash) else {
            warn!(username = %username, device_hash = %device_hash, "missing medium-term key");
            continue;
        };
        if medium_pk.verify(cert.pk.signing_public()).is_err() {
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
    let inner = signed
        .verify_blob(sender_descriptor.root_cert_hash)
        .map_err(|_| anyhow::anyhow!("failed to verify device-signed rekey"))?;
    if inner.kind != Blob::V1_AEAD_KEY {
        warn!(kind = %inner.kind, "ignoring non-rekey payload");
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

fn sample_rekey_interval() -> Duration {
    let mut rng = rand::thread_rng();
    let u: f64 = rng.gen_range(f64::MIN_POSITIVE..=1.0);
    let secs = -u.ln() * GROUP_REKEY_MEAN_SECS;
    Duration::from_secs_f64(secs)
}
