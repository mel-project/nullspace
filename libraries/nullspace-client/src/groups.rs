use std::collections::BTreeSet;

use anyctx::AnyCtx;
use nullspace_crypt::signing::{Signable, Signature};
use nullspace_structs::e2ee::HeaderEncrypted;
use nullspace_structs::group::{GroupBearerKey, GroupId, GroupRotation};
use nullspace_structs::server::ServerName;

use crate::auth_tokens::get_auth_token;
use crate::config::Config;
use crate::convo::{ConvoId, ensure_thread_id};
use crate::database::DATABASE;
use crate::identity::Identity;
use crate::internal::GroupCreateRequest;
use crate::server::{get_server_client, own_server_name};

pub async fn group_create(
    ctx: &AnyCtx<Config>,
    _request: GroupCreateRequest,
) -> anyhow::Result<GroupId> {
    let db = ctx.get(DATABASE);
    let identity = Identity::load(&mut *db.acquire().await?).await?;
    let server_name = own_server_name(ctx, &identity).await?;
    let server = get_server_client(ctx, &server_name).await?;
    let auth = get_auth_token(ctx).await?;

    let group_id = GroupId::random();
    let gbk = GroupBearerKey::generate(group_id, server_name.clone());

    // Encrypt GBK to our own device's medium-term key
    let gbk_bytes = bcs::to_bytes(&gbk)?;
    let gbk_encrypted = HeaderEncrypted::encrypt_bytes(
        &gbk_bytes,
        [identity.medium_sk_current.public_key()],
    )
    .map_err(|e| anyhow::anyhow!(e))?;

    let device_pk = identity.device_secret.public().signing_public();
    let mut admin_set = BTreeSet::new();
    admin_set.insert(device_pk);

    let mut rotation = GroupRotation {
        group_id,
        index: 0,
        signer: device_pk,
        new_admin_set: admin_set,
        gbk_rotation: gbk_encrypted,
        signature: Signature::from_bytes([0u8; 64]),
    };
    rotation.sign(&identity.device_secret);

    server
        .group_create(auth.clone(), rotation)
        .await?
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;

    server
        .mailbox_create(auth, gbk.mailbox_key())
        .await?
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;

    // Store GBK and create thread atomically
    let mut tx = db.begin().await?;
    store_gbk(&mut tx, group_id, &gbk, &server_name, 0).await?;
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
        "INSERT INTO group_keys (group_id, rotation_index, gbk, server_name) VALUES (?, ?, ?, ?)",
    )
    .bind(&gid)
    .bind(rotation_index as i64)
    .bind(bcs::to_bytes(gbk)?)
    .bind(server_name.as_str())
    .execute(&mut *conn)
    .await?;
    Ok(())
}
