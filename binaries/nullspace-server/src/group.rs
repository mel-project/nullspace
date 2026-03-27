use nullspace_crypt::signing::{Signable, SigningPublic};
use nullspace_structs::group::{GroupId, GroupRotation};
use nullspace_structs::server::{AuthToken, ServerRpcError};
use sqlx::{Sqlite, Transaction};

use crate::database::DATABASE;
use crate::fatal_retry_later;

pub async fn group_create(auth: AuthToken, rotation: GroupRotation) -> Result<(), ServerRpcError> {
    if rotation.prev_hash.is_some() {
        tracing::debug!(group = %rotation.group_id, "group create denied: initial rotation must have no prev_hash");
        return Err(ServerRpcError::AccessDenied);
    }
    if rotation.new_admin_set.is_empty() {
        tracing::debug!(group = %rotation.group_id, "group create denied: empty admin set");
        return Err(ServerRpcError::AccessDenied);
    }

    let mut tx = DATABASE.begin().await.map_err(fatal_retry_later)?;
    let Some(caller_device_pk) = auth_token_device_pk(&mut tx, auth).await? else {
        tracing::debug!(group = %rotation.group_id, "group create denied: unknown auth token");
        return Err(ServerRpcError::AccessDenied);
    };
    if rotation.signer != caller_device_pk {
        tracing::debug!(group = %rotation.group_id, "group create denied: signer/auth mismatch");
        return Err(ServerRpcError::AccessDenied);
    }
    if !rotation.new_admin_set.contains(&rotation.signer) {
        tracing::debug!(group = %rotation.group_id, "group create denied: signer not in admin set");
        return Err(ServerRpcError::AccessDenied);
    }
    rotation
        .verify(rotation.signer)
        .map_err(|_| ServerRpcError::AccessDenied)?;

    insert_rotation_row(&mut tx, 0, &rotation).await?;

    tx.commit().await.map_err(fatal_retry_later)?;
    tracing::debug!(group = %rotation.group_id, "group create accepted");
    Ok(())
}

pub async fn group_update(rotation: GroupRotation) -> Result<(), ServerRpcError> {
    if rotation.new_admin_set.is_empty() {
        tracing::debug!(group = %rotation.group_id, "group update denied: empty admin set");
        return Err(ServerRpcError::AccessDenied);
    }
    if rotation.prev_hash.is_none() {
        tracing::debug!(group = %rotation.group_id, "group update denied: missing prev_hash");
        return Err(ServerRpcError::AccessDenied);
    }

    let mut tx = DATABASE.begin().await.map_err(fatal_retry_later)?;
    let Some((latest_index, latest_rotation)) =
        latest_rotation_with_index(&mut tx, rotation.group_id).await?
    else {
        tracing::debug!(group = %rotation.group_id, "group update denied: unknown group");
        return Err(ServerRpcError::AccessDenied);
    };

    let new_index = latest_index
        .checked_add(1)
        .ok_or(ServerRpcError::AccessDenied)?;

    if !latest_rotation.new_admin_set.contains(&rotation.signer) {
        tracing::debug!(group = %rotation.group_id, index = new_index, "group update denied: signer is not an admin");
        return Err(ServerRpcError::AccessDenied);
    }
    rotation
        .verify(rotation.signer)
        .map_err(|_| ServerRpcError::AccessDenied)?;

    insert_rotation_row(&mut tx, new_index, &rotation).await?;

    tx.commit().await.map_err(fatal_retry_later)?;
    tracing::debug!(group = %rotation.group_id, index = new_index, "group update accepted");
    Ok(())
}

pub async fn group_get(
    group_id: GroupId,
    index: u64,
) -> Result<Option<GroupRotation>, ServerRpcError> {
    let index = i64::try_from(index).map_err(|_| ServerRpcError::AccessDenied)?;
    let row = sqlx::query_scalar::<_, Vec<u8>>(
        "SELECT entry FROM group_rotations \
         WHERE group_id = ? AND rotation_index = ?",
    )
    .bind(group_id.to_bytes().to_vec())
    .bind(index)
    .fetch_optional(&*DATABASE)
    .await
    .map_err(fatal_retry_later)?;

    row.map(|entry| bcs::from_bytes(&entry).map_err(fatal_retry_later))
        .transpose()
}

async fn auth_token_device_pk(
    tx: &mut Transaction<'_, Sqlite>,
    auth: AuthToken,
) -> Result<Option<SigningPublic>, ServerRpcError> {
    let auth_bytes = bcs::to_bytes(&auth).map_err(fatal_retry_later)?;
    let row = sqlx::query_scalar::<_, Vec<u8>>(
        "SELECT d.device_pk \
         FROM device_auth_tokens t \
         JOIN device_identities d \
           ON d.device_hash = t.device_hash AND d.username = t.username \
         WHERE t.auth_token = ?",
    )
    .bind(auth_bytes)
    .fetch_optional(tx.as_mut())
    .await
    .map_err(fatal_retry_later)?;

    row.map(|bytes| bytes_to_signing_public(&bytes)).transpose()
}

async fn latest_rotation_with_index(
    tx: &mut Transaction<'_, Sqlite>,
    group_id: GroupId,
) -> Result<Option<(u64, GroupRotation)>, ServerRpcError> {
    let row = sqlx::query_as::<_, (i64, Vec<u8>)>(
        "SELECT rotation_index, entry FROM group_rotations \
         WHERE group_id = ? \
         ORDER BY rotation_index DESC \
         LIMIT 1",
    )
    .bind(group_id.to_bytes().to_vec())
    .fetch_optional(tx.as_mut())
    .await
    .map_err(fatal_retry_later)?;

    row.map(|(idx, entry)| {
        let rotation = bcs::from_bytes(&entry).map_err(fatal_retry_later)?;
        Ok((idx as u64, rotation))
    })
    .transpose()
}

async fn insert_rotation_row(
    tx: &mut Transaction<'_, Sqlite>,
    index: u64,
    rotation: &GroupRotation,
) -> Result<(), ServerRpcError> {
    let index = i64::try_from(index).map_err(|_| ServerRpcError::AccessDenied)?;
    let entry_bytes = bcs::to_bytes(rotation).map_err(fatal_retry_later)?;
    sqlx::query(
        "INSERT INTO group_rotations (group_id, rotation_index, entry) \
         VALUES (?, ?, ?)",
    )
    .bind(rotation.group_id.to_bytes().to_vec())
    .bind(index)
    .bind(entry_bytes)
    .execute(tx.as_mut())
    .await
    .map_err(map_write_race)?;
    Ok(())
}

fn map_write_race(err: sqlx::Error) -> ServerRpcError {
    if is_unique_violation(&err) {
        ServerRpcError::AccessDenied
    } else {
        fatal_retry_later(err)
    }
}

fn bytes_to_signing_public(bytes: &[u8]) -> Result<SigningPublic, ServerRpcError> {
    let buf: [u8; 32] = bytes
        .try_into()
        .map_err(|_| fatal_retry_later("invalid device public key length"))?;
    SigningPublic::from_bytes(buf).map_err(|_| fatal_retry_later("invalid device public key bytes"))
}

fn is_unique_violation(err: &sqlx::Error) -> bool {
    matches!(err, sqlx::Error::Database(db_err) if db_err.is_unique_violation())
}
