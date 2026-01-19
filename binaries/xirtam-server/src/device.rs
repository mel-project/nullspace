use std::collections::BTreeMap;

use xirtam_crypt::dh::DhPublic;
use xirtam_crypt::hash::{BcsHashExt, Hash};
use xirtam_crypt::signing::Signable;
use xirtam_structs::certificate::CertificateChain;
use xirtam_structs::server::{AuthToken, ServerRpcError, SignedMediumPk};
use xirtam_structs::username::UserName;

use crate::config::CONFIG;
use crate::database::DATABASE;
use crate::dir_client::DIR_CLIENT;
use crate::fatal_retry_later;
use crate::mailbox;

pub async fn device_auth(
    username: UserName,
    cert: CertificateChain,
) -> Result<AuthToken, ServerRpcError> {
    let device = cert.last_device();
    let device_hash = device.pk.bcs_hash();

    let descriptor = DIR_CLIENT
        .get_user_descriptor(&username)
        .await
        .map_err(fatal_retry_later)?;
    let Some(descriptor) = descriptor else {
        tracing::debug!(username = %username, "device auth denied: username not in directory");
        return Err(ServerRpcError::AccessDenied);
    };
    if descriptor.server_name != CONFIG.server_name {
        tracing::debug!(
            username = %username,
            expected = %CONFIG.server_name,
            actual = %descriptor.server_name,
            "device auth denied: username server mismatch"
        );
        return Err(ServerRpcError::AccessDenied);
    }

    if cert.verify(descriptor.root_cert_hash).is_err() {
        tracing::debug!(username = %username, "device auth denied: certificate chain invalid");
        return Err(ServerRpcError::AccessDenied);
    }

    let mut tx = DATABASE.begin().await.map_err(fatal_retry_later)?;
    let existing_token = sqlx::query_scalar::<_, Vec<u8>>(
        "SELECT auth_token FROM device_auth_tokens WHERE username = ? AND device_hash = ?",
    )
    .bind(username.as_str())
    .bind(device_hash.to_bytes().to_vec())
    .fetch_optional(tx.as_mut())
    .await
    .map_err(fatal_retry_later)?;
    let has_existing_token = existing_token.is_some();
    let mut auth_token: Option<AuthToken> = match existing_token {
        Some(data) => Some(bcs::from_bytes(&data).map_err(fatal_retry_later)?),
        None => None,
    };
    let mut newly_created: Option<AuthToken> = None;
    let data = bcs::to_bytes(&cert).map_err(fatal_retry_later)?;
    sqlx::query(
        "INSERT OR REPLACE INTO device_certificates (device_hash, username, cert_chain) \
         VALUES (?, ?, ?)",
    )
    .bind(device_hash.to_bytes().to_vec())
    .bind(username.as_str())
    .bind(data)
    .execute(tx.as_mut())
    .await
    .map_err(fatal_retry_later)?;
    if auth_token.is_none() {
        let new_token = AuthToken::random();
        let token_data = bcs::to_bytes(&new_token).map_err(fatal_retry_later)?;
        sqlx::query(
            "INSERT OR REPLACE INTO device_auth_tokens (username, device_hash, auth_token) \
             VALUES (?, ?, ?)",
        )
        .bind(username.as_str())
        .bind(device_hash.to_bytes().to_vec())
        .bind(token_data)
        .execute(tx.as_mut())
        .await
        .map_err(fatal_retry_later)?;
        auth_token = Some(new_token);
        newly_created = Some(new_token);
    }
    mailbox::update_dm_mailbox(&mut tx, &username, newly_created).await?;
    tx.commit().await.map_err(fatal_retry_later)?;

    let auth_token = auth_token.expect("auth token is set");
    tracing::debug!(
        username = %username,
        reused_token = %has_existing_token,
        "device auth accepted"
    );
    Ok(auth_token)
}

pub async fn device_list(
    username: UserName,
) -> Result<Option<BTreeMap<Hash, CertificateChain>>, ServerRpcError> {
    let rows = sqlx::query_as::<_, (Vec<u8>, Vec<u8>)>(
        "SELECT device_hash, cert_chain FROM device_certificates WHERE username = ?",
    )
    .bind(username.as_str())
    .fetch_all(&*DATABASE)
    .await
    .map_err(fatal_retry_later)?;
    if rows.is_empty() {
        return Ok(None);
    }
    let mut out = BTreeMap::new();
    for (device_hash, chain_bytes) in rows {
        let hash = bytes_to_hash(&device_hash)?;
        let chain = bcs::from_bytes(&chain_bytes).map_err(fatal_retry_later)?;
        out.insert(hash, chain);
    }
    Ok(Some(out))
}

pub async fn device_add_medium_pk(
    auth: AuthToken,
    medium_pk: SignedMediumPk,
) -> Result<(), ServerRpcError> {
    let auth_bytes = bcs::to_bytes(&auth).map_err(fatal_retry_later)?;
    let row = sqlx::query_as::<_, (Vec<u8>, String)>(
        "SELECT device_hash, username FROM device_auth_tokens WHERE auth_token = ?",
    )
    .bind(auth_bytes)
    .fetch_optional(&*DATABASE)
    .await
    .map_err(fatal_retry_later)?;
    let Some((device_hash, username)) = row else {
        return Err(ServerRpcError::AccessDenied);
    };
    let chain_bytes = sqlx::query_scalar::<_, Vec<u8>>(
        "SELECT cert_chain FROM device_certificates WHERE device_hash = ? AND username = ?",
    )
    .bind(&device_hash)
    .bind(username)
    .fetch_optional(&*DATABASE)
    .await
    .map_err(fatal_retry_later)?;
    let Some(chain_bytes) = chain_bytes else {
        return Err(ServerRpcError::AccessDenied);
    };
    let chain: CertificateChain = bcs::from_bytes(&chain_bytes).map_err(fatal_retry_later)?;
    let device = chain.last_device();
    let device_hash_obj = bytes_to_hash(&device_hash)?;
    if device.pk.bcs_hash() != device_hash_obj {
        return Err(ServerRpcError::AccessDenied);
    }
    medium_pk
        .verify(device.pk.signing_public())
        .map_err(|_| ServerRpcError::AccessDenied)?;
    let created = i64::try_from(medium_pk.created.0)
        .map_err(|_| fatal_retry_later("invalid created timestamp"))?;
    sqlx::query(
        "INSERT OR REPLACE INTO device_medium_pks \
         (device_hash, medium_pk, created, signature) VALUES (?, ?, ?, ?)",
    )
    .bind(device_hash)
    .bind(medium_pk.medium_pk.to_bytes().to_vec())
    .bind(created)
    .bind(medium_pk.signature.to_bytes().to_vec())
    .execute(&*DATABASE)
    .await
    .map_err(fatal_retry_later)?;
    Ok(())
}

pub async fn device_medium_pks(
    username: UserName,
) -> Result<BTreeMap<Hash, SignedMediumPk>, ServerRpcError> {
    let rows = sqlx::query_as::<_, (Vec<u8>, Vec<u8>, i64, Vec<u8>)>(
        "SELECT t.device_hash, t.medium_pk, t.created, t.signature \
         FROM device_medium_pks t \
         JOIN device_auth_tokens d ON t.device_hash = d.device_hash \
         WHERE d.username = ?",
    )
    .bind(username.as_str())
    .fetch_all(&*DATABASE)
    .await
    .map_err(fatal_retry_later)?;

    let mut out = BTreeMap::new();
    for (device_hash, medium_pk, created, signature) in rows {
        let hash = bytes_to_hash(&device_hash)?;
        let pk = bytes_to_pk(&medium_pk)?;
        let created = created_to_timestamp(created)?;
        let signature = bytes_to_signature(&signature)?;
        out.insert(
            hash,
            SignedMediumPk {
                medium_pk: pk,
                created,
                signature,
            },
        );
    }
    Ok(out)
}

fn bytes_to_hash(bytes: &[u8]) -> Result<Hash, ServerRpcError> {
    let buf: [u8; 32] = bytes
        .try_into()
        .map_err(|_| fatal_retry_later("invalid device hash length"))?;
    Ok(Hash::from_bytes(buf))
}

fn bytes_to_pk(bytes: &[u8]) -> Result<DhPublic, ServerRpcError> {
    let buf: [u8; 32] = bytes
        .try_into()
        .map_err(|_| fatal_retry_later("invalid medium pk length"))?;
    Ok(DhPublic::from_bytes(buf))
}

fn bytes_to_signature(
    bytes: &[u8],
) -> Result<xirtam_crypt::signing::Signature, ServerRpcError> {
    let buf: [u8; 64] = bytes
        .try_into()
        .map_err(|_| fatal_retry_later("invalid signature length"))?;
    Ok(xirtam_crypt::signing::Signature::from_bytes(buf))
}

fn created_to_timestamp(
    created: i64,
) -> Result<xirtam_structs::timestamp::Timestamp, ServerRpcError> {
    let created =
        u64::try_from(created).map_err(|_| fatal_retry_later("invalid created timestamp"))?;
    Ok(xirtam_structs::timestamp::Timestamp(created))
}
