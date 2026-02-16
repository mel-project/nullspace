use std::collections::{BTreeMap, HashMap};
use std::sync::LazyLock;

use nullspace_crypt::dh::DhPublic;
use nullspace_crypt::hash::{BcsHashExt, Hash};
use nullspace_crypt::signing::Signable;
use nullspace_structs::server::{
    AuthToken, DeviceAuthChallenge, ServerRpcError, SignedDeviceAuthRequest, SignedMediumPk,
};
use nullspace_structs::timestamp::Timestamp;
use nullspace_structs::username::UserName;
use rand::RngCore;
use tokio::sync::RwLock;

use crate::config::CONFIG;
use crate::database::DATABASE;
use crate::dir_client::DIR_CLIENT;
use crate::fatal_retry_later;
use crate::mailbox;

const CHALLENGE_TTL_SECS: u64 = 60;

#[derive(Clone)]
struct ChallengeEntry {
    username: UserName,
    device_hash: Hash,
    expires_at: u64,
}

static DEVICE_AUTH_CHALLENGES: LazyLock<RwLock<HashMap<[u8; 32], ChallengeEntry>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

pub async fn device_auth_start(
    username: UserName,
    device_pk: nullspace_crypt::signing::SigningPublic,
) -> Result<DeviceAuthChallenge, ServerRpcError> {
    let now = unix_time();
    let descriptor = DIR_CLIENT
        .get_user_descriptor(&username)
        .await
        .map_err(fatal_retry_later)?;
    let Some(descriptor) = descriptor else {
        tracing::debug!(username = %username, "device auth start denied: username not in directory");
        return Err(ServerRpcError::AccessDenied);
    };

    if descriptor.server_name.as_ref() != Some(&CONFIG.server_name) {
        tracing::debug!(
            username = %username,
            expected = %CONFIG.server_name,
            actual = ?descriptor.server_name,
            "device auth start denied: username server mismatch"
        );
        return Err(ServerRpcError::AccessDenied);
    }

    let device_hash = device_pk.bcs_hash();
    let Some(device_state) = descriptor.devices.get(&device_hash) else {
        tracing::debug!(username = %username, device_hash = %device_hash, "device auth start denied: unknown device");
        return Err(ServerRpcError::AccessDenied);
    };
    if !device_state.active || device_state.is_expired(now) {
        tracing::debug!(username = %username, device_hash = %device_hash, "device auth start denied: inactive or expired device");
        return Err(ServerRpcError::AccessDenied);
    }

    let mut challenge = [0u8; 32];
    rand::rng().fill_bytes(&mut challenge);
    let expires_at = now.saturating_add(CHALLENGE_TTL_SECS);

    let mut challenges = DEVICE_AUTH_CHALLENGES.write().await;
    challenges.retain(|_k, entry| entry.expires_at > now);
    challenges.insert(
        challenge,
        ChallengeEntry {
            username,
            device_hash,
            expires_at,
        },
    );

    Ok(DeviceAuthChallenge {
        challenge,
        expires_at: Timestamp(expires_at),
    })
}

pub async fn device_auth_finish(
    request: SignedDeviceAuthRequest,
) -> Result<AuthToken, ServerRpcError> {
    request
        .verify(request.request.device_pk)
        .map_err(|_| ServerRpcError::AccessDenied)?;

    let now = unix_time();
    let challenge_entry = {
        let mut challenges = DEVICE_AUTH_CHALLENGES.write().await;
        challenges.retain(|_k, entry| entry.expires_at > now);
        challenges.remove(&request.request.challenge)
    }
    .ok_or(ServerRpcError::AccessDenied)?;

    if challenge_entry.expires_at <= now {
        return Err(ServerRpcError::AccessDenied);
    }

    let request_device_hash = request.request.device_pk.bcs_hash();
    if request.request.username != challenge_entry.username
        || request_device_hash != challenge_entry.device_hash
    {
        return Err(ServerRpcError::AccessDenied);
    }

    let descriptor = DIR_CLIENT
        .get_user_descriptor(&request.request.username)
        .await
        .map_err(fatal_retry_later)?;
    let Some(descriptor) = descriptor else {
        return Err(ServerRpcError::AccessDenied);
    };

    if descriptor.server_name.as_ref() != Some(&CONFIG.server_name) {
        return Err(ServerRpcError::AccessDenied);
    }

    let Some(device_state) = descriptor.devices.get(&request_device_hash) else {
        return Err(ServerRpcError::AccessDenied);
    };
    if !device_state.active || device_state.is_expired(now) {
        return Err(ServerRpcError::AccessDenied);
    }

    let username = request.request.username;
    let device_hash = request_device_hash;

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

    sqlx::query(
        "INSERT OR REPLACE INTO device_identities (device_hash, username, device_pk) \
         VALUES (?, ?, ?)",
    )
    .bind(device_hash.to_bytes().to_vec())
    .bind(username.as_str())
    .bind(request.request.device_pk.to_bytes().to_vec())
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

    let device_pk = sqlx::query_scalar::<_, Vec<u8>>(
        "SELECT device_pk FROM device_identities WHERE device_hash = ? AND username = ?",
    )
    .bind(&device_hash)
    .bind(username)
    .fetch_optional(&*DATABASE)
    .await
    .map_err(fatal_retry_later)?;
    let Some(device_pk) = device_pk else {
        return Err(ServerRpcError::AccessDenied);
    };
    let device_pk = bytes_to_signing_public(&device_pk)?;

    let device_hash_obj = bytes_to_hash(&device_hash)?;
    if device_pk.bcs_hash() != device_hash_obj {
        return Err(ServerRpcError::AccessDenied);
    }

    medium_pk
        .verify(device_pk)
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
         JOIN device_identities d ON t.device_hash = d.device_hash \
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

pub async fn auth_token_exists(auth: AuthToken) -> Result<bool, ServerRpcError> {
    let auth_bytes = bcs::to_bytes(&auth).map_err(fatal_retry_later)?;
    let exists = sqlx::query_scalar::<_, i64>(
        "SELECT 1 FROM device_auth_tokens WHERE auth_token = ? LIMIT 1",
    )
    .bind(auth_bytes)
    .fetch_optional(&*DATABASE)
    .await
    .map_err(fatal_retry_later)?
    .is_some();
    Ok(exists)
}

fn bytes_to_hash(bytes: &[u8]) -> Result<Hash, ServerRpcError> {
    let buf: [u8; 32] = bytes
        .try_into()
        .map_err(|_| fatal_retry_later("invalid device hash length"))?;
    Ok(Hash::from_bytes(buf))
}

fn bytes_to_signing_public(
    bytes: &[u8],
) -> Result<nullspace_crypt::signing::SigningPublic, ServerRpcError> {
    let buf: [u8; 32] = bytes
        .try_into()
        .map_err(|_| fatal_retry_later("invalid device public key length"))?;
    nullspace_crypt::signing::SigningPublic::from_bytes(buf)
        .map_err(|_| fatal_retry_later("invalid device public key bytes"))
}

fn bytes_to_pk(bytes: &[u8]) -> Result<DhPublic, ServerRpcError> {
    let buf: [u8; 32] = bytes
        .try_into()
        .map_err(|_| fatal_retry_later("invalid medium pk length"))?;
    Ok(DhPublic::from_bytes(buf))
}

fn bytes_to_signature(bytes: &[u8]) -> Result<nullspace_crypt::signing::Signature, ServerRpcError> {
    let buf: [u8; 64] = bytes
        .try_into()
        .map_err(|_| fatal_retry_later("invalid signature length"))?;
    Ok(nullspace_crypt::signing::Signature::from_bytes(buf))
}

fn created_to_timestamp(
    created: i64,
) -> Result<nullspace_structs::timestamp::Timestamp, ServerRpcError> {
    let created =
        u64::try_from(created).map_err(|_| fatal_retry_later("invalid created timestamp"))?;
    Ok(nullspace_structs::timestamp::Timestamp(created))
}

fn unix_time() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
