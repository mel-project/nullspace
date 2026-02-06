use nullspace_crypt::signing::Signable;
use nullspace_structs::certificate::CertificateChain;
use nullspace_structs::profile::UserProfile;
use nullspace_structs::server::ServerRpcError;
use nullspace_structs::username::UserName;

use crate::database::DATABASE;
use crate::fatal_retry_later;

pub async fn profile_get(username: UserName) -> Result<Option<UserProfile>, ServerRpcError> {
    let row = sqlx::query_scalar::<_, Vec<u8>>(
        "SELECT profile FROM user_profiles WHERE username = ?",
    )
    .bind(username.as_str())
    .fetch_optional(&*DATABASE)
    .await
    .map_err(fatal_retry_later)?;

    let Some(profile_bytes) = row else {
        return Ok(None);
    };

    let profile = bcs::from_bytes(&profile_bytes).map_err(fatal_retry_later)?;
    Ok(Some(profile))
}

pub async fn profile_set(
    username: UserName,
    profile: UserProfile,
) -> Result<(), ServerRpcError> {
    let device_rows = sqlx::query_scalar::<_, Vec<u8>>(
        "SELECT cert_chain FROM device_certificates WHERE username = ?",
    )
    .bind(username.as_str())
    .fetch_all(&*DATABASE)
    .await
    .map_err(fatal_retry_later)?;

    if device_rows.is_empty() {
        return Err(ServerRpcError::AccessDenied);
    }

    let mut verified = false;
    for chain_bytes in device_rows {
        let chain: CertificateChain = bcs::from_bytes(&chain_bytes).map_err(fatal_retry_later)?;
        let device = chain.last_device();
        if profile.verify(device.pk.signing_public()).is_ok() {
            verified = true;
            break;
        }
    }
    if !verified {
        return Err(ServerRpcError::AccessDenied);
    }

    let created = i64::try_from(profile.created.0)
        .map_err(|_| fatal_retry_later("invalid created timestamp"))?;
    let profile_bytes = bcs::to_bytes(&profile).map_err(fatal_retry_later)?;

    let mut tx = DATABASE.begin().await.map_err(fatal_retry_later)?;
    let existing_created =
        sqlx::query_scalar::<_, i64>("SELECT created FROM user_profiles WHERE username = ?")
            .bind(username.as_str())
            .fetch_optional(tx.as_mut())
            .await
            .map_err(fatal_retry_later)?;

    if let Some(previous_created) = existing_created
        && created <= previous_created {
            return Err(ServerRpcError::AccessDenied);
        }

    sqlx::query(
        "INSERT OR REPLACE INTO user_profiles (username, profile, created) VALUES (?, ?, ?)",
    )
    .bind(username.as_str())
    .bind(profile_bytes)
    .bind(created)
    .execute(tx.as_mut())
    .await
    .map_err(fatal_retry_later)?;
    tx.commit().await.map_err(fatal_retry_later)?;
    Ok(())
}
