use nullspace_crypt::signing::Signable;
use nullspace_structs::profile::UserProfile;
use nullspace_structs::server::ServerRpcError;
use nullspace_structs::username::UserName;

use crate::config::CONFIG;
use crate::database::DATABASE;
use crate::dir_client::DIR_CLIENT;
use crate::fatal_retry_later;

pub async fn profile_get(username: UserName) -> Result<Option<UserProfile>, ServerRpcError> {
    let row =
        sqlx::query_scalar::<_, Vec<u8>>("SELECT profile FROM user_profiles WHERE username = ?")
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

pub async fn profile_set(username: UserName, profile: UserProfile) -> Result<(), ServerRpcError> {
    let descriptor = DIR_CLIENT
        .get_user_descriptor(&username)
        .await
        .map_err(fatal_retry_later)?;
    let Some(descriptor) = descriptor else {
        return Err(ServerRpcError::AccessDenied);
    };
    if descriptor.server_name != CONFIG.server_name {
        return Err(ServerRpcError::AccessDenied);
    }

    let mut verified = false;
    for device_pk in &descriptor.devices {
        if profile.verify(*device_pk).is_ok() {
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
        && created <= previous_created
    {
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
