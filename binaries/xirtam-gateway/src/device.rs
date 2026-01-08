use xirtam_crypt::hash::BcsHashExt;
use xirtam_structs::certificate::CertificateChain;
use xirtam_structs::gateway::{AuthToken, GatewayServerError};
use xirtam_structs::handle::Handle;

use crate::config::CONFIG;
use crate::database::DATABASE;
use crate::dir_client::DIR_CLIENT;
use crate::fatal_retry_later;

pub async fn device_auth(
    handle: Handle,
    cert: CertificateChain,
) -> Result<AuthToken, GatewayServerError> {
    let device = match cert.last_device() {
        Some(device) => device,
        None => {
            tracing::debug!(handle = %handle, "device auth denied: empty certificate chain");
            return Err(GatewayServerError::AccessDenied);
        }
    };
    let device_hash = device.pk.bcs_hash();

    let descriptor = DIR_CLIENT
        .get_handle_descriptor(&handle)
        .await
        .map_err(fatal_retry_later)?;
    let Some(descriptor) = descriptor else {
        tracing::debug!(handle = %handle, "device auth denied: handle not in directory");
        return Err(GatewayServerError::AccessDenied);
    };
    if descriptor.gateway_name != CONFIG.gateway_name {
        tracing::debug!(
            handle = %handle,
            expected = %CONFIG.gateway_name,
            actual = %descriptor.gateway_name,
            "device auth denied: handle gateway mismatch"
        );
        return Err(GatewayServerError::AccessDenied);
    }

    if cert.verify(descriptor.root_cert_hash).is_err() {
        tracing::debug!(handle = %handle, "device auth denied: certificate chain invalid");
        return Err(GatewayServerError::AccessDenied);
    }

    let mut tx = DATABASE.begin().await.map_err(fatal_retry_later)?;
    let existing_token = sqlx::query_scalar::<_, Vec<u8>>(
        "SELECT auth_token FROM device_auth_tokens WHERE handle = ? AND device_hash = ?",
    )
    .bind(handle.as_str())
    .bind(device_hash.to_bytes().to_vec())
    .fetch_optional(&mut *tx)
    .await
    .map_err(fatal_retry_later)?;
    let has_existing_token = existing_token.is_some();
    let mut auth_token: Option<AuthToken> = match existing_token {
        Some(data) => Some(bcs::from_bytes(&data).map_err(fatal_retry_later)?),
        None => None,
    };
    let existing = sqlx::query_scalar::<_, Vec<u8>>(
        "SELECT cert_chain FROM device_certificates WHERE handle = ?",
    )
    .bind(handle.as_str())
    .fetch_optional(&mut *tx)
    .await
    .map_err(fatal_retry_later)?;
    let existing_chain = match existing {
        Some(data) => bcs::from_bytes(&data).map_err(fatal_retry_later)?,
        None => CertificateChain(Vec::new()),
    };
    let merged = existing_chain.merge(&cert);
    if merged.verify(descriptor.root_cert_hash).is_err() {
        tracing::debug!(handle = %handle, "device auth denied: merged chain invalid");
        return Err(GatewayServerError::AccessDenied);
    }
    let data = bcs::to_bytes(&merged).map_err(fatal_retry_later)?;
    sqlx::query("INSERT OR REPLACE INTO device_certificates (handle, cert_chain) VALUES (?, ?)")
        .bind(handle.as_str())
        .bind(data)
        .execute(&mut *tx)
        .await
        .map_err(fatal_retry_later)?;
    if auth_token.is_none() {
        let new_token = AuthToken::random();
        let token_data = bcs::to_bytes(&new_token).map_err(fatal_retry_later)?;
        sqlx::query(
            "INSERT OR REPLACE INTO device_auth_tokens (handle, device_hash, auth_token) \
             VALUES (?, ?, ?)",
        )
        .bind(handle.as_str())
        .bind(device_hash.to_bytes().to_vec())
        .bind(token_data)
        .execute(&mut *tx)
        .await
        .map_err(fatal_retry_later)?;
        auth_token = Some(new_token);
    }
    tx.commit().await.map_err(fatal_retry_later)?;

    let auth_token = auth_token.expect("auth token is set");
    tracing::debug!(
        handle = %handle,
        reused_token = %has_existing_token,
        "device auth accepted"
    );
    Ok(auth_token)
}

pub async fn device_list(handle: Handle) -> Result<Option<CertificateChain>, GatewayServerError> {
    let data = sqlx::query_scalar::<_, Vec<u8>>(
        "SELECT cert_chain FROM device_certificates WHERE handle = ?",
    )
    .bind(handle.as_str())
    .fetch_optional(&*DATABASE)
    .await
    .map_err(fatal_retry_later)?;
    let Some(data) = data else {
        return Ok(None);
    };
    let chain = bcs::from_bytes(&data).map_err(fatal_retry_later)?;
    Ok(Some(chain))
}
