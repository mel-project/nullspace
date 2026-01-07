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
    if cert.0.is_empty() {
        return Err(GatewayServerError::AccessDenied);
    }

    let descriptor = DIR_CLIENT
        .get_handle_descriptor(&handle)
        .await
        .map_err(fatal_retry_later)?;
    let Some(descriptor) = descriptor else {
        return Err(GatewayServerError::AccessDenied);
    };
    if descriptor.gateway_name != CONFIG.gateway_name {
        return Err(GatewayServerError::AccessDenied);
    }

    if cert.verify(descriptor.root_cert_hash).is_err() {
        return Err(GatewayServerError::AccessDenied);
    }

    let mut tx = DATABASE.begin().await.map_err(fatal_retry_later)?;
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
        return Err(GatewayServerError::AccessDenied);
    }
    let data = bcs::to_bytes(&merged).map_err(fatal_retry_later)?;
    sqlx::query("INSERT OR REPLACE INTO device_certificates (handle, cert_chain) VALUES (?, ?)")
        .bind(handle.as_str())
        .bind(data)
        .execute(&mut *tx)
        .await
        .map_err(fatal_retry_later)?;
    tx.commit().await.map_err(fatal_retry_later)?;

    Ok(AuthToken::random())
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
