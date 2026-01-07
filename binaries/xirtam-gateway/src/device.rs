use xirtam_structs::certificate::CertificateChain;
use xirtam_structs::gateway::GatewayServerError;
use xirtam_structs::handle::Handle;

use crate::database::DATABASE;
use crate::fatal_retry_later;

pub async fn device_auth(
    _handle: Handle,
    _cert: CertificateChain,
) -> Result<(), GatewayServerError> {
    Err(GatewayServerError::RetryLater)
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
