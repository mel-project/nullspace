use anyhow::Context;
use sqlx::SqlitePool;

use xirtam_crypt::dh::DhSecret;
use xirtam_structs::certificate::{CertificateChain, DeviceSecret};
use xirtam_structs::gateway::GatewayName;
use xirtam_structs::handle::Handle;

#[derive(Clone)]
pub struct Identity {
    pub handle: Handle,
    pub gateway_name: Option<GatewayName>,
    pub device_secret: DeviceSecret,
    pub cert_chain: CertificateChain,
    pub medium_sk_current: DhSecret,
    pub medium_sk_prev: DhSecret,
}

impl Identity {
    pub async fn load(db: &SqlitePool) -> anyhow::Result<Self> {
        let row =
            sqlx::query_as::<_, (String, Option<String>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)>(
                "SELECT handle, gateway_name, device_secret, cert_chain, medium_sk_current, medium_sk_prev \
                 FROM client_identity WHERE id = 1",
            )
            .fetch_optional(db)
            .await?;
        let Some((handle, gateway_name, device_secret, cert_chain, medium_sk_current, medium_sk_prev)) = row else {
            anyhow::bail!("client identity not initialized");
        };
        let handle = Handle::parse(handle).context("invalid stored handle")?;
        let gateway_name = match gateway_name {
            Some(name) => Some(GatewayName::parse(name).context("invalid stored gateway name")?),
            None => None,
        };
        let device_secret: DeviceSecret = bcs::from_bytes(&device_secret)?;
        let cert_chain: CertificateChain = bcs::from_bytes(&cert_chain)?;
        let medium_sk_current: DhSecret = bcs::from_bytes(&medium_sk_current)?;
        let medium_sk_prev: DhSecret = bcs::from_bytes(&medium_sk_prev)?;
        Ok(Self {
            handle,
            gateway_name,
            device_secret,
            cert_chain,
            medium_sk_current,
            medium_sk_prev,
        })
    }

}

pub async fn store_gateway_name(db: &SqlitePool, gateway_name: &GatewayName) -> anyhow::Result<()> {
    sqlx::query("UPDATE client_identity SET gateway_name = ? WHERE id = 1")
        .bind(gateway_name.as_str())
        .execute(db)
        .await?;
    Ok(())
}
