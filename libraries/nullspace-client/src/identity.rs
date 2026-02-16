use anyhow::Context;
use sqlx::SqlitePool;

use nullspace_crypt::dh::DhSecret;
use nullspace_structs::certificate::DeviceSecret;
use nullspace_structs::server::ServerName;
use nullspace_structs::username::UserName;

#[derive(Clone)]
pub struct Identity {
    pub username: UserName,
    pub server_name: Option<ServerName>,
    pub device_secret: DeviceSecret,
    pub medium_sk_current: DhSecret,
    pub medium_sk_prev: DhSecret,
}

impl Identity {
    pub async fn load(db: &SqlitePool) -> anyhow::Result<Self> {
        let row = sqlx::query_as::<_, (String, Option<String>, Vec<u8>, Vec<u8>, Vec<u8>)>(
            "SELECT username, server_name, device_secret, medium_sk_current, medium_sk_prev \
                 FROM client_identity WHERE id = 1",
        )
        .fetch_optional(db)
        .await?;
        let Some((username, server_name, device_secret, medium_sk_current, medium_sk_prev)) = row
        else {
            anyhow::bail!("client identity not initialized");
        };
        let username = UserName::parse(username).context("invalid stored username")?;
        let server_name = match server_name {
            Some(name) => Some(ServerName::parse(name).context("invalid stored server name")?),
            None => None,
        };
        let device_secret: DeviceSecret = bcs::from_bytes(&device_secret)?;
        let medium_sk_current: DhSecret = bcs::from_bytes(&medium_sk_current)?;
        let medium_sk_prev: DhSecret = bcs::from_bytes(&medium_sk_prev)?;
        Ok(Self {
            username,
            server_name,
            device_secret,
            medium_sk_current,
            medium_sk_prev,
        })
    }
}

pub async fn store_server_name(db: &SqlitePool, server_name: &ServerName) -> anyhow::Result<()> {
    sqlx::query("UPDATE client_identity SET server_name = ? WHERE id = 1")
        .bind(server_name.as_str())
        .execute(db)
        .await?;
    Ok(())
}
