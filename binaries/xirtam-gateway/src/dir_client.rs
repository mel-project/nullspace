use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::LazyLock;

use anyhow::Context;
use rand::RngCore;
use xirtam_crypt::signing::SigningSecret;
use xirtam_dirclient::DirClient;
use xirtam_nanorpc::Transport;
use xirtam_structs::gateway::GatewayDescriptor;

use crate::config::CONFIG;
use crate::database::DATABASE;

pub static DIR_CLIENT: LazyLock<DirClient> = LazyLock::new(|| {
    let transport = Transport::new(CONFIG.directory_url.clone());
    tokio::runtime::Handle::current()
        .block_on(DirClient::new(transport, CONFIG.directory_pk, DATABASE.clone()))
        .expect("failed to initialize directory client")
});

pub async fn init_name() -> anyhow::Result<()> {
    let signing_sk = load_signing_secret(&CONFIG.signing_sk)?;
    let gateway_pk = signing_sk.public_key();
    let descriptor = GatewayDescriptor {
        public_urls: CONFIG.public_urls.clone(),
        gateway_pk,
    };

    let client = &*DIR_CLIENT;

    if let Some(existing) = client
        .get_gateway_descriptor(&CONFIG.gateway_name)
        .await?
    {
        if existing != descriptor {
            anyhow::bail!(
                "gateway descriptor mismatch for {}",
                CONFIG.gateway_name.as_str()
            );
        }
        return Ok(());
    }

    client
        .add_gateway_owner(&CONFIG.gateway_name, gateway_pk, &signing_sk)
        .await?;
    client
        .insert_gateway_descriptor(&CONFIG.gateway_name, &descriptor, &signing_sk)
        .await?;
    Ok(())
}

fn load_signing_secret(path: &PathBuf) -> anyhow::Result<SigningSecret> {
    if !path.exists() {
        let mut bytes = [0u8; 32];
        rand::rng().fill_bytes(&mut bytes);
        std::fs::write(path, &bytes)
            .with_context(|| format!("write secret key {}", path.display()))?;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(path, perms)
            .with_context(|| format!("chmod secret key {}", path.display()))?;
    }
    let data =
        std::fs::read(path).with_context(|| format!("read secret key {}", path.display()))?;
    if data.len() != 32 {
        anyhow::bail!("secret key must be exactly 32 raw bytes")
    }
    let bytes: [u8; 32] = data.try_into().unwrap();
    Ok(SigningSecret::from_bytes(bytes))
}
