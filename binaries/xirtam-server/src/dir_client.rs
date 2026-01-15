use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::LazyLock;

use anyhow::Context;
use rand::RngCore;
use xirtam_crypt::signing::SigningSecret;
use xirtam_dirclient::DirClient;
use xirtam_nanorpc::Transport;
use xirtam_structs::server::ServerDescriptor;

use crate::config::CONFIG;
use crate::database::DATABASE;

pub static DIR_CLIENT: LazyLock<DirClient> = LazyLock::new(|| {
    let transport = Transport::new(CONFIG.directory_url.clone());
    pollster::block_on(DirClient::new(
        transport,
        CONFIG.directory_pk,
        DATABASE.clone(),
    ))
    .expect("failed to initialize directory client")
});

pub async fn init_name() -> anyhow::Result<()> {
    let signing_sk = load_signing_secret(&CONFIG.signing_sk)?;
    let server_pk = signing_sk.public_key();
    let descriptor = ServerDescriptor {
        public_urls: CONFIG.public_urls.clone(),
        server_pk,
    };

    let client = &*DIR_CLIENT;

    if let Some(existing) = client.get_server_descriptor(&CONFIG.server_name).await? {
        if existing != descriptor {
            anyhow::bail!(
                "server descriptor mismatch for {}",
                CONFIG.server_name.as_str()
            );
        }
    } else {
        tracing::info!("registering name step 1: adding server owner...");
        client
            .add_server_owner(&CONFIG.server_name, server_pk, &signing_sk)
            .await?;
        tracing::info!("registering name step 1: inserting server descriptor...");
        client
            .insert_server_descriptor(&CONFIG.server_name, &descriptor, &signing_sk)
            .await?;
        tracing::info!(
            "registering name step 1: done! Registered {}",
            CONFIG.server_name
        );
    }
    tracing::info!("validated server name {}", CONFIG.server_name);
    Ok(())
}

fn load_signing_secret(path: &PathBuf) -> anyhow::Result<SigningSecret> {
    if !path.exists() {
        let mut bytes = [0u8; 32];
        rand::rng().fill_bytes(&mut bytes);
        std::fs::write(path, bytes)
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
