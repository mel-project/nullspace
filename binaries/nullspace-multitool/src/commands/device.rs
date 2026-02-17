use std::path::{Path, PathBuf};

use anyhow::Context;
use bytes::Bytes;
use clap::{Parser, Subcommand};
use nullspace_crypt::signing::Signable;
use nullspace_rpc_pool::RpcPool;
use nullspace_structs::{
    Blob,
    certificate::DeviceSecret,
    server::{
        AuthToken, DeviceAuthRequest, MailboxId, MailboxRecvArgs, ServerClient,
        SignedDeviceAuthRequest,
    },
    timestamp::NanoTimestamp,
    username::UserName,
};
use serde::{Serialize, de::DeserializeOwned};
use url::Url;

use crate::shared::{GlobalArgs, build_dir_client, print_json};

#[derive(Parser)]
pub struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Auth {
        username: UserName,
        #[arg(long)]
        device_secret: PathBuf,
    },
    NewSecret {
        #[arg(long)]
        out: PathBuf,
    },
    MailboxSend {
        username: UserName,
        #[arg(long)]
        device_secret: PathBuf,
        message: String,
    },
    MailboxRecv {
        username: UserName,
        #[arg(long)]
        device_secret: PathBuf,
        #[arg(long, default_value_t = 30000)]
        timeout_ms: u64,
    },
}

#[derive(Serialize)]
struct AuthOutput {
    status: &'static str,
    auth_token: AuthToken,
}

pub async fn run(args: Args, global: &GlobalArgs) -> anyhow::Result<()> {
    let rpc_pool = RpcPool::new();
    match args.command {
        Command::Auth {
            username,
            device_secret,
        } => {
            let device_secret = read_bcs::<DeviceSecret>(&device_secret)?;
            let endpoint = resolve_server_endpoint(global, &username).await?;
            let client = ServerClient::from(rpc_pool.rpc(endpoint));
            let auth_token = authenticate(&client, &username, &device_secret).await?;
            let output = AuthOutput {
                status: "ok",
                auth_token,
            };
            print_json(&output)?;
        }
        Command::NewSecret { out } => {
            let secret = DeviceSecret::random();
            write_secret_file(&out, &secret)?;
        }
        Command::MailboxSend {
            username,
            device_secret,
            message,
        } => {
            let endpoint = resolve_server_endpoint(global, &username).await?;
            let client = ServerClient::from(rpc_pool.rpc(endpoint));
            let device_secret = read_bcs::<DeviceSecret>(&device_secret)?;
            let auth = authenticate(&client, &username, &device_secret).await?;
            let mailbox = MailboxId::direct(&username);
            let msg = Blob {
                kind: Blob::V1_PLAINTEXT_DIRECT_MESSAGE.into(),
                inner: Bytes::from(message.into_bytes()),
            };
            client
                .v1_mailbox_send(auth, mailbox, msg, 0)
                .await?
                .map_err(|err| anyhow::anyhow!(err.to_string()))?;
        }
        Command::MailboxRecv {
            username,
            device_secret,
            timeout_ms,
        } => {
            let endpoint = resolve_server_endpoint(global, &username).await?;
            let client = ServerClient::from(rpc_pool.rpc(endpoint));
            let device_secret = read_bcs::<DeviceSecret>(&device_secret)?;
            let auth = authenticate(&client, &username, &device_secret).await?;
            let mailbox = MailboxId::direct(&username);
            let mut after = NanoTimestamp(0);
            loop {
                let args = vec![MailboxRecvArgs {
                    auth,
                    mailbox,
                    after,
                }];
                let response = client
                    .v1_mailbox_multirecv(args, timeout_ms)
                    .await?
                    .map_err(|err| anyhow::anyhow!(err.to_string()))?;
                let entries = response.get(&mailbox).cloned().unwrap_or_default();
                if entries.is_empty() {
                    continue;
                }
                for entry in entries {
                    after = entry.received_at;
                    print_json_line(&entry)?;
                }
            }
        }
    }
    Ok(())
}

async fn authenticate(
    client: &ServerClient,
    username: &UserName,
    device_secret: &DeviceSecret,
) -> anyhow::Result<AuthToken> {
    let device_pk = device_secret.public().signing_public();
    let challenge = client
        .v1_device_auth_start(username.clone(), device_pk)
        .await?
        .map_err(|err| anyhow::anyhow!(err.to_string()))?;
    let mut request = SignedDeviceAuthRequest {
        request: DeviceAuthRequest {
            username: username.clone(),
            device_pk,
            challenge: challenge.challenge,
        },
        signature: nullspace_crypt::signing::Signature::from_bytes([0u8; 64]),
    };
    request.sign(device_secret);
    client
        .v1_device_auth_finish(request)
        .await?
        .map_err(|err| anyhow::anyhow!(err.to_string()))
}

async fn resolve_server_endpoint(global: &GlobalArgs, username: &UserName) -> anyhow::Result<Url> {
    let client = build_dir_client(global).await?;
    let descriptor = client
        .get_user_descriptor(username)
        .await?
        .with_context(|| format!("username not found: {}", username.as_str()))?;
    let server = client
        .get_server_descriptor(&descriptor.server_name)
        .await?
        .with_context(|| format!("server not found: {}", descriptor.server_name.as_str()))?;
    let url = server
        .public_urls
        .first()
        .cloned()
        .context("server has no public URLs")?;
    Ok(url)
}

fn read_bcs<T: DeserializeOwned>(path: &Path) -> anyhow::Result<T> {
    let data = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let value = bcs::from_bytes(&data).with_context(|| format!("decode BCS {}", path.display()))?;
    Ok(value)
}

fn write_bcs<T: Serialize>(path: &Path, value: &T) -> anyhow::Result<()> {
    let data = bcs::to_bytes(value).context("serialize BCS value")?;
    std::fs::write(path, data).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

fn write_secret_file(path: &Path, secret: &DeviceSecret) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    write_bcs(path, secret)?;
    let perms = std::fs::Permissions::from_mode(0o600);
    std::fs::set_permissions(path, perms)
        .with_context(|| format!("chmod secret {}", path.display()))?;
    Ok(())
}

fn print_json_line<T: Serialize>(value: &T) -> anyhow::Result<()> {
    let json = serde_json::to_string(value)?;
    println!("{json}");
    Ok(())
}
