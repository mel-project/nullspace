use std::path::{Path, PathBuf};

use anyhow::Context;
use bytes::Bytes;
use clap::{Parser, Subcommand};
use serde::{Serialize, de::DeserializeOwned};
use url::Url;
use xirtam_crypt::hash::BcsHashExt;
use xirtam_nanorpc::Transport;
use xirtam_structs::{
    Blob,
    certificate::{CertificateChain, DeviceCertificate, DeviceSecret},
    gateway::{AuthToken, GatewayClient, MailboxId, MailboxRecvArgs},
    handle::Handle,
    timestamp::{NanoTimestamp, Timestamp},
};

use crate::shared::{GlobalArgs, build_dir_client, print_json};

#[derive(Parser)]
pub struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    List {
        handle: Handle,
    },
    Auth {
        handle: Handle,
        #[arg(long)]
        chain: PathBuf,
    },
    NewSecret {
        #[arg(long)]
        out: PathBuf,
    },
    ChainInit {
        #[arg(long)]
        root_secret: PathBuf,
        #[arg(long)]
        ttl_secs: Option<u64>,
        #[arg(long)]
        leaf: bool,
        #[arg(long)]
        out: PathBuf,
    },
    ChainIssue {
        #[arg(long)]
        chain: PathBuf,
        #[arg(long)]
        issuer_secret: PathBuf,
        #[arg(long)]
        subject_secret: PathBuf,
        #[arg(long)]
        ttl_secs: Option<u64>,
        #[arg(long)]
        leaf: bool,
        #[arg(long)]
        out: PathBuf,
    },
    ChainDump {
        #[arg(long)]
        chain: PathBuf,
    },
    MailboxSend {
        handle: Handle,
        #[arg(long)]
        chain: PathBuf,
        message: String,
    },
    MailboxRecv {
        handle: Handle,
        #[arg(long)]
        chain: PathBuf,
        #[arg(long, default_value_t = 30000)]
        timeout_ms: u64,
    },
}

#[derive(Serialize)]
struct ChainListOutput {
    found: bool,
    chain: Option<CertificateChain>,
}

#[derive(Serialize)]
struct AuthOutput {
    status: &'static str,
    auth_token: AuthToken,
}

#[derive(Serialize)]
struct ChainDumpEntry {
    cert: DeviceCertificate,
    pk_hash: xirtam_crypt::hash::Hash,
}

pub async fn run(args: Args, global: &GlobalArgs) -> anyhow::Result<()> {
    match args.command {
        Command::List { handle } => {
            let endpoint = resolve_gateway_endpoint(global, &handle).await?;
            let client = GatewayClient::from(Transport::new(endpoint));
            let chain = client
                .v1_device_certs(handle)
                .await?
                .map_err(|err| anyhow::anyhow!(err.to_string()))?;
            let output = ChainListOutput {
                found: chain.is_some(),
                chain,
            };
            print_json(&output)?;
        }
        Command::Auth { handle, chain } => {
            let chain = read_bcs::<CertificateChain>(&chain)?;
            let endpoint = resolve_gateway_endpoint(global, &handle).await?;
            let client = GatewayClient::from(Transport::new(endpoint));
            let auth_token = client
                .v1_device_auth(handle, chain)
                .await?
                .map_err(|err| anyhow::anyhow!(err.to_string()))?;
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
        Command::ChainInit {
            root_secret,
            ttl_secs,
            leaf,
            out,
        } => {
            let root_secret = read_bcs::<DeviceSecret>(&root_secret)?;
            let expiry = expiry_from_ttl(ttl_secs);
            let cert = root_secret.self_signed(expiry, !leaf);
            let chain = CertificateChain(vec![cert]);
            write_bcs(&out, &chain)?;
        }
        Command::ChainIssue {
            chain,
            issuer_secret,
            subject_secret,
            ttl_secs,
            leaf,
            out,
        } => {
            let mut chain = read_bcs::<CertificateChain>(&chain)?;
            let issuer_secret = read_bcs::<DeviceSecret>(&issuer_secret)?;
            let subject_secret = read_bcs::<DeviceSecret>(&subject_secret)?;
            let expiry = expiry_from_ttl(ttl_secs);
            let cert = issuer_secret.issue_certificate(&subject_secret.public(), expiry, !leaf);
            chain.0.push(cert);
            write_bcs(&out, &chain)?;
        }
        Command::ChainDump { chain } => {
            let chain = read_bcs::<CertificateChain>(&chain)?;
            let dump: Vec<ChainDumpEntry> = chain
                .0
                .into_iter()
                .map(|cert| ChainDumpEntry {
                    pk_hash: cert.pk.bcs_hash(),
                    cert,
                })
                .collect();
            print_json(&dump)?;
        }
        Command::MailboxSend {
            handle,
            chain,
            message,
        } => {
            let endpoint = resolve_gateway_endpoint(global, &handle).await?;
            let client = GatewayClient::from(Transport::new(endpoint));
            let chain = read_bcs::<CertificateChain>(&chain)?;
            let auth = client
                .v1_device_auth(handle.clone(), chain)
                .await?
                .map_err(|err| anyhow::anyhow!(err.to_string()))?;
            let mailbox = MailboxId::direct(&handle);
            let msg = Blob {
                kind: Blob::V1_PLAINTEXT_DIRECT_MESSAGE.into(),
                inner: Bytes::from(message.into_bytes()),
            };
            client
                .v1_mailbox_send(auth, mailbox, msg)
                .await?
                .map_err(|err| anyhow::anyhow!(err.to_string()))?;
        }
        Command::MailboxRecv {
            handle,
            chain,
            timeout_ms,
        } => {
            let endpoint = resolve_gateway_endpoint(global, &handle).await?;
            let client = GatewayClient::from(Transport::new(endpoint));
            let chain = read_bcs::<CertificateChain>(&chain)?;
            let auth = client
                .v1_device_auth(handle.clone(), chain)
                .await?
                .map_err(|err| anyhow::anyhow!(err.to_string()))?;
            let mailbox = MailboxId::direct(&handle);
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

async fn resolve_gateway_endpoint(global: &GlobalArgs, handle: &Handle) -> anyhow::Result<Url> {
    let client = build_dir_client(global).await?;
    let descriptor = client
        .get_handle_descriptor(handle)
        .await?
        .with_context(|| format!("handle not found: {}", handle.as_str()))?;
    let gateway_name = descriptor.gateway_name;
    let gateway = client
        .get_gateway_descriptor(&gateway_name)
        .await?
        .with_context(|| format!("gateway not found: {}", gateway_name.as_str()))?;
    let url = gateway
        .public_urls
        .first()
        .cloned()
        .context("gateway has no public URLs")?;
    Ok(url)
}

fn expiry_from_ttl(ttl_secs: Option<u64>) -> Timestamp {
    match ttl_secs {
        Some(ttl) => {
            let now = Timestamp::now().0;
            Timestamp(now.saturating_add(ttl))
        }
        None => Timestamp(u64::MAX),
    }
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
