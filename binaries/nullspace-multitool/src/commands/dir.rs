use clap::{Parser, Subcommand};
use serde::Serialize;
use nullspace_crypt::{
    signing::{SigningPublic, SigningSecret},
};
use nullspace_structs::{
    server::{ServerDescriptor, ServerName},
    timestamp::{NanoTimestamp, Timestamp},
    username::UserName,
};

use crate::shared::{GlobalArgs, build_dir_client, print_json};

#[derive(Parser)]
pub struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    UsernameQuery {
        username: UserName,
    },
    UsernameBootstrap {
        username: UserName,
        server_name: ServerName,
        #[arg(long)]
        secret_key: SigningSecret,
        #[arg(long, default_value_t = true)]
        can_issue: bool,
        #[arg(long, default_value_t = u64::MAX)]
        expiry: u64,
        #[arg(long)]
        nonce_base: Option<u64>,
    },
    UsernameAddDevice {
        username: UserName,
        #[arg(long)]
        device_pk: SigningPublic,
        #[arg(long)]
        secret_key: SigningSecret,
        #[arg(long, default_value_t = true)]
        can_issue: bool,
        #[arg(long, default_value_t = u64::MAX)]
        expiry: u64,
        #[arg(long)]
        nonce: Option<u64>,
    },
    UsernameRemoveDevice {
        username: UserName,
        #[arg(long)]
        device_pk: SigningPublic,
        #[arg(long)]
        secret_key: SigningSecret,
        #[arg(long)]
        nonce: Option<u64>,
    },
    UsernameBindServer {
        username: UserName,
        server_name: ServerName,
        #[arg(long)]
        secret_key: SigningSecret,
        #[arg(long)]
        nonce: Option<u64>,
    },
    ServerQuery {
        server_name: ServerName,
    },
    ServerInsert {
        server_name: ServerName,
        #[arg(long = "public-url", required = true)]
        public_urls: Vec<url::Url>,
        #[arg(long = "server-pk")]
        server_pk: SigningPublic,
        #[arg(long)]
        secret_key: SigningSecret,
    },
}

#[derive(Serialize)]
struct QueryOutput<T> {
    found: bool,
    descriptor: Option<T>,
}

pub async fn run(args: Args, global: &GlobalArgs) -> anyhow::Result<()> {
    let client = build_dir_client(global).await?;
    match args.command {
        Command::UsernameQuery { username } => {
            let descriptor = client.get_user_descriptor(&username).await?;
            let output = QueryOutput {
                found: descriptor.is_some(),
                descriptor,
            };
            print_json(&output)?;
        }
        Command::UsernameBootstrap {
            username,
            server_name,
            secret_key,
            can_issue,
            expiry,
            nonce_base,
        } => {
            let base = nonce_base.unwrap_or_else(|| NanoTimestamp::now().0);
            client
                .add_device(
                    &username,
                    secret_key.public_key(),
                    can_issue,
                    Timestamp(expiry),
                    base,
                    &secret_key,
                )
                .await?;
            client
                .bind_server(
                    &username,
                    &server_name,
                    base.saturating_add(1),
                    &secret_key,
                )
                .await?;
        }
        Command::UsernameAddDevice {
            username,
            device_pk,
            secret_key,
            can_issue,
            expiry,
            nonce,
        } => {
            let nonce = nonce.unwrap_or_else(|| NanoTimestamp::now().0);
            client
                .add_device(
                    &username,
                    device_pk,
                    can_issue,
                    Timestamp(expiry),
                    nonce,
                    &secret_key,
                )
                .await?;
        }
        Command::UsernameRemoveDevice {
            username,
            device_pk,
            secret_key,
            nonce,
        } => {
            let nonce = nonce.unwrap_or_else(|| NanoTimestamp::now().0);
            client
                .remove_device(&username, device_pk, nonce, &secret_key)
                .await?;
        }
        Command::UsernameBindServer {
            username,
            server_name,
            secret_key,
            nonce,
        } => {
            let nonce = nonce.unwrap_or_else(|| NanoTimestamp::now().0);
            client
                .bind_server(&username, &server_name, nonce, &secret_key)
                .await?;
        }
        Command::ServerQuery { server_name } => {
            let descriptor = client.get_server_descriptor(&server_name).await?;
            let output = QueryOutput {
                found: descriptor.is_some(),
                descriptor,
            };
            print_json(&output)?;
        }
        Command::ServerInsert {
            server_name,
            public_urls,
            server_pk,
            secret_key,
        } => {
            let descriptor = ServerDescriptor {
                public_urls,
                server_pk,
            };
            client
                .set_server_descriptor(&server_name, &descriptor, &secret_key)
                .await?;
        }
    }
    Ok(())
}
