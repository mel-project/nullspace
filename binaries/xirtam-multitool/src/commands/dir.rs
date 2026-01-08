use clap::{Parser, Subcommand};
use serde::Serialize;
use xirtam_crypt::{
    hash::Hash,
    signing::{SigningPublic, SigningSecret},
};
use xirtam_structs::{
    gateway::{GatewayDescriptor, GatewayName},
    handle::{Handle, HandleDescriptor},
};

use crate::shared::{GlobalArgs, build_dir_client, print_json};

#[derive(Parser)]
pub struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    HandleQuery {
        handle: Handle,
    },
    HandleInsert {
        handle: Handle,
        gateway_name: GatewayName,
        #[arg(long)]
        roothash: Hash,
        #[arg(long)]
        secret_key: SigningSecret,
    },
    HandleAddOwner {
        handle: Handle,
        #[arg(long)]
        owner: SigningPublic,
        #[arg(long)]
        secret_key: SigningSecret,
    },
    HandleDelOwner {
        handle: Handle,
        #[arg(long)]
        owner: SigningPublic,
        #[arg(long)]
        secret_key: SigningSecret,
    },
    GatewayQuery {
        gateway_name: GatewayName,
    },
    GatewayInsert {
        gateway_name: GatewayName,
        #[arg(long = "public-url", required = true)]
        public_urls: Vec<url::Url>,
        #[arg(long = "gateway-pk")]
        gateway_pk: SigningPublic,
        #[arg(long)]
        secret_key: SigningSecret,
    },
    GatewayAddOwner {
        gateway_name: GatewayName,
        #[arg(long)]
        owner: SigningPublic,
        #[arg(long)]
        secret_key: SigningSecret,
    },
    GatewayDelOwner {
        gateway_name: GatewayName,
        #[arg(long)]
        owner: SigningPublic,
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
        Command::HandleQuery { handle } => {
            let descriptor = client.get_handle_descriptor(&handle).await?;
            let output = QueryOutput {
                found: descriptor.is_some(),
                descriptor,
            };
            print_json(&output)?;
        }
        Command::HandleInsert {
            handle,
            gateway_name,
            roothash,
            secret_key,
        } => {
            let descriptor = HandleDescriptor {
                gateway_name,
                root_cert_hash: roothash,
            };
            if let Some(existing) = client.get_handle_descriptor(&handle).await? {
                if existing == descriptor {
                    return Ok(());
                }
            }
            client
                .insert_handle_descriptor(&handle, &descriptor, &secret_key)
                .await?;
        }
        Command::HandleAddOwner {
            handle,
            owner,
            secret_key,
        } => {
            let listing = client.query_raw(handle.as_str()).await?;
            if listing.owners.contains(&owner) {
                return Ok(());
            }
            client.add_owner(&handle, owner, &secret_key).await?;
        }
        Command::HandleDelOwner {
            handle,
            owner,
            secret_key,
        } => {
            client.del_owner(&handle, owner, &secret_key).await?;
        }
        Command::GatewayQuery { gateway_name } => {
            let descriptor = client.get_gateway_descriptor(&gateway_name).await?;
            let output = QueryOutput {
                found: descriptor.is_some(),
                descriptor,
            };
            print_json(&output)?;
        }
        Command::GatewayInsert {
            gateway_name,
            public_urls,
            gateway_pk,
            secret_key,
        } => {
            let descriptor = GatewayDescriptor {
                public_urls,
                gateway_pk,
            };
            client
                .insert_gateway_descriptor(&gateway_name, &descriptor, &secret_key)
                .await?;
        }
        Command::GatewayAddOwner {
            gateway_name,
            owner,
            secret_key,
        } => {
            client
                .add_gateway_owner(&gateway_name, owner, &secret_key)
                .await?;
        }
        Command::GatewayDelOwner {
            gateway_name,
            owner,
            secret_key,
        } => {
            client
                .del_gateway_owner(&gateway_name, owner, &secret_key)
                .await?;
        }
    }
    Ok(())
}
