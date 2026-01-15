use clap::{Parser, Subcommand};
use serde::Serialize;
use xirtam_crypt::{
    hash::Hash,
    signing::{SigningPublic, SigningSecret},
};
use xirtam_structs::{
    server::{ServerDescriptor, ServerName},
    username::{UserDescriptor, UserName},
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
    UsernameInsert {
        username: UserName,
        server_name: ServerName,
        #[arg(long)]
        roothash: Hash,
        #[arg(long)]
        secret_key: SigningSecret,
    },
    UsernameAddOwner {
        username: UserName,
        #[arg(long)]
        owner: SigningPublic,
        #[arg(long)]
        secret_key: SigningSecret,
    },
    UsernameDelOwner {
        username: UserName,
        #[arg(long)]
        owner: SigningPublic,
        #[arg(long)]
        secret_key: SigningSecret,
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
    ServerAddOwner {
        server_name: ServerName,
        #[arg(long)]
        owner: SigningPublic,
        #[arg(long)]
        secret_key: SigningSecret,
    },
    ServerDelOwner {
        server_name: ServerName,
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
        Command::UsernameQuery { username } => {
            let descriptor = client.get_user_descriptor(&username).await?;
            let output = QueryOutput {
                found: descriptor.is_some(),
                descriptor,
            };
            print_json(&output)?;
        }
        Command::UsernameInsert {
            username,
            server_name,
            roothash,
            secret_key,
        } => {
            let descriptor = UserDescriptor {
                server_name,
                root_cert_hash: roothash,
            };
            if let Some(existing) = client.get_user_descriptor(&username).await?
                && existing == descriptor {
                    return Ok(());
                }
            client
                .insert_user_descriptor(&username, &descriptor, &secret_key)
                .await?;
        }
        Command::UsernameAddOwner {
            username,
            owner,
            secret_key,
        } => {
            let listing = client.query_raw(username.as_str()).await?;
            if listing.owners.contains(&owner) {
                return Ok(());
            }
            client.add_owner(&username, owner, &secret_key).await?;
        }
        Command::UsernameDelOwner {
            username,
            owner,
            secret_key,
        } => {
            client.del_owner(&username, owner, &secret_key).await?;
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
                .insert_server_descriptor(&server_name, &descriptor, &secret_key)
                .await?;
        }
        Command::ServerAddOwner {
            server_name,
            owner,
            secret_key,
        } => {
            client
                .add_server_owner(&server_name, owner, &secret_key)
                .await?;
        }
        Command::ServerDelOwner {
            server_name,
            owner,
            secret_key,
        } => {
            client
                .del_server_owner(&server_name, owner, &secret_key)
                .await?;
        }
    }
    Ok(())
}
