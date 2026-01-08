use std::str::FromStr;

use anyhow::Context;
use clap::Args;
use serde::Serialize;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use url::Url;
use xirtam_crypt::signing::SigningPublic;
use xirtam_dirclient::DirClient;
use xirtam_nanorpc::Transport;

#[derive(Args, Clone)]
pub struct GlobalArgs {
    #[arg(long, global = true)]
    pub endpoint: Option<Url>,
    #[arg(long, global = true)]
    pub public_key: Option<SigningPublic>,
    #[arg(long, global = true, default_value = ":memory:")]
    pub db_path: String,
}

pub fn print_json<T: Serialize>(value: &T) -> anyhow::Result<()> {
    let json = serde_json::to_string_pretty(value)?;
    print!("{json}");
    Ok(())
}

pub async fn build_dir_client(global: &GlobalArgs) -> anyhow::Result<DirClient> {
    let endpoint = global
        .endpoint
        .clone()
        .context("missing --endpoint for directory access")?;
    let anchor_pk = global
        .public_key
        .context("missing --public-key for directory access")?;
    let opts = SqliteConnectOptions::from_str(&global.db_path)?
        .create_if_missing(true)
        .shared_cache(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .min_connections(1)
        .connect_with(opts)
        .await?;
    let transport = Transport::new(endpoint);
    DirClient::new(transport, anchor_pk, pool).await
}
