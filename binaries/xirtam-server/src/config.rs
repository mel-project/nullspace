use std::{fs, net::SocketAddr, path::PathBuf, sync::LazyLock};

use clap::Parser;
use serde::Deserialize;
use url::Url;
use xirtam_crypt::signing::SigningPublic;
use xirtam_structs::server::ServerName;

#[derive(Parser, Debug)]
#[command(name = "xirtam-server")]
struct Args {
    #[arg(long)]
    config: PathBuf,
}

#[derive(Debug, Deserialize)]
pub struct Config {
    pub listen: SocketAddr,
    pub tcp_listen: Option<SocketAddr>,
    pub lz4_listen: Option<SocketAddr>,
    pub db_path: String,
    pub signing_sk: PathBuf,
    pub server_name: ServerName,
    pub public_urls: Vec<Url>,
    pub directory_url: Url,
    pub directory_pk: SigningPublic,
}

pub static CONFIG: LazyLock<Config> = LazyLock::new(|| {
    let args = Args::parse();
    let raw = fs::read_to_string(&args.config).unwrap_or_else(|err| {
        panic!("failed to read config {}: {err}", args.config.display());
    });
    toml::from_str(&raw).unwrap_or_else(|err| {
        panic!("failed to parse config {}: {err}", args.config.display());
    })
});
