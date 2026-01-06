use std::{net::SocketAddr, path::PathBuf};

use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "xirtam-directory")]
pub struct Args {
    #[arg(long)]
    pub listen: SocketAddr,
    #[arg(long)]
    pub db_path: PathBuf,
    #[arg(long, conflicts_with = "mirror", required_unless_present = "mirror")]
    pub secret_key: Option<PathBuf>,
    #[arg(long, value_name = "URL")]
    pub mirror: Option<String>,
}
