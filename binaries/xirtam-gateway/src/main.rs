mod config;
mod database;
mod dir_client;
mod rpc;

use axum::{Router, routing::post};
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

use crate::config::CONFIG;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("xirtam_gateway=debug"));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    dir_client::init_name().await?;
    let app = Router::new().route("/", post(rpc::handle_rpc));
    let listener = TcpListener::bind(CONFIG.listen).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
