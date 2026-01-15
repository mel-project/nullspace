mod config;
mod database;
mod device;
mod dir_client;
mod mailbox;
mod rpc;

use std::fmt::Display;
use std::future::Future;
use std::pin::Pin;

use axum::{Router, routing::post};
use futures_concurrency::future::Race;
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;
use xirtam_structs::server::{ServerError, ServerService};

use crate::config::CONFIG;
use crate::rpc::ServerRpc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("xirtam_server=debug"));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    dir_client::init_name().await?;
    let app = Router::new().route("/", post(rpc::rpc_handler));
    let listener = TcpListener::bind(CONFIG.listen).await?;
    let mut servers: Vec<Pin<Box<dyn Future<Output = anyhow::Result<()>>>>> = Vec::new();

    servers.push(Box::pin(async move {
        axum::serve(listener, app).await.map_err(anyhow::Error::from)
    }));

    if let Some(tcp_listen) = CONFIG.tcp_listen {
        let service = ServerService(ServerRpc);
        servers.push(Box::pin(async move {
            xirtam_nanorpc::serve_tcp(tcp_listen, service).await
        }));
    }

    if let Some(lz4_listen) = CONFIG.lz4_listen {
        let service = ServerService(ServerRpc);
        servers.push(Box::pin(async move {
            xirtam_nanorpc::serve_lz4tcp(lz4_listen, service).await
        }));
    }

    if servers.len() == 1 {
        servers.pop().unwrap().await?;
    } else {
        servers.race().await?;
    }
    Ok(())
}

fn fatal_retry_later(e: impl Display) -> ServerError {
    tracing::error!("fatal error: {e}");
    ServerError::RetryLater
}
