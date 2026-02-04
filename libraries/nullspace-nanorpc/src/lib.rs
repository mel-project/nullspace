use std::{
    sync::{Arc, atomic::AtomicU64},
    time::Instant,
};

use async_trait::async_trait;
use nanorpc::{JrpcRequest, JrpcResponse, RpcTransport};
use url::Url;

mod http;
mod tcp;

pub(crate) const REQUEST_TIMEOUT_SECS: u64 = 600;
pub(crate) const MAX_MESSAGE_BYTES: usize = 1024 * 1024;

pub use tcp::{serve_lz4tcp, serve_tcp};

#[derive(Clone)]
pub struct Transport {
    endpoint: Url,
    inner: TransportInner,
    inflight: Arc<AtomicU64>,
}

impl Transport {
    pub fn new(endpoint: Url) -> Self {
        match endpoint.scheme() {
            "http" | "https" => Self {
                endpoint: endpoint.clone(),
                inner: TransportInner::Http(http::HttpTransport::new(endpoint)),
                inflight: Default::default(),
            },
            "tcp" => Self {
                endpoint: endpoint.clone(),
                inner: TransportInner::Tcp(tcp::RawTcpClient::new(endpoint)),
                inflight: Default::default(),
            },
            "lz4tcp" => Self {
                endpoint: endpoint.clone(),
                inner: TransportInner::Tcp(tcp::RawTcpClient::new_lz4(endpoint)),
                inflight: Default::default(),
            },
            scheme => panic!("unsupported RPC endpoint scheme: {scheme}"),
        }
    }
}

#[async_trait]
impl RpcTransport for Transport {
    type Error = anyhow::Error;

    async fn call_raw(&self, req: JrpcRequest) -> Result<JrpcResponse, Self::Error> {
        let inflight = self
            .inflight
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let method = req.method.clone();
        let start = Instant::now();
        scopeguard::defer!({
            tracing::debug!(
                endpoint = display(&self.endpoint),
                method,
                inflight,
                elapsed = debug(start.elapsed()),
                "called an RPC endpoint"
            );
            self.inflight
                .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        });
        match &self.inner {
            TransportInner::Http(http) => http.call_raw(req).await,
            TransportInner::Tcp(tcp) => tcp.call_raw(req).await,
        }
    }
}

#[derive(Clone)]
enum TransportInner {
    Http(http::HttpTransport),
    Tcp(tcp::RawTcpClient),
}
