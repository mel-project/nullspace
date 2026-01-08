use async_trait::async_trait;
use nanorpc::{JrpcRequest, JrpcResponse, RpcTransport};
use url::Url;

mod http;
mod tcp;

pub(crate) const REQUEST_TIMEOUT_SECS: u64 = 600;

pub use tcp::serve_tcp;

#[derive(Clone)]
pub struct Transport {
    inner: TransportInner,
}

impl Transport {
    pub fn new(endpoint: Url) -> Self {
        match endpoint.scheme() {
            "http" | "https" => Self {
                inner: TransportInner::Http(http::HttpTransport::new(endpoint)),
            },
            "tcp" => Self {
                inner: TransportInner::Tcp(tcp::RawTcpClient::new(endpoint)),
            },
            scheme => panic!("unsupported RPC endpoint scheme: {scheme}"),
        }
    }
}

#[async_trait]
impl RpcTransport for Transport {
    type Error = anyhow::Error;

    async fn call_raw(&self, req: JrpcRequest) -> Result<JrpcResponse, Self::Error> {
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
