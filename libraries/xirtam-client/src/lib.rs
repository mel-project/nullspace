mod c_api;
mod config;
mod database;
mod directory;
mod dm;
mod server;
mod groups;
mod identity;
pub mod internal;
mod long_poll;
mod main_loop;
mod medium_keys;
mod peer;

use std::sync::mpsc::Sender;

use nanorpc::{DynRpcTransport, JrpcRequest, JrpcResponse, RpcTransport};
use tokio::sync::oneshot;
use tokio::time::{Duration, timeout};

pub use crate::config::Config;
pub use crate::internal::InternalClient;

pub struct Client {
    send_rpc: Sender<(JrpcRequest, oneshot::Sender<JrpcResponse>)>,
}

impl Client {
    pub fn new(config: Config) -> Self {
        let (send_rpc, recv_rpc) = std::sync::mpsc::channel();
        tokio::task::spawn(main_loop::main_loop(config, recv_rpc));
        Self { send_rpc }
    }

    pub fn rpc(&self) -> InternalClient {
        let transport = DynRpcTransport::new(InternalTransport {
            send_rpc: self.send_rpc.clone(),
        });
        InternalClient::from(transport)
    }

    pub(crate) fn send_rpc_raw(
        &self,
        req: JrpcRequest,
    ) -> Result<oneshot::Receiver<JrpcResponse>, anyhow::Error> {
        let (resp_tx, resp_rx) = oneshot::channel();
        self.send_rpc
            .send((req, resp_tx))
            .map_err(|_| anyhow::anyhow!("internal RPC channel closed"))?;
        Ok(resp_rx)
    }
}

#[derive(Clone)]
struct InternalTransport {
    send_rpc: Sender<(JrpcRequest, oneshot::Sender<JrpcResponse>)>,
}

#[async_trait::async_trait]
impl RpcTransport for InternalTransport {
    type Error = anyhow::Error;

    async fn call_raw(&self, req: JrpcRequest) -> Result<JrpcResponse, Self::Error> {
        let (resp_tx, resp_rx) = oneshot::channel();
        let req_debug = format!("{req:?}");
        let skip_timeout = req.method == "next_event";
        self.send_rpc
            .send((req, resp_tx))
            .map_err(|_| anyhow::anyhow!("internal RPC channel closed"))?;
        if skip_timeout {
            resp_rx
                .await
                .map_err(|_| anyhow::anyhow!("internal RPC channel closed"))
        } else {
            match timeout(Duration::from_secs(5), resp_rx).await {
                Ok(Ok(response)) => Ok(response),
                Ok(Err(_)) => Err(anyhow::anyhow!("internal RPC channel closed")),
                Err(_) => panic!("internal RPC timeout: {req_debug}"),
            }
        }
    }
}
