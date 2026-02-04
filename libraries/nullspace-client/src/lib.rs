mod c_api;
mod config;
mod auth_tokens;
mod attachments;
mod convo;
mod database;
mod directory;
mod events;
mod identity;
pub mod internal;
mod long_poll;
mod main_loop;
mod medium_keys;
mod rpc_pool;
mod retry;
mod server;
mod user_info;

use std::sync::mpsc::Sender;

use nanorpc::{DynRpcTransport, JrpcRequest, JrpcResponse, RpcTransport};
use tokio::sync::oneshot;

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

        self.send_rpc
            .send((req, resp_tx))
            .map_err(|_| anyhow::anyhow!("internal RPC channel closed"))?;

        resp_rx
            .await
            .map_err(|_| anyhow::anyhow!("internal RPC channel closed"))
    }
}
