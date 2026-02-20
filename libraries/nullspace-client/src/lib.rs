#![doc = include_str!(concat!(env!("OUT_DIR"), "/README-rustdocified.md"))]

mod attachments;
mod auth_tokens;
mod c_api;
mod config;
mod convo;
mod database;
mod directory;
mod events;
mod identity;
pub mod internal;
mod long_poll;
mod main_loop;
mod medium_keys;
mod profile;
mod provisioning;
mod retry;
mod rpc_pool;
mod server;
mod user_info;

use std::sync::mpsc::Sender;

use nanorpc::{DynRpcTransport, JrpcRequest, JrpcResponse, RpcTransport};
use tokio::sync::oneshot;

pub use crate::config::Config;
pub use crate::internal::InternalClient;

/// The main entry point for the nullspace messaging service.
///
/// `Client` owns a dedicated background thread running a Tokio
/// single-threaded runtime.  All protocol activity -- database access,
/// server communication, encryption, key rotation, message sending and
/// receiving -- happens inside that thread.
///
/// Frontends communicate with the service through an [`InternalClient`]
/// obtained via [`Client::rpc`].  The RPC handle is `Clone` + `Send` and
/// safe to share across threads; each call is serialized through an
/// in-process channel (no network overhead).
///
/// The client is **runtime-agnostic**: it brings its own Tokio runtime, so
/// the host application can use any async executor (or none at all).
pub struct Client {
    send_rpc: Sender<(JrpcRequest, oneshot::Sender<JrpcResponse>)>,
}

impl Client {
    /// Creates a new client and starts the background service.
    ///
    /// This spawns a dedicated OS thread (`nullspace-tokio`) that runs the
    /// main event loop.  The thread will:
    ///
    /// 1. Initialize the SQLite database at [`Config::db_path`] (creating it
    ///    if necessary and running migrations).
    /// 2. Start serving RPC requests immediately.
    /// 3. Once an identity exists in the database, launch the background
    ///    workers -- message send/receive loops, DM and group receivers,
    ///    medium-term key rotation, and the database event loop that drives
    ///    push [`Event`](internal::Event)s to the frontend.
    ///
    /// # Panics
    ///
    /// Panics if the background thread or Tokio runtime cannot be created.
    pub fn new(config: Config) -> Self {
        let (send_rpc, recv_rpc) = std::sync::mpsc::channel();
        std::thread::Builder::new()
            .name("nullspace-tokio".to_string())
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("nullspace-client tokio runtime");
                runtime.block_on(main_loop::main_loop(config, recv_rpc));
            })
            .expect("spawn nullspace-client runtime thread");
        Self { send_rpc }
    }

    /// Returns a typed RPC handle for calling the client's API.
    ///
    /// The returned [`InternalClient`] is cheap to clone and can be shared
    /// freely across threads.  Every method on it corresponds to a method on
    /// [`InternalProtocol`](internal::InternalProtocol); calls are dispatched
    /// over an in-process channel to the background service thread.
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
