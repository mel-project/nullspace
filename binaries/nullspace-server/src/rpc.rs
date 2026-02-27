use std::collections::BTreeMap;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use axum::{
    http::{StatusCode, header},
    response::IntoResponse,
};
use bytes::Bytes;
use moka::future::Cache as FutureCache;
use nanorpc::{JrpcRequest, JrpcResponse, RpcService, RpcTransport};
use nullspace_rpc_pool::PooledTransport;
use nullspace_structs::mailbox::{MailboxEntry, MailboxId, MailboxKey, MailboxRecvArgs};
use nullspace_structs::server::{
    AuthToken, ChanDirection, DeviceAuthChallenge, ProxyError, ServerName, ServerProtocol,
    ServerRpcError, ServerService, SignedDeviceAuthRequest, SignedMediumPk,
};
use nullspace_structs::{Blob, profile::UserProfile, timestamp::NanoTimestamp, username::UserName};

use crate::config::CONFIG;
use crate::profile;
use crate::rpc_pool::RPC_POOL;
use crate::{channel, device, dir_client::DIR_CLIENT, fragment, mailbox};

#[derive(Clone, Default)]
pub struct ServerRpc;

pub async fn rpc_handler(body: Bytes) -> impl IntoResponse {
    let Ok(req) = serde_json::from_slice::<JrpcRequest>(&body) else {
        return (
            StatusCode::BAD_REQUEST,
            [(header::CONTENT_TYPE, "text/plain")],
            Vec::new(),
        );
    };
    let service = ServerService(ServerRpc);
    let response = service.respond_raw(req).await;
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        serde_json::to_vec(&response).unwrap(),
    )
}

#[async_trait::async_trait]
impl ServerProtocol for ServerRpc {
    async fn chan_allocate(&self, auth: AuthToken) -> Result<u32, ServerRpcError> {
        channel::chan_allocate(auth).await
    }

    async fn chan_send(
        &self,
        channel_id: u32,
        direction: ChanDirection,
        value: Blob,
    ) -> Result<(), ServerRpcError> {
        channel::chan_send(channel_id, direction, value).await
    }

    async fn chan_recv(
        &self,
        channel_id: u32,
        direction: ChanDirection,
    ) -> Result<Option<Blob>, ServerRpcError> {
        channel::chan_recv(channel_id, direction).await
    }

    async fn device_auth_start(
        &self,
        username: UserName,
        device_pk: nullspace_crypt::signing::SigningPublic,
    ) -> Result<DeviceAuthChallenge, ServerRpcError> {
        device::device_auth_start(username, device_pk).await
    }

    async fn device_auth_finish(
        &self,
        request: SignedDeviceAuthRequest,
    ) -> Result<AuthToken, ServerRpcError> {
        device::device_auth_finish(request).await
    }

    async fn mailbox_send(
        &self,
        mailbox_id: MailboxId,
        message: Blob,
        ttl: u32,
    ) -> Result<NanoTimestamp, ServerRpcError> {
        mailbox::mailbox_send(mailbox_id, message, ttl).await
    }

    async fn mailbox_create(
        &self,
        auth: AuthToken,
        mailbox_key: MailboxKey,
    ) -> Result<MailboxId, ServerRpcError> {
        mailbox::mailbox_create(auth, mailbox_key).await
    }

    async fn device_medium_pks(
        &self,
        username: UserName,
    ) -> Result<BTreeMap<nullspace_crypt::hash::Hash, SignedMediumPk>, ServerRpcError> {
        device::device_medium_pks(username).await
    }

    async fn profile(&self, username: UserName) -> Result<Option<UserProfile>, ServerRpcError> {
        profile::profile_get(username).await
    }

    async fn profile_set(
        &self,
        username: UserName,
        profile_value: UserProfile,
    ) -> Result<(), ServerRpcError> {
        profile::profile_set(username, profile_value).await
    }

    async fn device_add_medium_pk(
        &self,
        auth: AuthToken,
        medium_pk: SignedMediumPk,
    ) -> Result<(), ServerRpcError> {
        device::device_add_medium_pk(auth, medium_pk).await
    }

    async fn mailbox_multirecv(
        &self,
        args: Vec<MailboxRecvArgs>,
        timeout_ms: u64,
    ) -> Result<BTreeMap<MailboxId, Vec<MailboxEntry>>, ServerRpcError> {
        mailbox::mailbox_multirecv(args, timeout_ms).await
    }

    async fn frag_upload(
        &self,
        auth: AuthToken,
        frag: nullspace_structs::fragment::Fragment,
        ttl: u32,
    ) -> Result<(), ServerRpcError> {
        fragment::frag_upload(auth, frag, ttl).await
    }

    async fn frag_download(
        &self,
        hash: nullspace_crypt::hash::Hash,
    ) -> Result<Option<nullspace_structs::fragment::Fragment>, ServerRpcError> {
        fragment::frag_download(hash).await
    }

    async fn proxy_server(
        &self,
        auth: AuthToken,
        server: ServerName,
        req: JrpcRequest,
    ) -> Result<JrpcResponse, ProxyError> {
        if !CONFIG.proxy_enabled {
            return Err(ProxyError::NotSupported);
        }
        static PROXY_CACHE: LazyLock<FutureCache<ServerName, PooledTransport>> =
            LazyLock::new(|| {
                FutureCache::builder()
                    .time_to_idle(Duration::from_secs(12 * 60 * 60))
                    .build()
            });

        match device::auth_token_exists(auth).await {
            Ok(true) => {}
            Ok(false) => return Err(ProxyError::NotSupported),
            Err(err) => return Err(ProxyError::Upstream(err.to_string())),
        }
        let transport = PROXY_CACHE
            .try_get_with(server.clone(), async {
                let descriptor = DIR_CLIENT
                    .get_server_descriptor(&server)
                    .await?
                    .ok_or_else(|| anyhow::anyhow!("server not in directory"))?;
                let endpoint = descriptor
                    .public_urls
                    .first()
                    .cloned()
                    .ok_or_else(|| anyhow::anyhow!("server has no public URLs"))?;
                Ok(RPC_POOL.rpc(endpoint))
            })
            .await
            .map_err(|err: Arc<anyhow::Error>| ProxyError::Upstream(err.to_string()))?;
        transport
            .call_raw(req)
            .await
            .map_err(|err| ProxyError::Upstream(err.to_string()))
    }

    async fn proxy_directory(
        &self,
        auth: AuthToken,
        req: JrpcRequest,
    ) -> Result<JrpcResponse, ProxyError> {
        match device::auth_token_exists(auth).await {
            Ok(true) => {}
            Ok(false) => return Err(ProxyError::NotSupported),
            Err(err) => return Err(ProxyError::Upstream(err.to_string())),
        }

        static DIRECTORY_TRANSPORT: LazyLock<PooledTransport> =
            LazyLock::new(|| RPC_POOL.rpc(CONFIG.directory_url.clone()));

        DIRECTORY_TRANSPORT
            .call_raw(req)
            .await
            .map_err(|err| ProxyError::Upstream(err.to_string()))
    }
}
