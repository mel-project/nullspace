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
use nullspace_structs::server::{
    AuthToken, DeviceAuthChallenge, MailboxAcl, MailboxEntry, MailboxId, MailboxRecvArgs,
    ProxyError, ServerName, ServerProtocol, ServerRpcError, ServerService, SignedDeviceAuthRequest,
    SignedMediumPk,
};
use nullspace_structs::{Blob, profile::UserProfile, timestamp::NanoTimestamp, username::UserName};

use crate::config::CONFIG;
use crate::profile;
use crate::rpc_pool::RPC_POOL;
use crate::{device, dir_client::DIR_CLIENT, fragment, mailbox, multicast};

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
    async fn v1_multicast_allocate(&self, auth: AuthToken) -> Result<u32, ServerRpcError> {
        multicast::multicast_allocate(auth).await
    }

    async fn v1_multicast_post(&self, channel: u32, value: Blob) -> Result<(), ServerRpcError> {
        multicast::multicast_post(channel, value).await
    }

    async fn v1_multicast_poll(&self, channel: u32) -> Result<Option<Blob>, ServerRpcError> {
        multicast::multicast_poll(channel).await
    }

    async fn v1_device_auth_start(
        &self,
        username: UserName,
        device_pk: nullspace_crypt::signing::SigningPublic,
    ) -> Result<DeviceAuthChallenge, ServerRpcError> {
        device::device_auth_start(username, device_pk).await
    }

    async fn v1_device_auth_finish(
        &self,
        request: SignedDeviceAuthRequest,
    ) -> Result<AuthToken, ServerRpcError> {
        device::device_auth_finish(request).await
    }

    async fn v1_mailbox_send(
        &self,
        auth: AuthToken,
        mailbox_id: MailboxId,
        message: Blob,
        ttl: u32,
    ) -> Result<NanoTimestamp, ServerRpcError> {
        mailbox::mailbox_send(auth, mailbox_id, message, ttl).await
    }

    async fn v1_device_medium_pks(
        &self,
        username: UserName,
    ) -> Result<BTreeMap<nullspace_crypt::hash::Hash, SignedMediumPk>, ServerRpcError> {
        device::device_medium_pks(username).await
    }

    async fn v1_profile(&self, username: UserName) -> Result<Option<UserProfile>, ServerRpcError> {
        profile::profile_get(username).await
    }

    async fn v1_profile_set(
        &self,
        username: UserName,
        profile_value: UserProfile,
    ) -> Result<(), ServerRpcError> {
        profile::profile_set(username, profile_value).await
    }

    async fn v1_device_add_medium_pk(
        &self,
        auth: AuthToken,
        medium_pk: SignedMediumPk,
    ) -> Result<(), ServerRpcError> {
        device::device_add_medium_pk(auth, medium_pk).await
    }

    async fn v1_mailbox_multirecv(
        &self,
        args: Vec<MailboxRecvArgs>,
        timeout_ms: u64,
    ) -> Result<BTreeMap<MailboxId, Vec<MailboxEntry>>, ServerRpcError> {
        mailbox::mailbox_multirecv(args, timeout_ms).await
    }

    async fn v1_mailbox_acl_edit(
        &self,
        auth: AuthToken,
        mailbox_id: MailboxId,
        arg: MailboxAcl,
    ) -> Result<(), ServerRpcError> {
        mailbox::mailbox_acl_edit(auth, mailbox_id, arg).await
    }

    async fn v1_register_group(
        &self,
        auth: AuthToken,
        group: nullspace_structs::group::GroupId,
    ) -> Result<(), ServerRpcError> {
        mailbox::register_group(auth, group).await
    }

    async fn v1_upload_frag(
        &self,
        auth: AuthToken,
        frag: nullspace_structs::fragment::Fragment,
        ttl: u32,
    ) -> Result<(), ServerRpcError> {
        fragment::upload_frag(auth, frag, ttl).await
    }

    async fn v1_download_frag(
        &self,
        hash: nullspace_crypt::hash::Hash,
    ) -> Result<Option<nullspace_structs::fragment::Fragment>, ServerRpcError> {
        fragment::download_frag(hash).await
    }

    async fn v1_proxy_server(
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

    async fn v1_proxy_directory(
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
