use std::collections::BTreeMap;

use axum::{
    http::{StatusCode, header},
    response::IntoResponse,
};
use bytes::Bytes;
use nanorpc::{JrpcRequest, RpcService};
use xirtam_structs::certificate::CertificateChain;
use xirtam_structs::gateway::{
    AuthToken, GatewayProtocol, GatewayServerError, GatewayService, MailboxAcl, MailboxEntry,
    MailboxId, MailboxRecvArgs, SignedTempPk,
};
use xirtam_structs::{Message, handle::Handle};

use crate::{device, mailbox};

#[derive(Clone, Default)]
pub struct GatewayServer;

pub async fn handle_rpc(body: Bytes) -> impl IntoResponse {
    let Ok(req) = serde_json::from_slice::<JrpcRequest>(&body) else {
        return (
            StatusCode::BAD_REQUEST,
            [(header::CONTENT_TYPE, "text/plain")],
            Vec::new(),
        );
    };
    let service = GatewayService(GatewayServer::default());
    let response = service.respond_raw(req).await;
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        serde_json::to_vec(&response).unwrap(),
    )
}

#[async_trait::async_trait]
impl GatewayProtocol for GatewayServer {
    async fn v1_device_auth(
        &self,
        handle: Handle,
        cert: CertificateChain,
    ) -> Result<AuthToken, GatewayServerError> {
        device::device_auth(handle, cert).await
    }

    async fn v1_device_certs(
        &self,
        handle: Handle,
    ) -> Result<Option<CertificateChain>, GatewayServerError> {
        device::device_list(handle).await
    }

    async fn v1_mailbox_send(
        &self,
        auth: AuthToken,
        mailbox_id: MailboxId,
        message: Message,
    ) -> Result<(), GatewayServerError> {
        mailbox::mailbox_send(auth, mailbox_id, message).await
    }

    async fn v1_device_temp_pks(
        &self,
        handle: Handle,
    ) -> Result<BTreeMap<xirtam_crypt::hash::Hash, SignedTempPk>, GatewayServerError> {
        device::device_temp_pks(handle).await
    }

    async fn v1_device_add_temp_pk(
        &self,
        auth: AuthToken,
        temp_pk: SignedTempPk,
    ) -> Result<(), GatewayServerError> {
        device::device_add_temp_pk(auth, temp_pk).await
    }

    async fn v1_mailbox_multirecv(
        &self,
        args: Vec<MailboxRecvArgs>,
        timeout_ms: u64,
    ) -> Result<BTreeMap<MailboxId, Vec<MailboxEntry>>, GatewayServerError> {
        mailbox::mailbox_multirecv(args, timeout_ms).await
    }

    async fn v1_mailbox_acl_edit(
        &self,
        auth: AuthToken,
        mailbox_id: MailboxId,
        arg: MailboxAcl,
    ) -> Result<(), GatewayServerError> {
        mailbox::mailbox_acl_edit(auth, mailbox_id, arg).await
    }
}
