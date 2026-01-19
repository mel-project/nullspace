use std::collections::BTreeMap;

use axum::{
    http::{StatusCode, header},
    response::IntoResponse,
};
use bytes::Bytes;
use nanorpc::{JrpcRequest, RpcService};
use xirtam_structs::certificate::CertificateChain;
use xirtam_structs::server::{
    AuthToken, ServerProtocol, ServerRpcError, ServerService, MailboxAcl, MailboxEntry,
    MailboxId, MailboxRecvArgs, SignedMediumPk,
};
use xirtam_structs::{Blob, username::UserName, timestamp::NanoTimestamp};

use crate::{device, mailbox};

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
    async fn v1_device_auth(
        &self,
        username: UserName,
        cert: CertificateChain,
    ) -> Result<AuthToken, ServerRpcError> {
        device::device_auth(username, cert).await
    }

    async fn v1_device_certs(
        &self,
        username: UserName,
    ) -> Result<Option<BTreeMap<xirtam_crypt::hash::Hash, CertificateChain>>, ServerRpcError> {
        device::device_list(username).await
    }

    async fn v1_mailbox_send(
        &self,
        auth: AuthToken,
        mailbox_id: MailboxId,
        message: Blob,
    ) -> Result<NanoTimestamp, ServerRpcError> {
        mailbox::mailbox_send(auth, mailbox_id, message).await
    }

    async fn v1_device_medium_pks(
        &self,
        username: UserName,
    ) -> Result<BTreeMap<xirtam_crypt::hash::Hash, SignedMediumPk>, ServerRpcError> {
        device::device_medium_pks(username).await
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
        group: xirtam_structs::group::GroupId,
    ) -> Result<(), ServerRpcError> {
        mailbox::register_group(auth, group).await
    }
}
