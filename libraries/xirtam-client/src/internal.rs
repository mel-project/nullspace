use async_trait::async_trait;
use bytes::Bytes;
use nanorpc::nanorpc_derive;
use serde::{Deserialize, Serialize};
use serde_with::base64::{Base64, UrlSafe};
use serde_with::formats::Unpadded;
use serde_with::{FromInto, IfIsHumanReadable, serde_as};
use smol_str::SmolStr;
use thiserror::Error;
use xirtam_structs::gateway::GatewayName;
use xirtam_structs::group::GroupId;
use xirtam_structs::handle::Handle;
use xirtam_structs::timestamp::{NanoTimestamp, Timestamp};
use std::collections::BTreeMap;

/// The internal JSON-RPC interface exposed by xirtam-client.
#[nanorpc_derive]
#[async_trait]
pub trait InternalProtocol {
    async fn next_event(&self) -> Event;
    async fn register_start(
        &self,
        handle: Handle,
    ) -> Result<Option<RegisterStartInfo>, InternalRpcError>;
    async fn register_finish(&self, request: RegisterFinish) -> Result<(), InternalRpcError>;
    async fn new_device_bundle(
        &self,
        can_sign: bool,
        expiry: Timestamp,
    ) -> Result<NewDeviceBundle, InternalRpcError>;
    async fn dm_send(
        &self,
        peer: Handle,
        mime: SmolStr,
        body: Bytes,
    ) -> Result<i64, InternalRpcError>;
    async fn group_create(&self, gateway: GatewayName) -> Result<GroupId, InternalRpcError>;
    async fn own_gateway(&self) -> Result<GatewayName, InternalRpcError>;
    async fn group_invite(&self, group: GroupId, handle: Handle) -> Result<(), InternalRpcError>;
    async fn group_send(
        &self,
        group: GroupId,
        mime: SmolStr,
        body: Bytes,
    ) -> Result<i64, InternalRpcError>;
    async fn group_history(
        &self,
        group: GroupId,
        before: Option<i64>,
        after: Option<i64>,
        limit: u16,
    ) -> Result<Vec<GroupMessage>, InternalRpcError>;
    async fn group_list(&self) -> Result<Vec<GroupId>, InternalRpcError>;
    async fn group_members(
        &self,
        group: GroupId,
    ) -> Result<Vec<GroupMember>, InternalRpcError>;
    async fn group_accept_invite(&self, dm_id: i64) -> Result<GroupId, InternalRpcError>;
    async fn add_contact(
        &self,
        handle: Handle,
        init_msg: String,
    ) -> Result<(), InternalRpcError>;
    async fn dm_history(
        &self,
        peer: Handle,
        before: Option<i64>,
        after: Option<i64>,
        limit: u16,
    ) -> Result<Vec<DmMessage>, InternalRpcError>;
    async fn all_peers(&self) -> Result<BTreeMap<Handle, DmMessage>, InternalRpcError>;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Event {
    State { logged_in: bool },
    DmUpdated { peer: Handle },
    GroupUpdated { group: GroupId },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegisterStartInfo {
    pub handle: Handle,
    pub gateway_name: GatewayName,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum RegisterFinish {
    BootstrapNewHandle {
        handle: Handle,
        gateway_name: GatewayName,
    },
    AddDevice {
        bundle: NewDeviceBundle,
    },
}

#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NewDeviceBundle(
    #[serde_as(as = "IfIsHumanReadable<Base64<UrlSafe, Unpadded>, FromInto<Vec<u8>>>")]
    pub Bytes,
);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DmMessage {
    pub id: i64,
    pub peer: Handle,
    pub sender: Handle,
    pub direction: DmDirection,
    pub mime: SmolStr,
    pub body: Bytes,
    pub received_at: Option<NanoTimestamp>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum DmDirection {
    Incoming,
    Outgoing,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupMessage {
    pub id: i64,
    pub group: GroupId,
    pub sender: Handle,
    pub direction: DmDirection,
    pub mime: SmolStr,
    pub body: Bytes,
    pub received_at: Option<NanoTimestamp>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupMember {
    pub handle: Handle,
    pub is_admin: bool,
    pub status: GroupMemberStatus,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GroupMemberStatus {
    Pending,
    Accepted,
    Banned,
}

#[derive(Clone, Debug, Error, Serialize, Deserialize)]
pub enum InternalRpcError {
    #[error("client not ready")]
    NotReady,
    #[error("access denied")]
    AccessDenied,
    #[error("{0}")]
    Other(String),
}
