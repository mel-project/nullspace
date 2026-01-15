use async_trait::async_trait;
use anyctx::AnyCtx;
use async_channel::Receiver as AsyncReceiver;
use bytes::Bytes;
use nanorpc::nanorpc_derive;
use serde::{Deserialize, Serialize};
use serde_with::base64::{Base64, UrlSafe};
use serde_with::formats::Unpadded;
use serde_with::{FromInto, IfIsHumanReadable, serde_as};
use smol_str::SmolStr;
use std::sync::Arc;
use tokio::sync::Mutex;
use thiserror::Error;
use xirtam_crypt::dh::DhSecret;
use xirtam_crypt::hash::BcsHashExt;
use xirtam_crypt::signing::{Signable, Signature};
use xirtam_structs::certificate::{CertificateChain, DeviceSecret};
use xirtam_structs::gateway::{AuthToken, GatewayClient, GatewayName, SignedMediumPk};
use xirtam_structs::group::GroupId;
use xirtam_structs::handle::{Handle, HandleDescriptor};
use xirtam_structs::timestamp::{NanoTimestamp, Timestamp};
use std::collections::BTreeMap;

use crate::Config;
use crate::database::{DATABASE, DbNotify, identity_exists};
use crate::directory::DIR_CLIENT;
use crate::dm::queue_dm;
use crate::gateway::get_gateway_client;
use crate::groups::{
    accept_invite, create_group, invite, load_group, queue_group_message, GroupRoster,
};
use crate::identity::Identity;

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

#[derive(Clone)]
pub(crate) struct InternalImpl {
    ctx: AnyCtx<Config>,
    events: Arc<Mutex<AsyncReceiver<Event>>>,
}

impl InternalImpl {
    pub fn new(ctx: AnyCtx<Config>, events: AsyncReceiver<Event>) -> Self {
        Self {
            ctx,
            events: Arc::new(Mutex::new(events)),
        }
    }
}

#[async_trait]
impl InternalProtocol for InternalImpl {
    async fn next_event(&self) -> Event {
        let events = self.events.lock().await;
        match events.recv().await {
            Ok(event) => event,
            Err(_) => Event::State { logged_in: false },
        }
    }

    async fn register_start(
        &self,
        handle: Handle,
    ) -> Result<Option<RegisterStartInfo>, InternalRpcError> {
        tracing::debug!(handle = %handle, "register_start begin");
        let dir = self.ctx.get(DIR_CLIENT);
        let descriptor = dir
            .get_handle_descriptor(&handle)
            .await
            .map_err(internal_err)?;
        let Some(descriptor) = descriptor else {
            tracing::debug!(handle = %handle, "register_start not found");
            return Ok(None);
        };
        tracing::debug!(handle = %handle, gateway = %descriptor.gateway_name, "register_start found");
        Ok(Some(RegisterStartInfo {
            handle,
            gateway_name: descriptor.gateway_name,
        }))
    }

    async fn register_finish(&self, request: RegisterFinish) -> Result<(), InternalRpcError> {
        let db = self.ctx.get(DATABASE);
        if identity_exists(db).await.map_err(internal_err)? {
            return Err(InternalRpcError::NotReady);
        }
        match request {
            RegisterFinish::BootstrapNewHandle {
                handle,
                gateway_name,
            } => register_bootstrap(self.ctx.clone(), handle, gateway_name).await,
            RegisterFinish::AddDevice { bundle } => {
                register_add_device(self.ctx.clone(), bundle).await
            }
        }
    }

    async fn new_device_bundle(
        &self,
        can_sign: bool,
        expiry: Timestamp,
    ) -> Result<NewDeviceBundle, InternalRpcError> {
        let db = self.ctx.get(DATABASE);
        let identity = Identity::load(db).await.map_err(internal_err)?;
        let can_issue = identity
            .cert_chain
            .0
            .iter()
            .find(|cert| cert.pk == identity.device_secret.public())
            .map(|cert| cert.can_sign)
            .unwrap_or(false);
        if !can_issue {
            return Err(InternalRpcError::AccessDenied);
        }
        let new_secret = DeviceSecret::random();
        let cert = identity
            .device_secret
            .issue_certificate(&new_secret.public(), expiry, can_sign);
        let mut chain = identity.cert_chain.clone();
        chain.0.push(cert);
        let bundle = BundleInner {
            handle: identity.handle,
            device_secret: new_secret,
            cert_chain: chain,
        };
        let encoded = bcs::to_bytes(&bundle).map_err(internal_err)?;
        Ok(NewDeviceBundle(Bytes::from(encoded)))
    }

    async fn dm_send(
        &self,
        peer: Handle,
        mime: smol_str::SmolStr,
        body: Bytes,
    ) -> Result<i64, InternalRpcError> {
        let db = self.ctx.get(DATABASE);
        let identity = Identity::load(db)
            .await
            .map_err(|_| InternalRpcError::NotReady)?;
        let id = queue_dm(db, &identity.handle, &peer, &mime, &body)
            .await
            .map_err(internal_err)?;
        DbNotify::touch();
        Ok(id)
    }

    async fn group_create(&self, gateway: GatewayName) -> Result<GroupId, InternalRpcError> {
        let db = self.ctx.get(DATABASE);
        if !identity_exists(db).await.map_err(internal_err)? {
            return Err(InternalRpcError::NotReady);
        }
        create_group(&self.ctx, gateway).await.map_err(internal_err)
    }

    async fn own_gateway(&self) -> Result<GatewayName, InternalRpcError> {
        let db = self.ctx.get(DATABASE);
        let identity = Identity::load(db).await.map_err(internal_err)?;
        identity
            .gateway_name
            .ok_or_else(|| InternalRpcError::Other("gateway name not available".into()))
    }

    async fn group_invite(&self, group: GroupId, handle: Handle) -> Result<(), InternalRpcError> {
        let db = self.ctx.get(DATABASE);
        if !identity_exists(db).await.map_err(internal_err)? {
            return Err(InternalRpcError::NotReady);
        }
        invite(&self.ctx, group, handle).await.map_err(internal_err)
    }

    async fn group_send(
        &self,
        group: GroupId,
        mime: smol_str::SmolStr,
        body: Bytes,
    ) -> Result<i64, InternalRpcError> {
        let db = self.ctx.get(DATABASE);
        let identity = Identity::load(db)
            .await
            .map_err(|_| InternalRpcError::NotReady)?;
        let id = queue_group_message(db, &group, &identity.handle, &mime, &body)
            .await
            .map_err(internal_err)?;
        DbNotify::touch();
        Ok(id)
    }

    async fn group_history(
        &self,
        group: GroupId,
        before: Option<i64>,
        after: Option<i64>,
        limit: u16,
    ) -> Result<Vec<GroupMessage>, InternalRpcError> {
        let db = self.ctx.get(DATABASE);
        let identity = Identity::load(db)
            .await
            .map_err(|_| InternalRpcError::NotReady)?;
        let before = before.unwrap_or(i64::MAX);
        let after = after.unwrap_or(i64::MIN);
        let mut rows = sqlx::query_as::<_, (i64, String, String, Vec<u8>, Option<i64>)>(
            "SELECT id, sender_handle, mime, body, received_at \
             FROM group_messages \
             WHERE group_id = ? AND id <= ? AND id >= ? \
             ORDER BY id DESC \
             LIMIT ?",
        )
        .bind(group.as_bytes().to_vec())
        .bind(before)
        .bind(after)
        .bind(limit as i64)
        .fetch_all(db)
        .await
        .map_err(internal_err)?;
        rows.reverse();
        let mut out = Vec::with_capacity(rows.len());
        for (id, sender_handle, mime, body, received_at) in rows {
            let sender = Handle::parse(sender_handle).map_err(internal_err)?;
            let direction = if sender == identity.handle {
                DmDirection::Outgoing
            } else {
                DmDirection::Incoming
            };
            out.push(GroupMessage {
                id,
                group,
                sender,
                direction,
                mime: smol_str::SmolStr::new(mime),
                body: Bytes::from(body),
                received_at: received_at.map(|ts| NanoTimestamp(ts as u64)),
            });
        }
        Ok(out)
    }

    async fn group_list(&self) -> Result<Vec<GroupId>, InternalRpcError> {
        let db = self.ctx.get(DATABASE);
        if !identity_exists(db).await.map_err(internal_err)? {
            return Err(InternalRpcError::NotReady);
        }
        let rows = sqlx::query_as::<_, (Vec<u8>,)>("SELECT group_id FROM groups ORDER BY group_id")
            .fetch_all(db)
            .await
            .map_err(internal_err)?;
        let mut out = Vec::with_capacity(rows.len());
        for (group_id,) in rows {
            let group = <[u8; 32]>::try_from(group_id.as_slice())
                .map(GroupId::from_bytes)
                .map_err(internal_err)?;
            out.push(group);
        }
        Ok(out)
    }

    async fn group_members(&self, group: GroupId) -> Result<Vec<GroupMember>, InternalRpcError> {
        let db = self.ctx.get(DATABASE);
        if !identity_exists(db).await.map_err(internal_err)? {
            return Err(InternalRpcError::NotReady);
        }
        let group_record = load_group(db, group)
            .await
            .map_err(internal_err)?
            .ok_or_else(|| InternalRpcError::Other("group not found".into()))?;
        let mut tx = db.begin().await.map_err(internal_err)?;
        let roster =
            GroupRoster::load(tx.as_mut(), group, group_record.descriptor.init_admin.clone())
                .await
                .map_err(internal_err)?;
        let members = roster.list(tx.as_mut()).await.map_err(internal_err)?;
        tx.commit().await.map_err(internal_err)?;
        let out = members
            .into_iter()
            .map(|member| GroupMember {
                handle: member.handle,
                is_admin: member.is_admin,
                status: member.status,
            })
            .collect();
        Ok(out)
    }

    async fn group_accept_invite(&self, dm_id: i64) -> Result<GroupId, InternalRpcError> {
        let db = self.ctx.get(DATABASE);
        if !identity_exists(db).await.map_err(internal_err)? {
            return Err(InternalRpcError::NotReady);
        }
        accept_invite(&self.ctx, dm_id).await.map_err(internal_err)
    }

    async fn add_contact(&self, handle: Handle, init_msg: String) -> Result<(), InternalRpcError> {
        let dir = self.ctx.get(DIR_CLIENT);
        if dir
            .get_handle_descriptor(&handle)
            .await
            .map_err(internal_err)?
            .is_none()
        {
            return Err(InternalRpcError::Other("handle not found".into()));
        }
        self.dm_send(handle, SmolStr::new("text/plain"), Bytes::from(init_msg))
            .await
            .map(|_| ())
    }

    async fn dm_history(
        &self,
        peer: Handle,
        before: Option<i64>,
        after: Option<i64>,
        limit: u16,
    ) -> Result<Vec<DmMessage>, InternalRpcError> {
        let db = self.ctx.get(DATABASE);
        let identity = Identity::load(db)
            .await
            .map_err(|_| InternalRpcError::NotReady)?;
        let before = before.unwrap_or(i64::MAX);
        let after = after.unwrap_or(i64::MIN);
        let mut rows = sqlx::query_as::<_, (i64, String, String, Vec<u8>, Option<i64>)>(
            "SELECT id, sender_handle, mime, body, received_at \
             FROM dm_messages \
             WHERE peer_handle = ? AND id <= ? AND id >= ? \
             ORDER BY id DESC \
             LIMIT ?",
        )
        .bind(peer.as_str())
        .bind(before)
        .bind(after)
        .bind(limit as i64)
        .fetch_all(db)
        .await
        .map_err(internal_err)?;
        rows.reverse();
        let mut out = Vec::with_capacity(rows.len());
        for (id, sender_handle, mime, body, received_at) in rows {
            let sender = Handle::parse(sender_handle).map_err(internal_err)?;
            let direction = if sender == identity.handle {
                DmDirection::Outgoing
            } else {
                DmDirection::Incoming
            };
            out.push(DmMessage {
                id,
                peer: peer.clone(),
                sender,
                direction,
                mime: smol_str::SmolStr::new(mime),
                body: Bytes::from(body),
                received_at: received_at.map(|ts| NanoTimestamp(ts as u64)),
            });
        }
        Ok(out)
    }

    async fn all_peers(&self) -> Result<BTreeMap<Handle, DmMessage>, InternalRpcError> {
        let db = self.ctx.get(DATABASE);
        let identity = Identity::load(db)
            .await
            .map_err(|_| InternalRpcError::NotReady)?;
        let rows = sqlx::query_as::<_, (i64, String, String, String, Vec<u8>, Option<i64>)>(
            "SELECT id, peer_handle, sender_handle, mime, body, received_at \
             FROM dm_messages \
             ORDER BY id DESC",
        )
        .fetch_all(db)
        .await
        .map_err(internal_err)?;
        let mut out = BTreeMap::new();
        for (id, peer_handle, sender_handle, mime, body, received_at) in rows {
            let peer = Handle::parse(peer_handle).map_err(internal_err)?;
            if out.contains_key(&peer) {
                continue;
            }
            let sender = Handle::parse(sender_handle).map_err(internal_err)?;
            let direction = if sender == identity.handle {
                DmDirection::Outgoing
            } else {
                DmDirection::Incoming
            };
            out.insert(
                peer.clone(),
                DmMessage {
                    id,
                    peer,
                    sender,
                    direction,
                    mime: smol_str::SmolStr::new(mime),
                    body: Bytes::from(body),
                    received_at: received_at.map(|ts| NanoTimestamp(ts as u64)),
                },
            );
        }
        if !out.contains_key(&identity.handle) {
            out.insert(
                identity.handle.clone(),
                DmMessage {
                    id: 0,
                    peer: identity.handle.clone(),
                    sender: identity.handle,
                    direction: DmDirection::Outgoing,
                    mime: smol_str::SmolStr::new(""),
                    body: Bytes::new(),
                    received_at: None,
                },
            );
        }
        Ok(out)
    }
}

async fn register_bootstrap(
    ctx: AnyCtx<Config>,
    handle: Handle,
    gateway_name: GatewayName,
) -> Result<(), InternalRpcError> {
    let dir = ctx.get(DIR_CLIENT);
    if dir
        .get_handle_descriptor(&handle)
        .await
        .map_err(internal_err)?
        .is_some()
    {
        return Err(InternalRpcError::Other("handle already exists".into()));
    }
    let device_secret = DeviceSecret::random();
    let root_cert = device_secret.self_signed(Timestamp(u64::MAX), true);
    let cert_chain = CertificateChain(vec![root_cert.clone()]);
    let handle_descriptor = HandleDescriptor {
        gateway_name: gateway_name.clone(),
        root_cert_hash: root_cert.pk.bcs_hash(),
    };
    dir.add_owner(
        &handle,
        device_secret.public().signing_public(),
        &device_secret,
    )
    .await
    .map_err(internal_err)?;
    dir.insert_handle_descriptor(&handle, &handle_descriptor, &device_secret)
        .await
        .map_err(internal_err)?;

    let gateway = gateway_from_name(&ctx, &gateway_name).await?;
    let auth = device_auth(&gateway, &handle, &cert_chain).await?;
    let medium_sk = register_medium_key(&gateway, auth, &device_secret).await?;

    persist_identity(
        ctx.get(DATABASE),
        handle,
        gateway_name,
        device_secret,
        cert_chain,
        medium_sk,
    )
    .await?;
    DbNotify::touch();
    Ok(())
}

async fn register_add_device(
    ctx: AnyCtx<Config>,
    bundle: NewDeviceBundle,
) -> Result<(), InternalRpcError> {
    let bundle: BundleInner = bcs::from_bytes(&bundle.0).map_err(internal_err)?;
    let dir = ctx.get(DIR_CLIENT);
    let handle_descriptor = dir
        .get_handle_descriptor(&bundle.handle)
        .await
        .map_err(internal_err)?
        .ok_or_else(|| InternalRpcError::Other("handle not found".into()))?;
    bundle
        .cert_chain
        .verify(handle_descriptor.root_cert_hash)
        .map_err(internal_err)?;
    let gateway = gateway_from_name(&ctx, &handle_descriptor.gateway_name).await?;
    let auth = device_auth(&gateway, &bundle.handle, &bundle.cert_chain).await?;
    let medium_sk = register_medium_key(&gateway, auth, &bundle.device_secret).await?;
    persist_identity(
        ctx.get(DATABASE),
        bundle.handle,
        handle_descriptor.gateway_name.clone(),
        bundle.device_secret,
        bundle.cert_chain,
        medium_sk,
    )
    .await?;
    DbNotify::touch();
    Ok(())
}

async fn gateway_from_name(
    ctx: &AnyCtx<Config>,
    gateway_name: &GatewayName,
) -> Result<Arc<GatewayClient>, InternalRpcError> {
    let dir = ctx.get(DIR_CLIENT);
    let descriptor = dir
        .get_gateway_descriptor(gateway_name)
        .await
        .map_err(internal_err)?
        .ok_or_else(|| InternalRpcError::Other("gateway not found".into()))?;
    let _ = descriptor;
    get_gateway_client(ctx, gateway_name)
        .await
        .map_err(internal_err)
}

async fn device_auth(
    gateway: &GatewayClient,
    handle: &Handle,
    cert_chain: &CertificateChain,
) -> Result<AuthToken, InternalRpcError> {
    gateway
        .v1_device_auth(handle.clone(), cert_chain.clone())
        .await
        .map_err(internal_err)?
        .map_err(|err| InternalRpcError::Other(err.to_string()))
}

async fn register_medium_key(
    gateway: &GatewayClient,
    auth: AuthToken,
    device_secret: &DeviceSecret,
) -> Result<DhSecret, InternalRpcError> {
    let medium_sk = DhSecret::random();
    let mut signed = SignedMediumPk {
        medium_pk: medium_sk.public_key(),
        created: Timestamp::now(),
        signature: Signature::from_bytes([0u8; 64]),
    };
    signed.sign(device_secret);
    gateway
        .v1_device_add_medium_pk(auth, signed)
        .await
        .map_err(internal_err)?
        .map_err(|err| InternalRpcError::Other(err.to_string()))?;
    Ok(medium_sk)
}

async fn persist_identity(
    db: &sqlx::SqlitePool,
    handle: Handle,
    gateway_name: GatewayName,
    device_secret: DeviceSecret,
    cert_chain: CertificateChain,
    medium_sk: DhSecret,
) -> Result<(), InternalRpcError> {
    sqlx::query(
        "INSERT INTO client_identity \
         (id, handle, gateway_name, device_secret, cert_chain, medium_sk_current, medium_sk_prev) \
         VALUES (1, ?, ?, ?, ?, ?, ?)",
    )
    .bind(handle.as_str())
    .bind(gateway_name.as_str())
    .bind(bcs::to_bytes(&device_secret).map_err(internal_err)?)
    .bind(bcs::to_bytes(&cert_chain).map_err(internal_err)?)
    .bind(bcs::to_bytes(&medium_sk).map_err(internal_err)?)
    .bind(bcs::to_bytes(&medium_sk).map_err(internal_err)?)
    .execute(db)
    .await
    .map_err(internal_err)?;
    Ok(())
}

#[derive(Serialize, Deserialize)]
struct BundleInner {
    handle: Handle,
    device_secret: DeviceSecret,
    cert_chain: CertificateChain,
}

fn internal_err(err: impl std::fmt::Display) -> InternalRpcError {
    InternalRpcError::Other(err.to_string())
}
