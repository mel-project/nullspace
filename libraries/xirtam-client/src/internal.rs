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
use xirtam_structs::server::{AuthToken, ServerClient, ServerName, SignedMediumPk};
use xirtam_structs::group::GroupId;
use xirtam_structs::username::{UserDescriptor, UserName};
use xirtam_structs::timestamp::{NanoTimestamp, Timestamp};
use std::collections::BTreeMap;

use crate::Config;
use crate::database::{DATABASE, DbNotify, identity_exists};
use crate::directory::DIR_CLIENT;
use crate::dm::queue_dm;
use crate::server::get_server_client;
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
        username: UserName,
    ) -> Result<Option<RegisterStartInfo>, InternalRpcError>;
    async fn register_finish(&self, request: RegisterFinish) -> Result<(), InternalRpcError>;
    async fn new_device_bundle(
        &self,
        can_issue: bool,
        expiry: Timestamp,
    ) -> Result<NewDeviceBundle, InternalRpcError>;
    async fn dm_send(
        &self,
        peer: UserName,
        mime: SmolStr,
        body: Bytes,
    ) -> Result<i64, InternalRpcError>;
    async fn group_create(&self, server: ServerName) -> Result<GroupId, InternalRpcError>;
    async fn own_server(&self) -> Result<ServerName, InternalRpcError>;
    async fn group_invite(&self, group: GroupId, username: UserName) -> Result<(), InternalRpcError>;
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
        username: UserName,
        init_msg: String,
    ) -> Result<(), InternalRpcError>;
    async fn dm_history(
        &self,
        peer: UserName,
        before: Option<i64>,
        after: Option<i64>,
        limit: u16,
    ) -> Result<Vec<DmMessage>, InternalRpcError>;
    async fn all_peers(&self) -> Result<BTreeMap<UserName, DmMessage>, InternalRpcError>;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Event {
    State { logged_in: bool },
    DmUpdated { peer: UserName },
    GroupUpdated { group: GroupId },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegisterStartInfo {
    pub username: UserName,
    pub server_name: ServerName,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum RegisterFinish {
    BootstrapNewUser {
        username: UserName,
        server_name: ServerName,
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
    pub peer: UserName,
    pub sender: UserName,
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
    pub sender: UserName,
    pub direction: DmDirection,
    pub mime: SmolStr,
    pub body: Bytes,
    pub received_at: Option<NanoTimestamp>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupMember {
    pub username: UserName,
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
        username: UserName,
    ) -> Result<Option<RegisterStartInfo>, InternalRpcError> {
        tracing::debug!(username = %username, "register_start begin");
        let dir = self.ctx.get(DIR_CLIENT);
        let descriptor = dir
            .get_user_descriptor(&username)
            .await
            .map_err(internal_err)?;
        let Some(descriptor) = descriptor else {
            tracing::debug!(username = %username, "register_start not found");
            return Ok(None);
        };
        tracing::debug!(username = %username, server = %descriptor.server_name, "register_start found");
        Ok(Some(RegisterStartInfo {
            username,
            server_name: descriptor.server_name,
        }))
    }

    async fn register_finish(&self, request: RegisterFinish) -> Result<(), InternalRpcError> {
        let db = self.ctx.get(DATABASE);
        if identity_exists(db).await.map_err(internal_err)? {
            return Err(InternalRpcError::NotReady);
        }
        match request {
            RegisterFinish::BootstrapNewUser {
                username,
                server_name,
            } => register_bootstrap(self.ctx.clone(), username, server_name).await,
            RegisterFinish::AddDevice { bundle } => {
                register_add_device(self.ctx.clone(), bundle).await
            }
        }
    }

    async fn new_device_bundle(
        &self,
        can_issue: bool,
        expiry: Timestamp,
    ) -> Result<NewDeviceBundle, InternalRpcError> {
        let db = self.ctx.get(DATABASE);
        let identity = Identity::load(db).await.map_err(internal_err)?;
        let issuer_can_issue = identity
            .cert_chain
            .0
            .iter()
            .find(|cert| cert.pk == identity.device_secret.public())
            .map(|cert| cert.can_issue)
            .unwrap_or(false);
        if !issuer_can_issue {
            return Err(InternalRpcError::AccessDenied);
        }
        let new_secret = DeviceSecret::random();
        let cert = identity
            .device_secret
            .issue_certificate(&new_secret.public(), expiry, can_issue);
        let mut chain = identity.cert_chain.clone();
        chain.0.push(cert);
        let bundle = BundleInner {
            username: identity.username,
            device_secret: new_secret,
            cert_chain: chain,
        };
        let encoded = bcs::to_bytes(&bundle).map_err(internal_err)?;
        Ok(NewDeviceBundle(Bytes::from(encoded)))
    }

    async fn dm_send(
        &self,
        peer: UserName,
        mime: smol_str::SmolStr,
        body: Bytes,
    ) -> Result<i64, InternalRpcError> {
        let db = self.ctx.get(DATABASE);
        let identity = Identity::load(db)
            .await
            .map_err(|_| InternalRpcError::NotReady)?;
        let id = queue_dm(db, &identity.username, &peer, &mime, &body)
            .await
            .map_err(internal_err)?;
        DbNotify::touch();
        Ok(id)
    }

    async fn group_create(&self, server: ServerName) -> Result<GroupId, InternalRpcError> {
        let db = self.ctx.get(DATABASE);
        if !identity_exists(db).await.map_err(internal_err)? {
            return Err(InternalRpcError::NotReady);
        }
        create_group(&self.ctx, server).await.map_err(internal_err)
    }

    async fn own_server(&self) -> Result<ServerName, InternalRpcError> {
        let db = self.ctx.get(DATABASE);
        let identity = Identity::load(db).await.map_err(internal_err)?;
        identity
            .server_name
            .ok_or_else(|| InternalRpcError::Other("server name not available".into()))
    }

    async fn group_invite(&self, group: GroupId, username: UserName) -> Result<(), InternalRpcError> {
        let db = self.ctx.get(DATABASE);
        if !identity_exists(db).await.map_err(internal_err)? {
            return Err(InternalRpcError::NotReady);
        }
        invite(&self.ctx, group, username).await.map_err(internal_err)
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
        let id = queue_group_message(db, &group, &identity.username, &mime, &body)
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
            "SELECT id, sender_username, mime, body, received_at \
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
        for (id, sender_username, mime, body, received_at) in rows {
            let sender = UserName::parse(sender_username).map_err(internal_err)?;
            let direction = if sender == identity.username {
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
                username: member.username,
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

    async fn add_contact(&self, username: UserName, init_msg: String) -> Result<(), InternalRpcError> {
        let dir = self.ctx.get(DIR_CLIENT);
        if dir
            .get_user_descriptor(&username)
            .await
            .map_err(internal_err)?
            .is_none()
        {
            return Err(InternalRpcError::Other("username not found".into()));
        }
        self.dm_send(username, SmolStr::new("text/plain"), Bytes::from(init_msg))
            .await
            .map(|_| ())
    }

    async fn dm_history(
        &self,
        peer: UserName,
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
            "SELECT id, sender_username, mime, body, received_at \
             FROM dm_messages \
             WHERE peer_username = ? AND id <= ? AND id >= ? \
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
        for (id, sender_username, mime, body, received_at) in rows {
            let sender = UserName::parse(sender_username).map_err(internal_err)?;
            let direction = if sender == identity.username {
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

    async fn all_peers(&self) -> Result<BTreeMap<UserName, DmMessage>, InternalRpcError> {
        let db = self.ctx.get(DATABASE);
        let identity = Identity::load(db)
            .await
            .map_err(|_| InternalRpcError::NotReady)?;
        let rows = sqlx::query_as::<_, (i64, String, String, String, Vec<u8>, Option<i64>)>(
            "SELECT id, peer_username, sender_username, mime, body, received_at \
             FROM dm_messages \
             ORDER BY id DESC",
        )
        .fetch_all(db)
        .await
        .map_err(internal_err)?;
        let mut out = BTreeMap::new();
        for (id, peer_username, sender_username, mime, body, received_at) in rows {
            let peer = UserName::parse(peer_username).map_err(internal_err)?;
            if out.contains_key(&peer) {
                continue;
            }
            let sender = UserName::parse(sender_username).map_err(internal_err)?;
            let direction = if sender == identity.username {
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
        if !out.contains_key(&identity.username) {
            out.insert(
                identity.username.clone(),
                DmMessage {
                    id: 0,
                    peer: identity.username.clone(),
                    sender: identity.username,
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
    username: UserName,
    server_name: ServerName,
) -> Result<(), InternalRpcError> {
    let dir = ctx.get(DIR_CLIENT);
    if dir
        .get_user_descriptor(&username)
        .await
        .map_err(internal_err)?
        .is_some()
    {
        return Err(InternalRpcError::Other("username already exists".into()));
    }
    let device_secret = DeviceSecret::random();
    let root_cert = device_secret.self_signed(Timestamp(u64::MAX), true);
    let cert_chain = CertificateChain(vec![root_cert.clone()]);
    let user_descriptor = UserDescriptor {
        server_name: server_name.clone(),
        root_cert_hash: root_cert.pk.bcs_hash(),
    };
    dir.add_owner(
        &username,
        device_secret.public().signing_public(),
        &device_secret,
    )
    .await
    .map_err(internal_err)?;
    dir.insert_user_descriptor(&username, &user_descriptor, &device_secret)
        .await
        .map_err(internal_err)?;

    let server = server_from_name(&ctx, &server_name).await?;
    let auth = device_auth(&server, &username, &cert_chain).await?;
    let medium_sk = register_medium_key(&server, auth, &device_secret).await?;

    persist_identity(
        ctx.get(DATABASE),
        username,
        server_name,
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
    let user_descriptor = dir
        .get_user_descriptor(&bundle.username)
        .await
        .map_err(internal_err)?
        .ok_or_else(|| InternalRpcError::Other("username not found".into()))?;
    bundle
        .cert_chain
        .verify(user_descriptor.root_cert_hash)
        .map_err(internal_err)?;
    let server = server_from_name(&ctx, &user_descriptor.server_name).await?;
    let auth = device_auth(&server, &bundle.username, &bundle.cert_chain).await?;
    let medium_sk = register_medium_key(&server, auth, &bundle.device_secret).await?;
    persist_identity(
        ctx.get(DATABASE),
        bundle.username,
        user_descriptor.server_name.clone(),
        bundle.device_secret,
        bundle.cert_chain,
        medium_sk,
    )
    .await?;
    DbNotify::touch();
    Ok(())
}

async fn server_from_name(
    ctx: &AnyCtx<Config>,
    server_name: &ServerName,
) -> Result<Arc<ServerClient>, InternalRpcError> {
    let dir = ctx.get(DIR_CLIENT);
    let descriptor = dir
        .get_server_descriptor(server_name)
        .await
        .map_err(internal_err)?
        .ok_or_else(|| InternalRpcError::Other("server not found".into()))?;
    let _ = descriptor;
    get_server_client(ctx, server_name)
        .await
        .map_err(internal_err)
}

async fn device_auth(
    server: &ServerClient,
    username: &UserName,
    cert_chain: &CertificateChain,
) -> Result<AuthToken, InternalRpcError> {
    server
        .v1_device_auth(username.clone(), cert_chain.clone())
        .await
        .map_err(internal_err)?
        .map_err(|err| InternalRpcError::Other(err.to_string()))
}

async fn register_medium_key(
    server: &ServerClient,
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
    server
        .v1_device_add_medium_pk(auth, signed)
        .await
        .map_err(internal_err)?
        .map_err(|err| InternalRpcError::Other(err.to_string()))?;
    Ok(medium_sk)
}

async fn persist_identity(
    db: &sqlx::SqlitePool,
    username: UserName,
    server_name: ServerName,
    device_secret: DeviceSecret,
    cert_chain: CertificateChain,
    medium_sk: DhSecret,
) -> Result<(), InternalRpcError> {
    sqlx::query(
        "INSERT INTO client_identity \
         (id, username, server_name, device_secret, cert_chain, medium_sk_current, medium_sk_prev) \
         VALUES (1, ?, ?, ?, ?, ?, ?)",
    )
    .bind(username.as_str())
    .bind(server_name.as_str())
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
    username: UserName,
    device_secret: DeviceSecret,
    cert_chain: CertificateChain,
}

fn internal_err(err: impl std::fmt::Display) -> InternalRpcError {
    InternalRpcError::Other(err.to_string())
}
