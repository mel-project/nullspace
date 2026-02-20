use anyctx::AnyCtx;
use async_channel::Receiver as AsyncReceiver;
use async_trait::async_trait;
use bytes::Bytes;
use nanorpc::nanorpc_derive;
use nullspace_crypt::dh::DhSecret;
use nullspace_crypt::hash::Hash;
use nullspace_crypt::signing::{Signable, Signature};
use nullspace_structs::certificate::DeviceSecret;
use nullspace_structs::event::EventPayload;
use nullspace_structs::fragment::Attachment;
use nullspace_structs::group::{GroupId, GroupInviteMsg};
use nullspace_structs::profile::UserProfile;
use nullspace_structs::server::{
    AuthToken, DeviceAuthRequest, ServerClient, ServerName, SignedDeviceAuthRequest, SignedMediumPk,
};
use nullspace_structs::timestamp::{NanoTimestamp, Timestamp};
use nullspace_structs::username::UserName;
use serde::{Deserialize, Serialize};
use smol_str::SmolStr;
use std::path::PathBuf;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::Mutex as AsyncMutex;

use crate::attachments::{self, AttachmentStatus, store_attachment_root};
use crate::config::Config;
pub use crate::convo::{ConvoId, ConvoMessage, ConvoSummary, MessageContent, OutgoingMessage};
use crate::convo::{
    GroupRoster, accept_invite, create_group, invite, load_group, parse_convo_id, queue_message,
};
use crate::database::{DATABASE, DbNotify, identity_exists};
use crate::directory::DIR_CLIENT;
use crate::identity::Identity;
use crate::profile::get_profile;
use crate::provisioning::{self, HostProvisioning};
use crate::server::get_server_client;
use crate::user_info::get_user_info;

/// The internal JSON-RPC interface exposed by nullspace-client.
#[nanorpc_derive]
#[async_trait]
pub trait InternalProtocol {
    async fn next_event(&self) -> Event;
    async fn register_start(
        &self,
        username: UserName,
    ) -> Result<Option<RegisterStartInfo>, InternalRpcError>;
    async fn register_finish(&self, request: RegisterFinish) -> Result<(), InternalRpcError>;
    async fn provision_host_start(&self) -> Result<ProvisionHostStart, InternalRpcError>;
    async fn provision_host_status(
        &self,
        session_id: u64,
    ) -> Result<ProvisionHostStatus, InternalRpcError>;
    async fn provision_host_stop(&self, session_id: u64) -> Result<(), InternalRpcError>;
    async fn convo_list(&self) -> Result<Vec<ConvoSummary>, InternalRpcError>;
    async fn convo_history(
        &self,
        convo_id: ConvoId,
        before: Option<i64>,
        after: Option<i64>,
        limit: u16,
    ) -> Result<Vec<ConvoMessage>, InternalRpcError>;
    async fn convo_mark_read(
        &self,
        convo_id: ConvoId,
        up_to_id: i64,
    ) -> Result<(), InternalRpcError>;
    async fn convo_send(
        &self,
        convo_id: ConvoId,
        message: OutgoingMessage,
    ) -> Result<i64, InternalRpcError>;
    async fn convo_create_group(&self, server: ServerName) -> Result<ConvoId, InternalRpcError>;
    async fn own_server(&self) -> Result<ServerName, InternalRpcError>;
    async fn group_invite(
        &self,
        group: GroupId,
        username: UserName,
    ) -> Result<(), InternalRpcError>;
    async fn group_members(&self, group: GroupId) -> Result<Vec<GroupMember>, InternalRpcError>;
    async fn group_accept_invite(&self, dm_id: i64) -> Result<GroupId, InternalRpcError>;

    async fn attachment_upload(
        &self,
        absolute_path: PathBuf,
        mime: SmolStr,
    ) -> Result<i64, InternalRpcError>;
    async fn attachment_download(
        &self,
        attachment_id: nullspace_crypt::hash::Hash,
        save_dir: PathBuf,
    ) -> Result<Hash, InternalRpcError>;
    async fn attachment_status(
        &self,
        attachment_id: nullspace_crypt::hash::Hash,
    ) -> Result<AttachmentStatus, InternalRpcError>;

    async fn attachment_download_oneshot(
        &self,
        sender: UserName,
        attachment: Attachment,
        save_to: PathBuf,
    ) -> Result<(), InternalRpcError>;

    async fn own_username(&self) -> Result<UserName, InternalRpcError>;

    async fn own_profile_set(
        &self,
        display_name: Option<String>,
        avatar: Option<Attachment>,
    ) -> Result<(), InternalRpcError>;

    async fn user_details(&self, username: UserName) -> Result<UserDetails, InternalRpcError>;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Event {
    State {
        logged_in: bool,
    },
    ConvoUpdated {
        convo_id: ConvoId,
    },
    GroupUpdated {
        group: GroupId,
    },
    UploadProgress {
        id: i64,
        uploaded_size: u64,
        total_size: u64,
    },
    UploadDone {
        id: i64,
        root: Attachment,
    },
    UploadFailed {
        id: i64,
        error: String,
    },
    DownloadProgress {
        attachment_id: Hash,
        downloaded_size: u64,
        total_size: u64,
    },
    DownloadDone {
        attachment_id: Hash,
        absolute_path: PathBuf,
    },
    DownloadFailed {
        attachment_id: Hash,
        error: String,
    },
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
    AddDeviceByCode {
        username: UserName,
        code: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProvisionHostStart {
    pub session_id: u64,
    pub display_code: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProvisionHostStatus {
    pub phase: ProvisionHostPhase,
    pub display_code: String,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProvisionHostPhase {
    Pending,
    Completed,
    Failed,
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserDetails {
    pub username: UserName,
    pub display_name: Option<String>,
    pub avatar: Option<Attachment>,
    pub server_name: Option<ServerName>,
    pub common_groups: Vec<GroupId>,
    pub last_dm_message: Option<UserLastMessageSummary>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserLastMessageSummary {
    pub received_at: Option<NanoTimestamp>,
    pub direction: MessageDirection,
    pub preview: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageDirection {
    Incoming,
    Outgoing,
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
    events: Arc<AsyncMutex<AsyncReceiver<Event>>>,
    host_provisioning: Arc<HostProvisioning>,
}

impl InternalImpl {
    pub fn new(ctx: AnyCtx<Config>, events: AsyncReceiver<Event>) -> Self {
        Self {
            ctx,
            events: Arc::new(AsyncMutex::new(events)),
            host_provisioning: Arc::new(HostProvisioning::new()),
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
        let server_name = descriptor.server_name.clone();
        tracing::debug!(username = %username, server = %server_name, "register_start found");
        Ok(Some(RegisterStartInfo {
            username,
            server_name,
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
            RegisterFinish::AddDeviceByCode { username, code } => {
                provisioning::register_add_device_by_code(self.ctx.clone(), username, code).await
            }
        }
    }

    async fn provision_host_start(&self) -> Result<ProvisionHostStart, InternalRpcError> {
        self.host_provisioning.start(self.ctx.clone()).await
    }

    async fn provision_host_status(
        &self,
        session_id: u64,
    ) -> Result<ProvisionHostStatus, InternalRpcError> {
        self.host_provisioning.status(session_id).await
    }

    async fn provision_host_stop(&self, session_id: u64) -> Result<(), InternalRpcError> {
        self.host_provisioning.stop(session_id).await
    }

    async fn convo_list(&self) -> Result<Vec<ConvoSummary>, InternalRpcError> {
        let db = self.ctx.get(DATABASE);
        convo_list(db).await.map_err(internal_err)
    }

    async fn convo_history(
        &self,
        convo_id: ConvoId,
        before: Option<i64>,
        after: Option<i64>,
        limit: u16,
    ) -> Result<Vec<ConvoMessage>, InternalRpcError> {
        let db = self.ctx.get(DATABASE);
        convo_history(db, convo_id, before, after, limit)
            .await
            .map_err(internal_err)
    }

    async fn convo_send(
        &self,
        convo_id: ConvoId,
        message: OutgoingMessage,
    ) -> Result<i64, InternalRpcError> {
        let db = self.ctx.get(DATABASE);
        let identity = Identity::load(db)
            .await
            .map_err(|_| InternalRpcError::NotReady)?;
        let (mime, body) = match message {
            OutgoingMessage::PlainText(text) => ("text/plain".into(), Bytes::from(text)),
            OutgoingMessage::Attachment(root) => (
                SmolStr::new(Attachment::mime()),
                Bytes::from(serde_json::to_vec(&root).map_err(internal_err)?),
            ),
        };
        let mut conn = db.acquire().await.map_err(internal_err)?;
        let id = queue_message(&mut conn, &convo_id, &identity.username, &mime, &body)
            .await
            .map_err(internal_err)?;
        DbNotify::touch();
        Ok(id)
    }

    async fn convo_mark_read(
        &self,
        convo_id: ConvoId,
        up_to_id: i64,
    ) -> Result<(), InternalRpcError> {
        let db = self.ctx.get(DATABASE);
        let affected = mark_convo_read(db, convo_id, up_to_id)
            .await
            .map_err(internal_err)?;
        if affected > 0 {
            DbNotify::touch();
        }
        Ok(())
    }

    async fn convo_create_group(&self, server: ServerName) -> Result<ConvoId, InternalRpcError> {
        let db = self.ctx.get(DATABASE);
        if !identity_exists(db).await.map_err(internal_err)? {
            return Err(InternalRpcError::NotReady);
        }
        let group_id = create_group(&self.ctx, server)
            .await
            .map_err(internal_err)?;
        Ok(ConvoId::Group { group_id })
    }

    async fn own_server(&self) -> Result<ServerName, InternalRpcError> {
        let db = self.ctx.get(DATABASE);
        let identity = Identity::load(db).await.map_err(internal_err)?;
        identity
            .server_name
            .ok_or_else(|| InternalRpcError::Other("server name not available".into()))
    }

    async fn group_invite(
        &self,
        group: GroupId,
        username: UserName,
    ) -> Result<(), InternalRpcError> {
        let db = self.ctx.get(DATABASE);
        if !identity_exists(db).await.map_err(internal_err)? {
            return Err(InternalRpcError::NotReady);
        }
        invite(&self.ctx, group, username)
            .await
            .map_err(internal_err)
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
        let mut conn = db.acquire().await.map_err(internal_err)?;
        let roster =
            GroupRoster::load(&mut conn, group, group_record.descriptor.init_admin.clone())
                .await
                .map_err(internal_err)?;
        let members = roster.list(&mut conn).await.map_err(internal_err)?;
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
        tracing::debug!(invite_id = dm_id, "group_accept_invite called");
        let result = accept_invite(&self.ctx, dm_id).await;
        match &result {
            Ok(group_id) => {
                tracing::debug!(invite_id = dm_id, group_id = %group_id, "group_accept_invite ok");
            }
            Err(err) => {
                tracing::warn!(invite_id = dm_id, error = %err, "group_accept_invite failed");
            }
        }
        result.map_err(internal_err)
    }

    async fn attachment_upload(
        &self,
        absolute_path: PathBuf,
        mime: SmolStr,
    ) -> Result<i64, InternalRpcError> {
        attachments::attachment_upload(&self.ctx, absolute_path, mime)
            .await
            .map_err(map_anyhow_err)
    }

    async fn attachment_download(
        &self,
        attachment_id: nullspace_crypt::hash::Hash,
        save_dir: PathBuf,
    ) -> Result<Hash, InternalRpcError> {
        attachments::attachment_download(&self.ctx, attachment_id, save_dir)
            .await
            .map_err(map_anyhow_err)
    }

    async fn attachment_status(
        &self,
        attachment_id: nullspace_crypt::hash::Hash,
    ) -> Result<AttachmentStatus, InternalRpcError> {
        attachments::attachment_status(&self.ctx, attachment_id)
            .await
            .map_err(map_anyhow_err)
    }

    async fn attachment_download_oneshot(
        &self,
        sender: UserName,
        attachment: Attachment,
        save_to: PathBuf,
    ) -> Result<(), InternalRpcError> {
        attachments::attachment_download_oneshot(&self.ctx, sender, attachment, save_to)
            .await
            .map_err(map_anyhow_err)
    }

    async fn user_details(&self, username: UserName) -> Result<UserDetails, InternalRpcError> {
        let db = self.ctx.get(DATABASE);
        if !identity_exists(db).await.map_err(internal_err)? {
            return Err(InternalRpcError::NotReady);
        }
        let identity = Identity::load(db).await.map_err(internal_err)?;
        let profile = get_profile(&self.ctx, &username)
            .await
            .map_err(map_anyhow_err)?;
        if let Some(profile) = profile.as_ref()
            && let Some(avatar) = profile.avatar.as_ref()
        {
            let mut conn = db.acquire().await.map_err(internal_err)?;
            store_attachment_root(&mut conn, &username, avatar)
                .await
                .map_err(internal_err)?;
        }
        let user_info = get_user_info(&self.ctx, &username)
            .await
            .map_err(map_anyhow_err)?;

        let (display_name, avatar) = match profile {
            Some(profile) => (profile.display_name, profile.avatar),
            None => (None, None),
        };

        let common_groups = common_groups(db, &identity.username, &username)
            .await
            .map_err(internal_err)?;
        let last_dm_message = last_dm_message_summary(db, &identity.username, &username)
            .await
            .map_err(internal_err)?;

        Ok(UserDetails {
            username,
            display_name,
            avatar,
            server_name: Some(user_info.server_name.clone()),
            common_groups,
            last_dm_message,
        })
    }

    async fn own_username(&self) -> Result<UserName, InternalRpcError> {
        let db = self.ctx.get(DATABASE);
        let identity = Identity::load(db).await.map_err(internal_err)?;
        Ok(identity.username)
    }

    async fn own_profile_set(
        &self,
        display_name: Option<String>,
        avatar: Option<Attachment>,
    ) -> Result<(), InternalRpcError> {
        let db = self.ctx.get(DATABASE);
        if !identity_exists(db).await.map_err(internal_err)? {
            return Err(InternalRpcError::NotReady);
        }
        let identity = Identity::load(db).await.map_err(internal_err)?;
        let Some(server_name) = identity.server_name.clone() else {
            return Err(InternalRpcError::Other("server name not available".into()));
        };
        let server = server_from_name(&self.ctx, &server_name).await?;

        let created = Timestamp::now();
        let mut profile = UserProfile {
            display_name,
            avatar,
            created,
            signature: Signature::from_bytes([0u8; 64]),
        };
        profile.sign(&identity.device_secret);

        server
            .v1_profile_set(identity.username, profile)
            .await
            .map_err(internal_err)?
            .map_err(|err| InternalRpcError::Other(err.to_string()))?;
        Ok(())
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
    let server = server_from_name(&ctx, &server_name).await?;
    let device_secret = DeviceSecret::random();
    let nonce_bind = provisioning::next_nonce(0);
    dir.bind_server(&username, &server_name, nonce_bind, &device_secret)
        .await
        .map_err(internal_err)?;
    let auth = authenticate_device(&server, &username, &device_secret).await?;
    let medium_sk = register_medium_key(&server, auth, &device_secret).await?;

    persist_identity(
        ctx.get(DATABASE),
        username,
        server_name,
        device_secret,
        medium_sk,
    )
    .await?;
    DbNotify::touch();
    Ok(())
}

pub(crate) async fn server_from_name(
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

pub(crate) async fn register_medium_key(
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

pub(crate) async fn persist_identity(
    db: &sqlx::SqlitePool,
    username: UserName,
    server_name: ServerName,
    device_secret: DeviceSecret,
    medium_sk: DhSecret,
) -> Result<(), InternalRpcError> {
    sqlx::query(
        "INSERT INTO client_identity \
         (id, username, server_name, device_secret, medium_sk_current, medium_sk_prev) \
         VALUES (1, ?, ?, ?, ?, ?)",
    )
    .bind(username.as_str())
    .bind(server_name.as_str())
    .bind(bcs::to_bytes(&device_secret).map_err(internal_err)?)
    .bind(bcs::to_bytes(&medium_sk).map_err(internal_err)?)
    .bind(bcs::to_bytes(&medium_sk).map_err(internal_err)?)
    .execute(db)
    .await
    .map_err(internal_err)?;
    Ok(())
}

pub(crate) async fn authenticate_device(
    server: &ServerClient,
    username: &UserName,
    device_secret: &DeviceSecret,
) -> Result<AuthToken, InternalRpcError> {
    let device_pk = device_secret.public().signing_public();
    let challenge = server
        .v1_device_auth_start(username.clone(), device_pk)
        .await
        .map_err(internal_err)?
        .map_err(|err| InternalRpcError::Other(err.to_string()))?;
    let mut request = SignedDeviceAuthRequest {
        request: DeviceAuthRequest {
            username: username.clone(),
            device_pk,
            challenge: challenge.challenge,
        },
        signature: Signature::from_bytes([0u8; 64]),
    };
    request.sign(device_secret);
    server
        .v1_device_auth_finish(request)
        .await
        .map_err(internal_err)?
        .map_err(|err| InternalRpcError::Other(err.to_string()))
}

pub(crate) fn internal_err(err: impl std::fmt::Display) -> InternalRpcError {
    InternalRpcError::Other(err.to_string())
}

fn map_anyhow_err(err: anyhow::Error) -> InternalRpcError {
    if let Some(rpc_err) = err.downcast_ref::<InternalRpcError>() {
        rpc_err.clone()
    } else {
        InternalRpcError::Other(err.to_string())
    }
}

async fn convo_list(db: &sqlx::SqlitePool) -> anyhow::Result<Vec<ConvoSummary>> {
    let rows = sqlx::query_as::<
        _,
        (
            String,
            String,
            i64,
            i64,
            Option<i64>,
            Option<String>,
            Option<String>,
            Option<Vec<u8>>,
            Option<i64>,
            Option<i64>,
            Option<String>,
        ),
    >(
        "SELECT c.convo_type, c.convo_counterparty, c.created_at, \
                (SELECT COUNT(*) FROM convo_messages um \
                 JOIN client_identity ci ON ci.id = 1 \
                 LEFT JOIN message_reads mr ON mr.message_id = um.id \
                 WHERE um.convo_id = c.id \
                   AND um.received_at IS NOT NULL \
                   AND um.sender_username != ci.username \
                   AND mr.message_id IS NULL) AS unread_count, \
                m.id, m.sender_username, m.mime, m.body, m.received_at, mr.read_at, m.send_error \
         FROM convos c \
         LEFT JOIN convo_messages m \
           ON m.id = (SELECT MAX(id) FROM convo_messages WHERE convo_id = c.id) \
         LEFT JOIN message_reads mr ON mr.message_id = m.id \
         ORDER BY (m.received_at IS NULL) DESC, m.received_at DESC, c.created_at DESC, c.id DESC",
    )
    .fetch_all(db)
    .await?;
    let mut out = Vec::with_capacity(rows.len());
    for (
        convo_type,
        counterparty,
        _created_at,
        unread_count,
        msg_id,
        sender_username,
        mime,
        body,
        received_at,
        read_at,
        send_error,
    ) in rows
    {
        let convo_id = parse_convo_id(&convo_type, &counterparty)
            .ok_or_else(|| anyhow::anyhow!("invalid convo row"))?;
        let last_message = match (msg_id, sender_username, mime, body) {
            (Some(id), Some(sender_username), Some(mime), Some(body)) => {
                let sender = UserName::parse(sender_username)?;
                let body = (decode_message_content(db, id, &sender, &mime, &body).await).ok();
                body.map(|body| ConvoMessage {
                    id,
                    convo_id: convo_id.clone(),
                    sender,
                    body,
                    send_error,
                    received_at: received_at.map(|ts| NanoTimestamp(ts as u64)),
                    read_at: read_at.map(|ts| NanoTimestamp(ts as u64)),
                })
            }
            _ => None,
        };
        out.push(ConvoSummary {
            convo_id,
            last_message,
            unread_count: unread_count as u64,
        });
    }
    Ok(out)
}

async fn convo_history(
    db: &sqlx::SqlitePool,
    convo_id: ConvoId,
    before: Option<i64>,
    after: Option<i64>,
    limit: u16,
) -> anyhow::Result<Vec<ConvoMessage>> {
    let before = before.unwrap_or(i64::MAX);
    let after = after.unwrap_or(i64::MIN);
    let convo_type = convo_id.convo_type();
    let counterparty = convo_id.counterparty();
    let mut rows = sqlx::query_as::<
        _,
        (
            i64,
            String,
            String,
            Vec<u8>,
            Option<i64>,
            Option<i64>,
            Option<String>,
        ),
    >(
        "SELECT m.id, m.sender_username, m.mime, m.body, m.received_at, mr.read_at, m.send_error \
         FROM convo_messages m \
         JOIN convos c ON m.convo_id = c.id \
         LEFT JOIN message_reads mr ON mr.message_id = m.id \
         WHERE c.convo_type = ? AND c.convo_counterparty = ? AND m.id <= ? AND m.id >= ? \
         ORDER BY m.id DESC \
         LIMIT ?",
    )
    .bind(convo_type)
    .bind(counterparty)
    .bind(before)
    .bind(after)
    .bind(limit as i64)
    .fetch_all(db)
    .await?;
    rows.reverse();
    let mut out = Vec::with_capacity(rows.len());
    for (id, sender_username, mime, body, received_at, read_at, send_error) in rows {
        let sender = UserName::parse(sender_username)?;
        let body = match decode_message_content(db, id, &sender, &mime, &body).await {
            Ok(body) => body,
            Err(_) => {
                continue;
            }
        };
        out.push(ConvoMessage {
            id,
            convo_id: convo_id.clone(),
            sender,
            body,
            send_error,
            received_at: received_at.map(|ts| NanoTimestamp(ts as u64)),
            read_at: read_at.map(|ts| NanoTimestamp(ts as u64)),
        });
    }
    Ok(out)
}

async fn mark_convo_read(
    db: &sqlx::SqlitePool,
    convo_id: ConvoId,
    up_to_id: i64,
) -> anyhow::Result<u64> {
    let read_at = NanoTimestamp::now().0 as i64;
    let affected = sqlx::query(
        "INSERT OR IGNORE INTO message_reads (message_id, read_at) \
         SELECT m.id, ? \
         FROM convo_messages m \
         JOIN convos c ON m.convo_id = c.id \
         JOIN client_identity ci ON ci.id = 1 \
         WHERE c.convo_type = ? \
           AND c.convo_counterparty = ? \
           AND m.id <= ? \
           AND m.received_at IS NOT NULL \
           AND m.sender_username != ci.username",
    )
    .bind(read_at)
    .bind(convo_id.convo_type())
    .bind(convo_id.counterparty())
    .bind(up_to_id)
    .execute(db)
    .await?
    .rows_affected();
    Ok(affected)
}

async fn common_groups(
    db: &sqlx::SqlitePool,
    local_username: &UserName,
    other_username: &UserName,
) -> anyhow::Result<Vec<GroupId>> {
    let rows = sqlx::query_scalar::<_, Vec<u8>>(
        "SELECT DISTINCT gm_other.group_id \
         FROM group_members gm_other \
         JOIN group_members gm_self ON gm_self.group_id = gm_other.group_id \
         WHERE gm_other.username = ? AND gm_self.username = ? \
           AND gm_other.status IN ('pending', 'accepted') \
           AND gm_self.status IN ('pending', 'accepted') \
         ORDER BY gm_other.group_id",
    )
    .bind(other_username.as_str())
    .bind(local_username.as_str())
    .fetch_all(db)
    .await?;

    let mut out = Vec::new();
    for bytes in rows {
        if bytes.len() != 32 {
            tracing::warn!(len = bytes.len(), "invalid group id bytes");
            continue;
        }
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&bytes);
        out.push(GroupId::from_bytes(buf));
    }
    Ok(out)
}

async fn last_dm_message_summary(
    db: &sqlx::SqlitePool,
    local_username: &UserName,
    other_username: &UserName,
) -> anyhow::Result<Option<UserLastMessageSummary>> {
    let convo_id = ConvoId::Direct {
        peer: other_username.clone(),
    };
    let convo_type = convo_id.convo_type();
    let counterparty = convo_id.counterparty();
    let received_at = sqlx::query_scalar::<_, Option<i64>>(
        "SELECT m.received_at \
         FROM convo_messages m \
         JOIN convos c ON m.convo_id = c.id \
         WHERE c.convo_type = ? AND c.convo_counterparty = ? AND m.sender_username != ? \
         ORDER BY m.id DESC \
         LIMIT 1",
    )
    .bind(convo_type)
    .bind(counterparty)
    .bind(local_username.as_str())
    .fetch_optional(db)
    .await?
    .flatten();

    let Some(received_at) = received_at else {
        return Ok(None);
    };
    Ok(Some(UserLastMessageSummary {
        received_at: Some(NanoTimestamp(received_at as u64)),
        direction: MessageDirection::Incoming,
        preview: String::new(),
    }))
}

async fn decode_message_content(
    db: &sqlx::SqlitePool,
    message_id: i64,
    sender: &UserName,
    mime: &str,
    body: &[u8],
) -> anyhow::Result<MessageContent> {
    match mime {
        "text/plain" => Ok(MessageContent::PlainText(
            String::from_utf8_lossy(body).to_string(),
        )),
        // Keep older stored/server markdown messages readable as plain text.
        "text/markdown" => Ok(MessageContent::PlainText(
            String::from_utf8_lossy(body).to_string(),
        )),
        mime if mime == GroupInviteMsg::mime() => Ok(MessageContent::GroupInvite {
            invite_id: message_id,
        }),
        mime if mime == Attachment::mime() => {
            let root = match serde_json::from_slice::<Attachment>(body) {
                Ok(root) => root,
                Err(err) => {
                    tracing::warn!(
                        message_id,
                        error = %err,
                        "failed to decode attachment root"
                    );
                    return Err(anyhow::anyhow!("invalid attachment root"));
                }
            };
            let id = store_attachment_root(&mut *db.acquire().await?, sender, &root).await?;
            Ok(MessageContent::Attachment {
                id,
                size: root.total_size(),
                mime: root.mime,
                filename: root.filename.clone(),
            })
        }
        _ => Ok(MessageContent::PlainText("Unsupported message".to_string())),
    }
}
