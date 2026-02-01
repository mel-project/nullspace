use anyctx::AnyCtx;
use async_channel::Receiver as AsyncReceiver;
use async_trait::async_trait;
use bytes::Bytes;
use nanorpc::nanorpc_derive;
use nullspace_crypt::dh::DhSecret;
use nullspace_crypt::hash::{BcsHashExt, Hash};
use nullspace_crypt::signing::{Signable, Signature};
use nullspace_structs::certificate::{CertificateChain, DeviceSecret};
use nullspace_structs::event::EventPayload;
use nullspace_structs::fragment::FragmentRoot;
use nullspace_structs::group::{GroupId, GroupInviteMsg};
use nullspace_structs::server::{AuthToken, ServerClient, ServerName, SignedMediumPk};
use nullspace_structs::timestamp::{NanoTimestamp, Timestamp};
use nullspace_structs::username::{UserDescriptor, UserName};
use serde::{Deserialize, Serialize};
use serde_with::base64::{Base64, UrlSafe};
use serde_with::formats::Unpadded;
use serde_with::{FromInto, IfIsHumanReadable, serde_as};
use smol_str::SmolStr;
use std::path::PathBuf;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::Mutex;

use crate::attachments::{self, AttachmentStatus, store_attachment_root};
use crate::config::Config;
pub use crate::convo::{ConvoId, ConvoMessage, ConvoSummary, MessageContent};
use crate::convo::{
    GroupRoster, accept_invite, create_group, invite, load_group, parse_convo_id, queue_message,
};
use crate::database::{DATABASE, DbNotify, identity_exists};
use crate::directory::DIR_CLIENT;
use crate::identity::Identity;
use crate::server::get_server_client;

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
    async fn new_device_bundle(
        &self,
        can_issue: bool,
        expiry: Timestamp,
    ) -> Result<NewDeviceBundle, InternalRpcError>;
    async fn convo_list(&self) -> Result<Vec<ConvoSummary>, InternalRpcError>;
    async fn convo_history(
        &self,
        convo_id: ConvoId,
        before: Option<i64>,
        after: Option<i64>,
        limit: u16,
    ) -> Result<Vec<ConvoMessage>, InternalRpcError>;
    async fn convo_send(
        &self,
        convo_id: ConvoId,
        mime: SmolStr,
        body: Bytes,
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
        root: FragmentRoot,
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
    AddDevice {
        bundle: NewDeviceBundle,
    },
}

#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NewDeviceBundle(
    #[serde_as(as = "IfIsHumanReadable<Base64<UrlSafe, Unpadded>, FromInto<Vec<u8>>>")] pub Bytes,
);

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
        let issuer_cert = identity.cert_chain.last_device();
        let issuer_can_issue =
            issuer_cert.pk == identity.device_secret.public() && issuer_cert.can_issue;
        if !issuer_can_issue {
            return Err(InternalRpcError::AccessDenied);
        }
        let new_secret = DeviceSecret::random();
        let cert =
            identity
                .device_secret
                .issue_certificate(&new_secret.public(), expiry, can_issue);
        let mut ancestors = identity.cert_chain.ancestors.clone();
        ancestors.push(identity.cert_chain.this.clone());
        let chain = CertificateChain {
            ancestors,
            this: cert,
        };
        let bundle = BundleInner {
            username: identity.username,
            device_secret: new_secret,
            cert_chain: chain,
        };
        let encoded = bcs::to_bytes(&bundle).map_err(internal_err)?;
        Ok(NewDeviceBundle(Bytes::from(encoded)))
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
        mime: smol_str::SmolStr,
        body: Bytes,
    ) -> Result<i64, InternalRpcError> {
        let db = self.ctx.get(DATABASE);
        let identity = Identity::load(db)
            .await
            .map_err(|_| InternalRpcError::NotReady)?;
        let mut conn = db.acquire().await.map_err(internal_err)?;
        let id = queue_message(&mut *conn, &convo_id, &identity.username, &mime, &body)
            .await
            .map_err(internal_err)?;
        DbNotify::touch();
        Ok(id)
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
        let roster = GroupRoster::load(
            &mut *conn,
            group,
            group_record.descriptor.init_admin.clone(),
        )
        .await
        .map_err(internal_err)?;
        let members = roster.list(&mut *conn).await.map_err(internal_err)?;
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
    let root_cert = device_secret.self_signed(Timestamp(u64::MAX), true);
    let cert_chain = CertificateChain {
        ancestors: Vec::new(),
        this: root_cert.clone(),
    };
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

pub(crate) async fn device_auth(
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
            Option<i64>,
            Option<String>,
            Option<String>,
            Option<Vec<u8>>,
            Option<i64>,
            Option<String>,
        ),
    >(
        "SELECT c.convo_type, c.convo_counterparty, c.created_at, \
                m.id, m.sender_username, m.mime, m.body, m.received_at, m.send_error \
         FROM convos c \
         LEFT JOIN convo_messages m \
           ON m.id = (SELECT MAX(id) FROM convo_messages WHERE convo_id = c.id) \
         ORDER BY (m.received_at IS NULL) DESC, m.received_at DESC, c.created_at DESC, c.id DESC",
    )
    .fetch_all(db)
    .await?;
    let mut out = Vec::with_capacity(rows.len());
    for (
        convo_type,
        counterparty,
        _created_at,
        msg_id,
        sender_username,
        mime,
        body,
        received_at,
        send_error,
    ) in rows
    {
        let convo_id = parse_convo_id(&convo_type, &counterparty)
            .ok_or_else(|| anyhow::anyhow!("invalid convo row"))?;
        let last_message = match (msg_id, sender_username, mime, body) {
            (Some(id), Some(sender_username), Some(mime), Some(body)) => {
                let sender = UserName::parse(sender_username)?;
                let body = match decode_message_content(db, id, &sender, &mime, &body).await {
                    Ok(body) => Some(body),
                    Err(_) => None,
                };
                body.map(|body| ConvoMessage {
                    id,
                    convo_id: convo_id.clone(),
                    sender,
                    body,
                    send_error,
                    received_at: received_at.map(|ts| NanoTimestamp(ts as u64)),
                })
            }
            _ => None,
        };
        out.push(ConvoSummary {
            convo_id,
            last_message,
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
    let mut rows =
        sqlx::query_as::<_, (i64, String, String, Vec<u8>, Option<i64>, Option<String>)>(
            "SELECT m.id, m.sender_username, m.mime, m.body, m.received_at, m.send_error \
         FROM convo_messages m \
         JOIN convos c ON m.convo_id = c.id \
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
    for (id, sender_username, mime, body, received_at, send_error) in rows {
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
        });
    }
    Ok(out)
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
        "text/markdown" => Ok(MessageContent::Markdown(
            String::from_utf8_lossy(body).to_string(),
        )),
        mime if mime == GroupInviteMsg::mime() => Ok(MessageContent::GroupInvite {
            invite_id: message_id,
        }),
        mime if mime == FragmentRoot::mime() => {
            let root = match serde_json::from_slice::<FragmentRoot>(body) {
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
