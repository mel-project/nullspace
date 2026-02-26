use anyctx::AnyCtx;
use async_channel::Receiver as AsyncReceiver;
use async_trait::async_trait;
use bytes::Bytes;
use nanorpc::nanorpc_derive;
use nullspace_crypt::dh::DhSecret;
use nullspace_crypt::hash::Hash;
use nullspace_crypt::signing::{Signable, Signature};
use nullspace_structs::certificate::DeviceSecret;
use nullspace_structs::event::{
    MessageAttachment, MessageAttachmentData, MessagePayload, MessageText, TAG_MESSAGE,
};
use nullspace_structs::fragment::{Attachment, ImageAttachment};
use nullspace_structs::group::GroupId;
use nullspace_structs::profile::UserProfile;
use nullspace_structs::server::{
    AuthToken, DeviceAuthRequest, MailboxKey, ServerClient, ServerName, SignedDeviceAuthRequest,
    SignedMediumPk,
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
use crate::convo::{parse_convo_id, queue_message};
use crate::database::{DATABASE, DbNotify, identity_exists};
use crate::directory::DIR_CLIENT;
use crate::identity::Identity;
use crate::profile::get_profile;
use crate::provisioning::{self, HostProvisioning};
use crate::server::get_server_client;
use crate::user_info::get_user_info;

/// The client's full RPC interface.
///
/// Every method here is available through the [`InternalClient`] handle
/// returned by [`Client::rpc`](crate::Client::rpc).  The `nanorpc_derive`
/// macro generates a matching `InternalClient` struct with an identical
/// method signature, serializing each call as JSON-RPC over the in-process
/// transport.
///
/// # Design principles
///
/// - **No crypto leaks.**  Frontends never see encryption keys, device
///   secrets, or raw protocol blobs.  All types exposed here are simple,
///   serializable value objects.
/// - **Database-driven events.**  State changes flow through SQLite.
///   Background workers write to the DB, the event loop detects changes,
///   and the frontend observes them via [`next_event`](Self::next_event).
/// - **Fire-and-forget sends.**  [`convo_send`](Self::convo_send) enqueues
///   the message locally and returns immediately; the background send loop
///   handles encryption, delivery, and retries.
/// - **Idempotent reads.**  List/history/status calls are pure DB reads and
///   can be called at any frequency without side effects.
#[nanorpc_derive]
#[async_trait]
pub trait InternalProtocol {
    /// Blocks until the next push event is available.
    ///
    /// This is the primary mechanism for frontends to react to state
    /// changes.  Typical usage is a dedicated background task that calls
    /// this in a loop and dispatches each [`Event`] to the UI layer.
    ///
    /// The call will block (async) indefinitely until an event is ready.
    /// If the internal event channel closes, returns
    /// `Event::State { logged_in: false }`.
    async fn next_event(&self) -> Event;

    /// Looks up a username in the directory.
    ///
    /// Returns `Ok(Some(info))` if the user exists (with the server they
    /// are registered on), `Ok(None)` if the username is not found, or an
    /// error on directory failure.
    ///
    /// This is the first step of the registration flow -- the frontend
    /// calls this to check whether a username exists before proceeding to
    /// [`register_finish`](Self::register_finish).
    async fn register_start(
        &self,
        username: UserName,
    ) -> Result<Option<RegisterStartInfo>, InternalRpcError>;

    /// Completes registration and persists the new identity.
    ///
    /// Two registration modes are supported:
    ///
    /// - [`RegisterFinish::BootstrapNewUser`] -- creates a brand-new user,
    ///   binding the username to a server in the directory and generating a
    ///   fresh device secret and medium-term key.
    /// - [`RegisterFinish::AddDeviceByCode`] -- adds this device to an
    ///   existing user account via a pairing code obtained from
    ///   [`provision_host_start`](Self::provision_host_start) on another
    ///   device.
    ///
    /// On success the background workers start automatically (key rotation,
    /// send/receive loops), and a `State { logged_in: true }` event is
    /// emitted.
    async fn register_finish(&self, request: RegisterFinish) -> Result<(), InternalRpcError>;

    /// Begins a device-provisioning session on the *host* (existing) device.
    ///
    /// Returns a session ID and a human-readable pairing code that the user
    /// enters on the new device.  The session runs in the background; poll
    /// its progress with
    /// [`provision_host_status`](Self::provision_host_status).
    async fn provision_host_start(&self) -> Result<ProvisionHostStart, InternalRpcError>;

    /// Queries the current state of a provisioning session.
    async fn provision_host_status(
        &self,
        session_id: u64,
    ) -> Result<ProvisionHostStatus, InternalRpcError>;

    /// Cancels an in-progress provisioning session.
    async fn provision_host_stop(&self, session_id: u64) -> Result<(), InternalRpcError>;

    /// Lists all conversations (DMs and groups) with their most recent
    /// message and unread count.
    ///
    /// Results are ordered by last activity (most recent first).
    async fn convo_list(&self) -> Result<Vec<ConvoSummary>, InternalRpcError>;

    /// Fetches paginated message history for a conversation.
    ///
    /// - `before` / `after` -- optional message-ID boundaries for
    ///   cursor-based pagination.
    /// - `limit` -- maximum number of messages to return.
    ///
    /// Messages are returned in chronological order (oldest first).
    async fn convo_history(
        &self,
        convo_id: ConvoId,
        before: Option<i64>,
        after: Option<i64>,
        limit: u16,
    ) -> Result<Vec<ConvoMessage>, InternalRpcError>;

    /// Marks all messages up to (and including) `up_to_id` as read.
    ///
    /// Triggers a [`Event::ConvoUpdated`] if any messages were newly marked.
    async fn convo_mark_read(
        &self,
        convo_id: ConvoId,
        up_to_id: i64,
    ) -> Result<(), InternalRpcError>;

    /// Enqueues a message for delivery and returns its local ID.
    ///
    /// The message is inserted into the local database immediately with a
    /// `received_at` of `None` (pending).  The background send loop picks
    /// it up, encrypts it per-recipient, and posts it to the server.  On
    /// success `received_at` is set and a [`Event::ConvoUpdated`] is
    /// emitted; on failure the `send_error` field is populated.
    async fn convo_send(
        &self,
        convo_id: ConvoId,
        message: OutgoingMessage,
    ) -> Result<i64, InternalRpcError>;

    /// Creates a new group on the given server and returns its
    /// [`ConvoId`].
    ///
    /// The calling user becomes the group's initial administrator.
    async fn convo_create_group(&self, server: ServerName) -> Result<ConvoId, InternalRpcError>;

    /// Returns the server name this client's identity is registered on.
    async fn own_server(&self) -> Result<ServerName, InternalRpcError>;

    /// Invites a user to a group.
    ///
    /// The invitation is delivered as a special DM to the target user,
    /// who can accept it with
    /// [`group_accept_invite`](Self::group_accept_invite).
    async fn group_invite(
        &self,
        group: GroupId,
        username: UserName,
    ) -> Result<(), InternalRpcError>;

    /// Returns the current membership roster for a group.
    async fn group_members(&self, group: GroupId) -> Result<Vec<GroupMember>, InternalRpcError>;

    /// Accepts a group invitation received as a DM.
    ///
    /// `dm_id` is the message ID of the invitation DM.  On success returns
    /// the [`GroupId`] of the joined group.
    async fn group_accept_invite(&self, dm_id: i64) -> Result<GroupId, InternalRpcError>;

    /// Starts an asynchronous file upload.
    ///
    /// The file at `absolute_path` is chunked, encrypted with a random
    /// content key, and uploaded as a Merkle tree of fragments.  Progress
    /// is reported through [`Event::UploadProgress`] events; on completion
    /// an [`Event::UploadDone`] delivers the [`Attachment`] root that can
    /// be sent in a message via [`convo_send`](Self::convo_send).
    ///
    /// Returns an opaque upload ID for correlating progress events.
    async fn attachment_upload(
        &self,
        absolute_path: PathBuf,
        mime: SmolStr,
    ) -> Result<i64, InternalRpcError>;

    /// Starts an asynchronous image upload.
    ///
    /// The image is resized/compressed to a WEBP payload, a ThumbHash string
    /// is generated, and then the result is uploaded as an attachment tree.
    /// Progress is reported through [`Event::UploadProgress`], and completion
    /// is reported through [`Event::UploadDone`] with an
    /// [`UploadedRoot::ImageAttachment`] payload.
    async fn image_attachment_upload(
        &self,
        absolute_path: PathBuf,
    ) -> Result<i64, InternalRpcError>;

    /// Starts an asynchronous attachment download.
    ///
    /// The fragment tree is fetched from the sender's server, decrypted,
    /// and reassembled into a file at `save_path`.  The caller is
    /// responsible for choosing the filename (including uniqueness).
    /// Progress is reported through [`Event::DownloadProgress`]; on
    /// completion [`Event::DownloadDone`] provides the final file path.
    async fn attachment_download(
        &self,
        attachment_id: nullspace_crypt::hash::Hash,
        save_path: PathBuf,
    ) -> Result<Hash, InternalRpcError>;

    /// Queries the current status of a known attachment (download path, root
    /// metadata).
    async fn attachment_status(
        &self,
        attachment_id: nullspace_crypt::hash::Hash,
    ) -> Result<AttachmentStatus, InternalRpcError>;

    /// Downloads an attachment synchronously (blocking the RPC call until
    /// complete).
    ///
    /// Unlike [`attachment_download`](Self::attachment_download), this does
    /// not emit progress events and waits for the full file to be written
    /// to `save_to` before returning.  Useful for one-off downloads like
    /// fetching a user avatar.
    async fn attachment_download_oneshot(
        &self,
        sender: UserName,
        attachment: Attachment,
        save_to: PathBuf,
    ) -> Result<(), InternalRpcError>;

    /// Returns the authenticated user's username.
    async fn own_username(&self) -> Result<UserName, InternalRpcError>;

    /// Updates the authenticated user's profile.
    ///
    /// Fields set to `None` are cleared.  The profile is signed with the
    /// device secret and pushed to the user's home server.
    async fn own_profile_set(
        &self,
        display_name: Option<String>,
        avatar: Option<ImageAttachment>,
    ) -> Result<(), InternalRpcError>;

    /// Fetches detailed information about a user, including their profile,
    /// common groups, and last DM summary.
    async fn user_details(&self, username: UserName) -> Result<UserDetails, InternalRpcError>;
}

/// A push notification emitted by the client's background service.
///
/// Events are the sole mechanism through which the client communicates
/// state changes to the frontend.  They are derived from database
/// mutations -- background workers never emit events directly, ensuring
/// that replaying the DB always reproduces the same event stream.
///
/// Retrieve events by calling
/// [`InternalProtocol::next_event`] (or `InternalClient::next_event`)
/// in a loop.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Event {
    /// The login state changed.
    ///
    /// Emitted once at startup and again whenever the identity row is
    /// created or removed.
    State {
        /// `true` once the client has a persisted identity and is ready
        /// to send/receive messages.
        logged_in: bool,
    },

    /// A conversation has new or updated messages.
    ///
    /// The frontend should refresh the conversation view (e.g. by
    /// re-calling [`convo_history`](InternalProtocol::convo_history) or
    /// [`convo_list`](InternalProtocol::convo_list)).
    ConvoUpdated {
        /// The conversation that changed.
        convo_id: ConvoId,
    },

    /// Progress update for an in-flight file upload.
    UploadProgress {
        /// The upload ID returned by
        /// [`attachment_upload`](InternalProtocol::attachment_upload).
        id: i64,
        uploaded_size: u64,
        total_size: u64,
    },

    /// A file upload completed successfully.
    UploadDone {
        /// The upload ID.
        id: i64,
        /// The uploaded payload root that can be sent in a message or used as
        /// a profile avatar.
        root: UploadedRoot,
    },

    /// A file upload failed.
    UploadFailed { id: i64, error: String },

    /// Progress update for an in-flight file download.
    DownloadProgress {
        attachment_id: Hash,
        downloaded_size: u64,
        total_size: u64,
    },

    /// A file download completed successfully.
    DownloadDone {
        attachment_id: Hash,
        /// Absolute path to the saved file.
        absolute_path: PathBuf,
    },

    /// A file download failed.
    DownloadFailed { attachment_id: Hash, error: String },
}

/// Typed upload completion payload.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum UploadedRoot {
    Attachment(Attachment),
    ImageAttachment(ImageAttachment),
}

/// Information about an existing user, returned by
/// [`register_start`](InternalProtocol::register_start).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegisterStartInfo {
    /// The looked-up username.
    pub username: UserName,
    /// The server this user is registered on.
    pub server_name: ServerName,
}

/// Describes how to complete registration.
///
/// Passed to [`register_finish`](InternalProtocol::register_finish).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum RegisterFinish {
    /// Create a brand-new user bound to `server_name`.
    ///
    /// Generates a fresh device secret, binds the username in the
    /// directory, authenticates with the server, and registers the
    /// initial medium-term key.
    BootstrapNewUser {
        username: UserName,
        server_name: ServerName,
    },
    /// Join an existing account by entering a pairing code from another
    /// device.
    ///
    /// The host device must have an active provisioning session (see
    /// [`provision_host_start`](InternalProtocol::provision_host_start)).
    /// The SPAKE2 handshake derives a shared key, the host sends an
    /// encrypted device secret, and this device registers itself in the
    /// directory.
    AddDeviceByCode {
        username: UserName,
        /// The numeric pairing code displayed on the host device.
        code: String,
    },
}

/// Returned when starting a device-provisioning session on the host.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProvisionHostStart {
    /// Opaque session handle for status polling and cancellation.
    pub session_id: u64,
    /// Human-readable pairing code to display to the user (e.g.
    /// `"1234 5678 9012"`).
    pub display_code: String,
}

/// Current state of a device-provisioning session.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProvisionHostStatus {
    pub phase: ProvisionHostPhase,
    pub display_code: String,
    /// Set when `phase` is [`ProvisionHostPhase::Failed`].
    pub error: Option<String>,
}

/// Lifecycle phase of a host-side provisioning session.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProvisionHostPhase {
    /// Waiting for the new device to enter the pairing code.
    Pending,
    /// The new device was successfully provisioned.
    Completed,
    /// The provisioning attempt failed (see
    /// [`ProvisionHostStatus::error`]).
    Failed,
}

/// A member entry in a group's roster.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupMember {
    pub username: UserName,
    /// Whether this member has admin privileges (can invite others).
    pub is_admin: bool,
    pub status: GroupMemberStatus,
}

/// Membership state of a user in a group.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GroupMemberStatus {
    /// Invited but has not yet accepted.
    Pending,
    /// Active member.
    Accepted,
    /// Removed from the group.
    Banned,
}

/// Rich profile and relationship information about a user.
///
/// Returned by [`user_details`](InternalProtocol::user_details).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserDetails {
    pub username: UserName,
    /// Display name from the user's signed profile, if set.
    pub display_name: Option<String>,
    /// Avatar image attachment from the user's signed profile, if set.
    pub avatar: Option<ImageAttachment>,
    /// The server the user is registered on.
    pub server_name: Option<ServerName>,
    /// Groups that both the local user and this user belong to.
    pub common_groups: Vec<GroupId>,
    /// Summary of the most recent DM with this user, if any.
    pub last_dm_message: Option<UserLastMessageSummary>,
}

/// Abbreviated view of the last DM with a peer.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserLastMessageSummary {
    pub received_at: Option<NanoTimestamp>,
    pub direction: MessageDirection,
    pub preview: String,
}

/// Whether a DM message was sent or received.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageDirection {
    Incoming,
    Outgoing,
}

/// Errors returned by the internal RPC interface.
#[derive(Clone, Debug, Error, Serialize, Deserialize)]
pub enum InternalRpcError {
    /// No identity exists yet -- the user must register first.
    #[error("client not ready")]
    NotReady,
    /// The operation was denied (e.g. the local device is not in the
    /// user's device chain).
    #[error("access denied")]
    AccessDenied,
    /// A catch-all for unexpected failures.
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
        if matches!(convo_id, ConvoId::Group { .. }) {
            return Err(groups_disabled_error());
        }
        let db = self.ctx.get(DATABASE);
        let identity = Identity::load(db)
            .await
            .map_err(|_| InternalRpcError::NotReady)?;
        let own_server = identity
            .server_name
            .clone()
            .ok_or_else(|| InternalRpcError::Other("server name not available".into()))?;
        let payload = match message {
            OutgoingMessage::PlainText(text) => MessagePayload {
                payload: MessageText::Plain(text),
                attachments: Vec::new(),
                replies_to: None,
                metadata: Default::default(),
            },
            OutgoingMessage::Attachment(root) => MessagePayload {
                payload: MessageText::Plain(String::new()),
                attachments: vec![MessageAttachment {
                    server_name: own_server.clone(),
                    data: MessageAttachmentData::Attachment(root),
                }],
                replies_to: None,
                metadata: Default::default(),
            },
            OutgoingMessage::ImageAttachment(root) => MessagePayload {
                payload: MessageText::Plain(String::new()),
                attachments: vec![MessageAttachment {
                    server_name: own_server.clone(),
                    data: MessageAttachmentData::ImageAttachment(root),
                }],
                replies_to: None,
                metadata: Default::default(),
            },
        };
        let body = Bytes::from(bcs::to_bytes(&payload).map_err(internal_err)?);
        let mut conn = db.acquire().await.map_err(internal_err)?;
        let id = queue_message(&mut conn, &convo_id, &identity.username, TAG_MESSAGE, &body)
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
        let _ = server;
        Err(groups_disabled_error())
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
        let _ = (group, username);
        Err(groups_disabled_error())
    }

    async fn group_members(&self, group: GroupId) -> Result<Vec<GroupMember>, InternalRpcError> {
        let _ = group;
        Err(groups_disabled_error())
    }

    async fn group_accept_invite(&self, dm_id: i64) -> Result<GroupId, InternalRpcError> {
        let _ = dm_id;
        Err(groups_disabled_error())
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

    async fn image_attachment_upload(
        &self,
        absolute_path: PathBuf,
    ) -> Result<i64, InternalRpcError> {
        attachments::image_attachment_upload(&self.ctx, absolute_path)
            .await
            .map_err(map_anyhow_err)
    }

    async fn attachment_download(
        &self,
        attachment_id: nullspace_crypt::hash::Hash,
        save_path: PathBuf,
    ) -> Result<Hash, InternalRpcError> {
        attachments::attachment_download(&self.ctx, attachment_id, save_path)
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
            store_attachment_root(&mut conn, &username, &avatar.inner)
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

        let common_groups = Vec::new();
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
        avatar: Option<ImageAttachment>,
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
            dm_mailbox: identity.dm_mailbox_id(),
            created,
            signature: Signature::from_bytes([0u8; 64]),
        };
        profile.sign(&identity.device_secret);

        server
            .profile_set(identity.username, profile)
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
    let dm_mailbox_key = MailboxKey::random();
    let dm_mailbox = server
        .mailbox_create(auth, dm_mailbox_key)
        .await
        .map_err(internal_err)?
        .map_err(|err| InternalRpcError::Other(err.to_string()))?;

    let created = Timestamp::now();
    let mut profile = UserProfile {
        display_name: None,
        avatar: None,
        dm_mailbox,
        created,
        signature: Signature::from_bytes([0u8; 64]),
    };
    profile.sign(&device_secret);
    server
        .profile_set(username.clone(), profile)
        .await
        .map_err(internal_err)?
        .map_err(|err| InternalRpcError::Other(err.to_string()))?;

    persist_identity(
        ctx.get(DATABASE),
        username,
        server_name,
        device_secret,
        medium_sk,
        dm_mailbox_key,
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
        .device_add_medium_pk(auth, signed)
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
    dm_mailbox_key: MailboxKey,
) -> Result<(), InternalRpcError> {
    sqlx::query(
        "INSERT INTO client_identity \
         (id, username, server_name, device_secret, medium_sk_current, medium_sk_prev, dm_mailbox_key) \
         VALUES (1, ?, ?, ?, ?, ?, ?)",
    )
    .bind(username.as_str())
    .bind(server_name.as_str())
    .bind(bcs::to_bytes(&device_secret).map_err(internal_err)?)
    .bind(bcs::to_bytes(&medium_sk).map_err(internal_err)?)
    .bind(bcs::to_bytes(&medium_sk).map_err(internal_err)?)
    .bind(bcs::to_bytes(&dm_mailbox_key).map_err(internal_err)?)
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
        .device_auth_start(username.clone(), device_pk)
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
        .device_auth_finish(request)
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

fn groups_disabled_error() -> InternalRpcError {
    InternalRpcError::Other("groups are disabled".into())
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
            Option<i64>,
            Option<Vec<u8>>,
            Option<i64>,
            Option<i64>,
            Option<String>,
        ),
    >(
        "SELECT t.thread_kind, t.thread_counterparty, t.created_at, \
                (SELECT COUNT(*) FROM thread_events ue \
                 JOIN client_identity ci ON ci.id = 1 \
                 LEFT JOIN message_reads mr ON mr.message_id = ue.id \
                 WHERE ue.thread_id = t.id \
                   AND ue.received_at IS NOT NULL \
                   AND ue.sender_username != ci.username \
                   AND mr.message_id IS NULL) AS unread_count, \
                e.id, e.sender_username, e.event_tag, e.event_body, e.received_at, mr.read_at, e.send_error \
         FROM event_threads t \
         LEFT JOIN thread_events e \
           ON e.id = (SELECT MAX(id) FROM thread_events WHERE thread_id = t.id) \
         LEFT JOIN message_reads mr ON mr.message_id = e.id \
         ORDER BY (e.received_at IS NULL) DESC, e.received_at DESC, t.created_at DESC, t.id DESC",
    )
    .fetch_all(db)
    .await?;
    let mut out = Vec::with_capacity(rows.len());
    for (
        thread_kind,
        counterparty,
        _created_at,
        unread_count,
        msg_id,
        sender_username,
        event_tag,
        event_body,
        received_at,
        read_at,
        send_error,
    ) in rows
    {
        let convo_id = parse_convo_id(&thread_kind, &counterparty)
            .ok_or_else(|| anyhow::anyhow!("invalid convo row"))?;
        let last_message = match (msg_id, sender_username, event_tag, event_body) {
            (Some(id), Some(sender_username), Some(event_tag), Some(body)) => {
                let sender = UserName::parse(sender_username)?;
                let body = (decode_message_content(db, &sender, u16::try_from(event_tag)?, &body)
                    .await)
                    .ok();
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
    let thread_kind = convo_id.convo_type();
    let counterparty = convo_id.counterparty();
    let mut rows = sqlx::query_as::<
        _,
        (
            i64,
            String,
            i64,
            Vec<u8>,
            Option<i64>,
            Option<i64>,
            Option<String>,
        ),
    >(
        "SELECT e.id, e.sender_username, e.event_tag, e.event_body, e.received_at, mr.read_at, e.send_error \
         FROM thread_events e \
         JOIN event_threads t ON e.thread_id = t.id \
         LEFT JOIN message_reads mr ON mr.message_id = e.id \
         WHERE t.thread_kind = ? AND t.thread_counterparty = ? AND e.id <= ? AND e.id >= ? \
         ORDER BY e.id DESC \
         LIMIT ?",
    )
    .bind(thread_kind)
    .bind(counterparty)
    .bind(before)
    .bind(after)
    .bind(limit as i64)
    .fetch_all(db)
    .await?;
    rows.reverse();
    let mut out = Vec::with_capacity(rows.len());
    for (id, sender_username, event_tag, body, received_at, read_at, send_error) in rows {
        let sender = UserName::parse(sender_username)?;
        let body = match decode_message_content(db, &sender, u16::try_from(event_tag)?, &body).await
        {
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
         SELECT e.id, ? \
         FROM thread_events e \
         JOIN event_threads t ON e.thread_id = t.id \
         JOIN client_identity ci ON ci.id = 1 \
         WHERE t.thread_kind = ? \
           AND t.thread_counterparty = ? \
           AND e.id <= ? \
           AND e.received_at IS NOT NULL \
           AND e.sender_username != ci.username",
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

async fn last_dm_message_summary(
    db: &sqlx::SqlitePool,
    local_username: &UserName,
    other_username: &UserName,
) -> anyhow::Result<Option<UserLastMessageSummary>> {
    let convo_id = ConvoId::Direct {
        peer: other_username.clone(),
    };
    let thread_kind = convo_id.convo_type();
    let counterparty = convo_id.counterparty();
    let received_at = sqlx::query_scalar::<_, Option<i64>>(
        "SELECT e.received_at \
         FROM thread_events e \
         JOIN event_threads t ON e.thread_id = t.id \
         WHERE t.thread_kind = ? AND t.thread_counterparty = ? AND e.sender_username != ? \
         ORDER BY e.id DESC \
         LIMIT 1",
    )
    .bind(thread_kind)
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
    sender: &UserName,
    event_tag: u16,
    body: &[u8],
) -> anyhow::Result<MessageContent> {
    if event_tag != TAG_MESSAGE {
        return Ok(MessageContent::PlainText("Unsupported message".to_string()));
    }

    let payload: MessagePayload = bcs::from_bytes(body)?;
    let text = match payload.payload {
        MessageText::Plain(text) | MessageText::Rich(text) => text,
    };

    if payload.attachments.len() == 1 && text.is_empty() {
        let attachment = payload
            .attachments
            .into_iter()
            .next()
            .expect("len checked above");
        match attachment.data {
            MessageAttachmentData::Attachment(root) => {
                let id = store_attachment_root(&mut *db.acquire().await?, sender, &root).await?;
                return Ok(MessageContent::Attachment {
                    id,
                    size: root.total_size(),
                    mime: root.mime,
                    filename: root.filename.clone(),
                });
            }
            MessageAttachmentData::ImageAttachment(image_root) => {
                let id =
                    store_attachment_root(&mut *db.acquire().await?, sender, &image_root.inner)
                        .await?;
                return Ok(MessageContent::ImageAttachment {
                    id,
                    size: image_root.inner.total_size(),
                    mime: image_root.inner.mime.clone(),
                    filename: image_root.inner.filename.clone(),
                    width: image_root.width,
                    height: image_root.height,
                    thumbhash: image_root.thumbhash,
                });
            }
        }
    }

    if payload.attachments.is_empty() {
        return Ok(MessageContent::PlainText(text));
    }

    if text.is_empty() {
        return Ok(MessageContent::PlainText(format!(
            "{} attachment(s)",
            payload.attachments.len()
        )));
    }

    Ok(MessageContent::PlainText(text))
}
