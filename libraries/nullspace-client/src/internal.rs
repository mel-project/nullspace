use anyctx::AnyCtx;
use async_channel::Receiver as AsyncReceiver;
use async_trait::async_trait;
use bytes::Bytes;
use nanorpc::nanorpc_derive;
use nullspace_crypt::hash::Hash;
use nullspace_structs::event::{MessagePayload, TAG_MESSAGE};
use nullspace_structs::fragment::{Attachment, ImageAttachment};
use nullspace_structs::group::GroupId;
use nullspace_structs::server::ServerName;
use nullspace_structs::timestamp::NanoTimestamp;
use nullspace_structs::username::UserName;
use serde::{Deserialize, Serialize};
use smol_str::SmolStr;
use std::path::PathBuf;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::Mutex as AsyncMutex;
use uuid::Uuid;

use crate::attachments::{self, AttachmentStatus};
use crate::config::Config;
pub use crate::convo::{
    ConvoId, ConvoItem, ConvoItemKind, ConvoItemPreview, ConvoSummary, SystemItem,
};
use crate::convo::{convo_history, convo_list, mark_convo_read, queue_message};
use crate::database::{DATABASE, DbNotify};
use crate::events::emit_event;
use crate::identity::Identity;
use crate::identity::identity_exists;
use crate::users::own_profile_set as set_own_profile;
use crate::identity::provisioning::{self, HostProvisioning};
use crate::users::user_details_data;

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

    /// Starts or replaces the single active device-provisioning session on
    /// the *host* (existing) device.
    ///
    /// Returns the human-readable pairing code that the user enters on the
    /// new device. Poll [`provision_host_status`](Self::provision_host_status)
    /// to keep the host-side handshake progressing.
    async fn provision_host_start(&self) -> Result<String, InternalRpcError>;

    /// Queries the current host-side provisioning state.
    ///
    /// This call also advances pending host-side handshake work while the UI
    /// is polling.
    async fn provision_host_status(&self) -> Result<ProvisionHostState, InternalRpcError>;

    /// Cancels the active host-side provisioning session, if any.
    async fn provision_host_stop(&self) -> Result<(), InternalRpcError>;

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
    ) -> Result<Vec<ConvoItem>, InternalRpcError>;

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
        message: MessagePayload,
    ) -> Result<i64, InternalRpcError>;

    /// Creates a new group and returns its [`GroupId`].
    async fn group_create(&self, request: GroupCreateRequest) -> Result<GroupId, InternalRpcError>;

    /// Returns the server name this client's identity is registered on.
    async fn own_server(&self) -> Result<ServerName, InternalRpcError>;

    /// Returns a consolidated snapshot of the local user's current view of a group.
    async fn group_view(&self, group: GroupId) -> Result<GroupView, InternalRpcError>;

    /// Applies a typed group action.
    async fn group_action(
        &self,
        group: GroupId,
        action: GroupAction,
    ) -> Result<(), InternalRpcError>;

    /// Lists pending inbound group invitations.
    async fn group_invitation_list(&self) -> Result<Vec<GroupInvitationSummary>, InternalRpcError>;

    /// Accepts an inbound group invitation and returns the joined group ID.
    async fn group_invitation_accept(
        &self,
        invitation_id: i64,
    ) -> Result<GroupId, InternalRpcError>;

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
    ) -> Result<Uuid, InternalRpcError>;

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
    ) -> Result<Uuid, InternalRpcError>;

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
        id: Uuid,
        uploaded_size: u64,
        total_size: u64,
    },

    /// A file upload completed successfully.
    UploadDone {
        /// The upload ID.
        id: Uuid,
        /// The uploaded payload root that can be sent in a message or used as
        /// a profile avatar.
        root: UploadedRoot,
    },

    /// A file upload failed.
    UploadFailed { id: Uuid, error: String },

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

/// Current state of the single active host-side provisioning session.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProvisionHostState {
    /// No host-side provisioning session is active.
    Idle,
    /// Waiting for the new device to enter the pairing code.
    Pending {
        /// Human-readable pairing code to display to the user (e.g.
        /// `"1234 5678 9012"`).
        display_code: String,
    },
    /// The new device was successfully provisioned.
    Completed,
    /// The provisioning attempt failed.
    Failed { error: String },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupCreateRequest {
    pub server: ServerName,
    pub title: Option<String>,
    pub description: Option<String>,
    pub new_members_muted: bool,
    pub allow_new_members_to_see_history: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupView {
    pub group_id: GroupId,
    pub display_title: String,
    pub title: Option<String>,
    pub description: Option<String>,
    pub server: ServerName,
    pub capabilities: GroupCapabilities,
    pub settings: GroupSettings,
    pub roster: Vec<GroupRosterEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupCapabilities {
    pub can_send_messages: bool,
    pub can_share_invites: bool,
    pub can_edit_metadata: bool,
    pub can_manage_mutes: bool,
    pub can_manage_members: bool,
    pub can_manage_admins: bool,
    pub can_rotate_keys: bool,
    pub can_leave: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupSettings {
    pub new_members_muted: bool,
    pub allow_new_members_to_see_history: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupRosterEntry {
    pub username: UserName,
    pub is_admin: bool,
    pub is_muted: bool,
    pub is_banned: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GroupAction {
    ShareInvite {
        username: UserName,
    },
    SetMetadata {
        title: Option<String>,
        description: Option<String>,
    },
    SetMemberMuted {
        username: UserName,
        muted: bool,
    },
    SetNewMembersMuted {
        muted: bool,
    },
    SetAllowNewMembersToSeeHistory {
        allow: bool,
    },
    SetAdmin {
        username: UserName,
        is_admin: bool,
    },
    SetBanned {
        username: UserName,
        banned: bool,
    },
    Leave,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupInvitationSummary {
    pub invitation_id: i64,
    pub group_id: GroupId,
    pub display_title: String,
    pub title: Option<String>,
    pub description: Option<String>,
    pub inviter: UserName,
    pub server: ServerName,
    pub received_at: NanoTimestamp,
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
    /// The requested entity is not present in the local client state.
    #[error("not found")]
    NotFound,
    /// The caller needs to refresh and retry against newer local state.
    #[error("conflict")]
    Conflict,
    /// A catch-all for unexpected failures.
    #[error("{0}")]
    Other(String),
}

#[derive(Clone)]
pub struct InternalImpl {
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

    async fn conn(&self) -> Result<sqlx::pool::PoolConnection<sqlx::Sqlite>, InternalRpcError> {
        self.ctx.get(DATABASE).acquire().await.map_err(internal_err)
    }

    async fn load_identity(&self) -> Result<Identity, InternalRpcError> {
        Identity::load(&mut *self.conn().await?)
            .await
            .map_err(internal_err)
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
        provisioning::register_start(&self.ctx, username).await
    }

    async fn register_finish(&self, request: RegisterFinish) -> Result<(), InternalRpcError> {
        provisioning::register_finish(self.ctx.clone(), request).await
    }

    async fn provision_host_start(&self) -> Result<String, InternalRpcError> {
        self.host_provisioning.start(self.ctx.clone()).await
    }

    async fn provision_host_status(&self) -> Result<ProvisionHostState, InternalRpcError> {
        self.host_provisioning.status(&self.ctx).await
    }

    async fn provision_host_stop(&self) -> Result<(), InternalRpcError> {
        self.host_provisioning.stop().await
    }

    async fn convo_list(&self) -> Result<Vec<ConvoSummary>, InternalRpcError> {
        convo_list(&mut *self.conn().await?)
            .await
            .map_err(internal_err)
    }

    async fn convo_history(
        &self,
        convo_id: ConvoId,
        before: Option<i64>,
        after: Option<i64>,
        limit: u16,
    ) -> Result<Vec<ConvoItem>, InternalRpcError> {
        convo_history(&mut *self.conn().await?, convo_id, before, after, limit)
            .await
            .map_err(internal_err)
    }

    async fn convo_send(
        &self,
        convo_id: ConvoId,
        message: MessagePayload,
    ) -> Result<i64, InternalRpcError> {
        let identity = self
            .load_identity()
            .await
            .map_err(|_| InternalRpcError::NotReady)?;
        let body = Bytes::from(bcs::to_bytes(&message).map_err(internal_err)?);
        let mut conn = self.conn().await?;
        let id = queue_message(&mut conn, &convo_id, &identity.username, TAG_MESSAGE, &body)
            .await
            .map_err(internal_err)?;
        DbNotify::touch();
        emit_event(&self.ctx, Event::ConvoUpdated { convo_id });
        Ok(id)
    }

    async fn convo_mark_read(
        &self,
        convo_id: ConvoId,
        up_to_id: i64,
    ) -> Result<(), InternalRpcError> {
        let affected = mark_convo_read(&mut *self.conn().await?, &convo_id, up_to_id)
            .await
            .map_err(internal_err)?;
        if affected > 0 {
            emit_event(&self.ctx, Event::ConvoUpdated { convo_id });
        }
        Ok(())
    }

    async fn group_create(&self, request: GroupCreateRequest) -> Result<GroupId, InternalRpcError> {
        let group_id = crate::convo::group_create(&self.ctx, request)
            .await
            .map_err(internal_err)?;
        emit_event(
            &self.ctx,
            Event::ConvoUpdated {
                convo_id: ConvoId::Group { group_id },
            },
        );
        Ok(group_id)
    }

    async fn own_server(&self) -> Result<ServerName, InternalRpcError> {
        self.load_identity()
            .await?
            .server_name
            .ok_or_else(|| InternalRpcError::Other("server name not available".into()))
    }

    async fn group_view(&self, group: GroupId) -> Result<GroupView, InternalRpcError> {
        let _ = group;
        Err(groups_disabled_error())
    }

    async fn group_action(
        &self,
        group: GroupId,
        action: GroupAction,
    ) -> Result<(), InternalRpcError> {
        let _ = (group, action);
        Err(groups_disabled_error())
    }

    async fn group_invitation_list(&self) -> Result<Vec<GroupInvitationSummary>, InternalRpcError> {
        Err(groups_disabled_error())
    }

    async fn group_invitation_accept(
        &self,
        invitation_id: i64,
    ) -> Result<GroupId, InternalRpcError> {
        let _ = invitation_id;
        Err(groups_disabled_error())
    }

    async fn attachment_upload(
        &self,
        absolute_path: PathBuf,
        mime: SmolStr,
    ) -> Result<Uuid, InternalRpcError> {
        attachments::attachment_upload(&self.ctx, absolute_path, mime)
            .await
            .map_err(map_anyhow_err)
    }

    async fn image_attachment_upload(
        &self,
        absolute_path: PathBuf,
    ) -> Result<Uuid, InternalRpcError> {
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
        if !identity_exists(&mut *self.conn().await?)
            .await
            .map_err(internal_err)?
        {
            return Err(InternalRpcError::NotReady);
        }
        let identity = self.load_identity().await?;
        let details = user_details_data(&self.ctx, &identity.username, &username)
            .await
            .map_err(map_anyhow_err)?;

        Ok(UserDetails {
            username,
            display_name: details.display_name,
            avatar: details.avatar,
            server_name: Some(details.server_name),
            common_groups: Vec::new(),
            last_dm_message: details.last_dm_received_at.map(|received_at| {
                UserLastMessageSummary {
                    received_at: Some(received_at),
                    direction: MessageDirection::Incoming,
                    preview: String::new(),
                }
            }),
        })
    }

    async fn own_username(&self) -> Result<UserName, InternalRpcError> {
        Ok(self.load_identity().await?.username)
    }

    async fn own_profile_set(
        &self,
        display_name: Option<String>,
        avatar: Option<ImageAttachment>,
    ) -> Result<(), InternalRpcError> {
        set_own_profile(&self.ctx, display_name, avatar).await
    }
}

pub fn internal_err(err: impl std::fmt::Display) -> InternalRpcError {
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
