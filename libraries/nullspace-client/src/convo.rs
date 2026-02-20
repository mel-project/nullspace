//! Conversation primitives shared across the frontend API.
//!
//! This module defines the types that frontends use to display and interact
//! with conversations.  The heavy lifting -- encryption, sending, receiving,
//! group management, key rotation -- lives in private sub-modules and is
//! never exposed.

use anyctx::AnyCtx;
use futures_concurrency::future::Race;
use nullspace_crypt::hash::Hash;
use nullspace_structs::fragment::Attachment;
use nullspace_structs::group::GroupId;
use nullspace_structs::timestamp::NanoTimestamp;
use nullspace_structs::username::UserName;
use serde::{Deserialize, Serialize};
use smol_str::SmolStr;
use std::str::FromStr;

use crate::config::Config;

mod dm_common;
mod dm_recv;
mod group;
mod group_recv;
mod rekey;
mod roster;
mod send;

pub use group::{accept_invite, create_group, invite, load_group};
pub use roster::GroupRoster;
pub use send::queue_message;

/// Identifies a conversation.
///
/// Every conversation is either a direct message with a single peer or a
/// named group with multiple members.  This enum is the primary key used
/// throughout the API to refer to conversations in list, history, send,
/// and mark-read calls.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ConvoId {
    /// A one-to-one direct message conversation.
    Direct { peer: UserName },
    /// A group conversation.
    Group { group_id: GroupId },
}

impl ConvoId {
    pub fn convo_type(&self) -> &'static str {
        match self {
            ConvoId::Direct { .. } => "direct",
            ConvoId::Group { .. } => "group",
        }
    }

    pub fn counterparty(&self) -> String {
        match self {
            ConvoId::Direct { peer } => peer.as_str().to_string(),
            ConvoId::Group { group_id } => group_id.to_string(),
        }
    }
}

pub fn parse_convo_id(convo_type: &str, counterparty: &str) -> Option<ConvoId> {
    match convo_type {
        "direct" => UserName::parse(counterparty)
            .ok()
            .map(|peer| ConvoId::Direct { peer }),
        "group" => GroupId::from_str(counterparty)
            .ok()
            .map(|group_id| ConvoId::Group { group_id }),
        _ => None,
    }
}

/// A single message in a conversation, as returned by
/// [`convo_history`](crate::internal::InternalProtocol::convo_history).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConvoMessage {
    /// Locally-assigned, monotonically increasing message ID.
    pub id: i64,
    /// The conversation this message belongs to.
    pub convo_id: ConvoId,
    /// Who sent the message.
    pub sender: UserName,
    /// The decoded message payload.
    pub body: MessageContent,
    /// If the send loop failed to deliver this message, the error
    /// description.  `None` for incoming messages and successfully
    /// delivered outgoing messages.
    pub send_error: Option<String>,
    /// Timestamp set by the server when the message was received.
    /// `None` for outgoing messages that have not yet been delivered.
    pub received_at: Option<NanoTimestamp>,
    /// Timestamp at which the local user marked this message as read.
    pub read_at: Option<NanoTimestamp>,
}

/// The decoded content of a message.
///
/// The client handles all decryption and deserialization internally;
/// frontends receive this fully-decoded representation.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageContent {
    /// A plain-text (or Markdown) message.
    PlainText(String),
    /// A file attachment.
    ///
    /// The `id` is the hash of the attachment root -- use it with
    /// [`attachment_download`](crate::internal::InternalProtocol::attachment_download)
    /// and
    /// [`attachment_status`](crate::internal::InternalProtocol::attachment_status).
    Attachment {
        id: Hash,
        /// Total size of the decrypted file in bytes.
        size: u64,
        /// MIME type (e.g. `"image/png"`).
        mime: SmolStr,
        /// Original filename.
        filename: SmolStr,
    },
    /// An invitation to join a group, embedded in a DM.
    ///
    /// Accept it with
    /// [`group_accept_invite`](crate::internal::InternalProtocol::group_accept_invite).
    GroupInvite {
        /// The message ID of this invitation (pass to
        /// `group_accept_invite`).
        invite_id: i64,
    },
}

/// A message the frontend wishes to send.
///
/// Passed to
/// [`convo_send`](crate::internal::InternalProtocol::convo_send).
/// The client handles encryption, chunking (for attachments), and
/// reliable delivery.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutgoingMessage {
    /// A plain-text message.
    PlainText(String),
    /// A previously-uploaded attachment root (obtained from
    /// [`Event::UploadDone`](crate::internal::Event::UploadDone)).
    Attachment(Attachment),
}

/// Summary of a conversation for list views.
///
/// Returned by
/// [`convo_list`](crate::internal::InternalProtocol::convo_list).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConvoSummary {
    pub convo_id: ConvoId,
    /// The most recent message in the conversation, if any.
    pub last_message: Option<ConvoMessage>,
    /// Number of unread incoming messages.
    pub unread_count: u64,
}

pub async fn convo_loop(ctx: &AnyCtx<Config>) {
    (
        send::send_loop(ctx),
        dm_recv::dm_recv_loop(ctx),
        group_recv::group_recv_loop(ctx),
        rekey::group_rekey_loop(ctx),
    )
        .race()
        .await;
}
