use bytes::Bytes;
use nullspace_crypt::hash::Hash;
use serde::{Deserialize, Serialize};
use smol_str::SmolStr;

use crate::fragment::{Attachment, ImageAttachment};
use crate::group::GroupId;
use crate::timestamp::NanoTimestamp;
use crate::username::UserName;

pub const TAG_MESSAGE: u16 = 1;
pub const TAG_ROTATION_HINT: u16 = 2;
pub const TAG_GROUP_INVITATION: u16 = 3;
pub const TAG_LEAVE_REQUEST: u16 = 4;
pub const TAG_GROUP_ADMIN_CHANGE: u16 = 5;
pub const TAG_GROUP_MUTE_CHANGE: u16 = 6;
pub const TAG_GROUP_METADATA_CHANGE: u16 = 7;
pub const TAG_GROUP_SETTINGS_CHANGE: u16 = 8;

/// Distinguishes whether an event targets a DM or a group conversation.
///
/// Included in the event hash so a malicious server cannot replay a DM event
/// into a group mailbox (or vice-versa).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum EventRecipient {
    Dm(UserName),
    Group(GroupId),
}

/// The text content of a message, either plain or rich (formatted).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageText {
    Plain(String),
    Rich(String),
}

/// The full payload of a message event, including text, attachments, and metadata.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessagePayload {
    pub payload: MessageText,
    pub attachments: Vec<Attachment>,
    pub images: Vec<ImageAttachment>,
    pub replies_to: Option<Hash>,
    pub metadata: std::collections::BTreeMap<SmolStr, String>,
}

/// A decoded event payload.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Event {
    pub sender: UserName,
    pub recipient: EventRecipient,
    pub sent_at: NanoTimestamp,
    pub after: Option<Hash>,
    pub tag: u16,
    pub body: Bytes,
}

impl Event {
    pub fn hash(&self) -> Hash {
        let bytes = bcs::to_bytes(self).expect("event bcs serialization");
        Hash::digest(&bytes)
    }
}

use crate::group::GroupBearerKey;

/// Body of a `TAG_GROUP_INVITATION` DM event. Contains the GBK so the
/// invitee can immediately start polling the group mailbox, plus a
/// rotation_index hint for fetching the roster snapshot.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupInvitationBody {
    pub group_id: GroupId,
    pub gbk: GroupBearerKey,
    pub rotation_index: u64,
    pub title: Option<String>,
    pub description: Option<String>,
}

/// Body of a `TAG_GROUP_ADMIN_CHANGE` group mailbox event.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupAdminChangeBody {
    pub username: UserName,
    pub is_admin: bool,
}

/// Body of a `TAG_GROUP_MUTE_CHANGE` group mailbox event.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupMuteChangeBody {
    pub username: UserName,
    pub muted: bool,
}

/// Body of a `TAG_GROUP_METADATA_CHANGE` group mailbox event.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupMetadataChangeBody {
    pub title: Option<String>,
    pub description: Option<String>,
}

/// Body of a `TAG_GROUP_SETTINGS_CHANGE` group mailbox event.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupSettingsChangeBody {
    pub new_members_muted: bool,
    pub allow_new_members_to_see_history: bool,
}
