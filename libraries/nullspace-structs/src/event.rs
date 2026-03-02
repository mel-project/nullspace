use bytes::Bytes;
use nullspace_crypt::hash::Hash;
use serde::{Deserialize, Serialize};
use smol_str::SmolStr;

use crate::fragment::{Attachment, ImageAttachment};
use crate::timestamp::NanoTimestamp;
use crate::username::UserName;

pub const TAG_MESSAGE: u16 = 1;

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
    pub recipient: UserName,
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
