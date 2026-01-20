use bytes::Bytes;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use smol_str::SmolStr;
use thiserror::Error;

use crate::group::GroupId;
use crate::timestamp::NanoTimestamp;
use crate::username::UserName;

/// The intended recipient of an event payload.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Recipient {
    User(UserName),
    Group(GroupId),
}

impl From<UserName> for Recipient {
    fn from(value: UserName) -> Self {
        Self::User(value)
    }
}

impl From<GroupId> for Recipient {
    fn from(value: GroupId) -> Self {
        Self::Group(value)
    }
}

/// A decoded event payload.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Event {
    pub recipient: Recipient,
    pub sent_at: NanoTimestamp,
    pub mime: SmolStr,
    pub body: Bytes,
}

/// A structured event payload with a mime.
pub trait EventPayload: Serialize + DeserializeOwned {
    fn mime() -> &'static str;
}

/// Errors returned by event payload helpers.
#[derive(Debug, Error)]
pub enum EventPayloadError {
    #[error("unexpected mime {0}")]
    UnexpectedMime(String),
    #[error("payload decode failed")]
    Decode(#[from] serde_json::Error),
}

impl Event {
    pub fn decode_json_payload<T: EventPayload>(&self) -> Result<T, EventPayloadError> {
        if self.mime != T::mime() {
            return Err(EventPayloadError::UnexpectedMime(self.mime.to_string()));
        }
        Ok(serde_json::from_slice(&self.body)?)
    }

    pub fn from_json_payload<T: EventPayload>(
        recipient: impl Into<Recipient>,
        sent_at: NanoTimestamp,
        payload: &T,
    ) -> Result<Self, EventPayloadError> {
        let body = serde_json::to_vec(payload)?;
        Ok(Self {
            recipient: recipient.into(),
            sent_at,
            mime: SmolStr::new(T::mime()),
            body: Bytes::from(body),
        })
    }
}
