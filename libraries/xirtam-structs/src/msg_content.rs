use bytes::Bytes;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use smol_str::SmolStr;
use thiserror::Error;

use crate::{handle::Handle, timestamp::NanoTimestamp};

/// A decoded message payload.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageContent {
    pub recipient: Handle,
    pub sent_at: NanoTimestamp,
    pub mime: SmolStr,
    pub body: Bytes,
}

/// A structured message payload with a mime.
pub trait MessagePayload: Serialize + DeserializeOwned {
    fn mime() -> &'static str;
}

#[derive(Debug, Error)]
pub enum MessagePayloadError {
    #[error("unexpected mime {0}")]
    UnexpectedMime(String),
    #[error("payload decode failed")]
    Decode(#[from] serde_json::Error),
}

impl MessageContent {
    pub fn decode_json_payload<T: MessagePayload>(&self) -> Result<T, MessagePayloadError> {
        if self.mime != T::mime() {
            return Err(MessagePayloadError::UnexpectedMime(self.mime.to_string()));
        }
        Ok(serde_json::from_slice(&self.body)?)
    }

    pub fn from_json_payload<T: MessagePayload>(
        recipient: Handle,
        sent_at: NanoTimestamp,
        payload: &T,
    ) -> Result<Self, MessagePayloadError> {
        let body = serde_json::to_vec(payload)?;
        Ok(Self {
            recipient,
            sent_at,
            mime: SmolStr::new(T::mime()),
            body: Bytes::from(body),
        })
    }
}
