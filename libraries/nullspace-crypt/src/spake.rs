use std::fmt;
use std::str::FromStr;

use derivative::Derivative;
use serde::{Deserialize, Serialize};
use serde_with::base64::{Base64, UrlSafe};
use serde_with::formats::Unpadded;
use serde_with::{Bytes, IfIsHumanReadable, serde_as};
use spake2::{Ed25519Group, Error as InnerSpakeError, Identity, Password, Spake2};
use thiserror::Error;

use crate::ParseKeyError;
use crate::encoding;
use crate::redacted_debug;

/// Errors returned by SPAKE operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum SpakeError {
    #[error("invalid SPAKE message length")]
    WrongLength,
    #[error("invalid SPAKE peer message")]
    CorruptMessage,
    #[error("invalid SPAKE peer side marker")]
    BadSide,
}

/// SPAKE handshake message.
#[serde_as]
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct SpakeMessage(
    #[serde_as(as = "IfIsHumanReadable<Base64<UrlSafe, Unpadded>, Bytes>")] [u8; 33],
);

/// Shared key produced by a SPAKE exchange.
#[serde_as]
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Derivative, Hash)]
#[derivative(Debug)]
pub struct SpakeKey(
    #[derivative(Debug(format_with = "redacted_debug"))]
    #[serde_as(as = "IfIsHumanReadable<Base64<UrlSafe, Unpadded>, Bytes>")]
    [u8; 32],
);

/// In-progress SPAKE exchange session.
pub struct SpakeSession(Spake2<Ed25519Group>);

impl SpakeMessage {
    /// Build a SPAKE message from its fixed-size byte representation.
    pub fn from_bytes(bytes: [u8; 33]) -> Self {
        Self(bytes)
    }

    /// Build a SPAKE message from an arbitrary slice.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, SpakeError> {
        let bytes = bytes.try_into().map_err(|_| SpakeError::WrongLength)?;
        Ok(Self(bytes))
    }

    /// Serialize the message as 33 bytes.
    pub fn to_bytes(&self) -> [u8; 33] {
        self.0
    }
}

impl AsRef<[u8]> for SpakeMessage {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl SpakeKey {
    /// Build a SPAKE shared key from 32 raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Serialize the SPAKE shared key as 32 bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Display for SpakeKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", encoding::encode_32_base64(self.to_bytes()))
    }
}

impl FromStr for SpakeKey {
    type Err = ParseKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = encoding::decode_32_base64(s)?;
        Ok(Self::from_bytes(bytes))
    }
}

impl SpakeSession {
    /// Start a SPAKE exchange.
    ///
    /// Returns the exchange state and the outbound message to send to the peer.
    pub fn start(password: impl AsRef<[u8]>, id: impl AsRef<[u8]>) -> (Self, SpakeMessage) {
        let password = Password::new(password.as_ref());
        let id = Identity::new(id.as_ref());
        let (state, outbound) = Spake2::<Ed25519Group>::start_symmetric(&password, &id);
        let outbound =
            SpakeMessage::from_slice(&outbound).expect("spake2 message length invariant");
        (Self(state), outbound)
    }

    /// Finish a SPAKE exchange and derive the shared key.
    pub fn finish(self, peer_message: &SpakeMessage) -> Result<SpakeKey, SpakeError> {
        let key = match self.0.finish(peer_message.as_ref()) {
            Ok(key) => key,
            Err(InnerSpakeError::BadSide) => return Err(SpakeError::BadSide),
            Err(InnerSpakeError::CorruptMessage) => return Err(SpakeError::CorruptMessage),
            Err(InnerSpakeError::WrongLength) => unreachable!("spake2 message length invariant"),
        };
        let key = key
            .as_slice()
            .try_into()
            .expect("spake2 key length invariant");
        Ok(SpakeKey::from_bytes(key))
    }

    /// Finish a SPAKE exchange from a raw message slice.
    pub fn finish_from_slice(self, peer_message: &[u8]) -> Result<SpakeKey, SpakeError> {
        let peer_message = SpakeMessage::from_slice(peer_message)?;
        self.finish(&peer_message)
    }
}

#[cfg(test)]
mod tests {
    use super::{SpakeError, SpakeKey, SpakeMessage, SpakeSession};

    #[test]
    fn spake_matches() {
        let (a_state, a_msg) = SpakeSession::start(b"password", b"idS");
        let (b_state, b_msg) = SpakeSession::start(b"password", b"idS");

        let a_key = a_state.finish(&b_msg).expect("a key");
        let b_key = b_state.finish(&a_msg).expect("b key");

        assert_eq!(a_key.to_bytes(), b_key.to_bytes());
    }

    #[test]
    fn spake_mismatch_differs() {
        let (a_state, a_msg) = SpakeSession::start(b"password-a", b"idS");
        let (b_state, b_msg) = SpakeSession::start(b"password-b", b"idS");

        let a_key = a_state.finish(&b_msg).expect("a key");
        let b_key = b_state.finish(&a_msg).expect("b key");

        assert_ne!(a_key.to_bytes(), b_key.to_bytes());
    }

    #[test]
    fn rejects_wrong_message_length() {
        let err = SpakeMessage::from_slice(&[0u8; 32]).expect_err("wrong length");
        assert_eq!(err, SpakeError::WrongLength);

        let (state, _msg) = SpakeSession::start(b"password", b"idS");
        let err = state
            .finish_from_slice(&[0u8; 32])
            .expect_err("wrong length");
        assert_eq!(err, SpakeError::WrongLength);
    }

    #[test]
    fn serde_json_round_trip() {
        let (a_state, a_msg) = SpakeSession::start(b"password", b"idS");
        let (b_state, b_msg) = SpakeSession::start(b"password", b"idS");

        let a_key = a_state.finish(&b_msg).expect("a key");
        let _b_key = b_state.finish(&a_msg).expect("b key");

        let message_json = serde_json::to_string(&a_msg).expect("message to json");
        let message_back: SpakeMessage =
            serde_json::from_str(&message_json).expect("message from json");
        assert_eq!(a_msg.to_bytes(), message_back.to_bytes());

        let key_json = serde_json::to_string(&a_key).expect("key to json");
        let key_back: SpakeKey = serde_json::from_str(&key_json).expect("key from json");
        assert_eq!(a_key.to_bytes(), key_back.to_bytes());
    }
}
