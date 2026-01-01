use serde::{Deserialize, Serialize};
use serde_with::hex::Hex;
use serde_with::{Bytes, IfIsHumanReadable, serde_as};

/// BLAKE3 hash output.
#[serde_as]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug)]
pub struct Hash(#[serde_as(as = "IfIsHumanReadable<Hex, Bytes>")] [u8; 32]);

impl Hash {
    /// Hash a message with BLAKE3.
    pub fn digest(msg: &[u8]) -> Self {
        let hash = blake3::hash(msg);
        Self(*hash.as_bytes())
    }

    /// Hash a message with a key of any length by prehashing the key.
    pub fn keyed_digest(key: &[u8], msg: &[u8]) -> Self {
        let key_hash = blake3::hash(key);
        let hash = blake3::keyed_hash(key_hash.as_bytes(), msg);
        Self(*hash.as_bytes())
    }

    /// Build a hash from its 32-byte form.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Serialize the hash as 32 bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }
}
