use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use serde_with::hex::Hex;
use serde_with::{Bytes, IfIsHumanReadable, serde_as};

/// BLAKE3 hash output.
#[serde_as]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub struct Hash(#[serde_as(as = "IfIsHumanReadable<Hex, Bytes>")] [u8; 32]);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HashParseError;

impl Hash {
    /// Hash a message with BLAKE3.
    pub fn digest(msg: &[u8]) -> Self {
        let hash = blake3::hash(msg);
        Self(*hash.as_bytes())
    }

    /// Generate a random hash value.
    pub fn random() -> Self {
        Self(rand::random())
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

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl FromStr for Hash {
    type Err = HashParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = hex::decode(s).map_err(|_| HashParseError)?;
        if bytes.len() != 32 {
            return Err(HashParseError);
        }
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&bytes);
        Ok(Self::from_bytes(buf))
    }
}

impl fmt::Display for HashParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid hash")
    }
}

impl std::error::Error for HashParseError {}

/// Extension trait for hashing any BCS-serializable value.
pub trait BcsHashExt: Serialize {
    /// Serialize with BCS and hash the resulting bytes.
    ///
    /// Panics if serialization fails.
    fn bcs_hash(&self) -> Hash;
}

impl<T> BcsHashExt for T
where
    T: Serialize,
{
    fn bcs_hash(&self) -> Hash {
        let bytes = bcs::to_bytes(self).expect("bcs serialization failed");
        Hash::digest(&bytes)
    }
}
