use nullspace_crypt::hash::{Hash, HashParseError};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use thiserror::Error;

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Hash)]
#[serde(transparent)]
pub struct GroupId(Hash);

#[derive(Debug, Error)]
#[error("invalid group id")]
pub struct GroupIdParseError;

impl GroupId {
    pub fn as_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Hash::from_bytes(bytes))
    }

    pub fn short_id(self) -> String {
        let bytes = self.as_bytes();
        let mut out = String::with_capacity(8);
        for byte in bytes.iter().take(4) {
            out.push_str(&format!("{byte:02x}"));
        }
        out
    }
}

impl fmt::Display for GroupId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for GroupId {
    type Err = GroupIdParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let hash = Hash::from_str(s).map_err(|_err: HashParseError| GroupIdParseError)?;
        Ok(Self(hash))
    }
}
