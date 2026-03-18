use std::collections::BTreeSet;
use std::fmt;
use std::str::FromStr;

use nullspace_crypt::signing::{Signable, Signature, SigningPublic};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::e2ee::HeaderEncrypted;

/// A unique group identifier, wrapping a v4 UUID.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Hash)]
#[serde(transparent)]
pub struct GroupId(Uuid);

/// Error returned when parsing an invalid group ID string.
#[derive(Debug, Error)]
#[error("invalid group id")]
pub struct GroupIdParseError;

impl GroupId {
    pub fn random() -> Self {
        Self(Uuid::new_v4())
    }

    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(Uuid::from_bytes(bytes))
    }

    pub fn to_bytes(&self) -> [u8; 16] {
        *self.0.as_bytes()
    }

    pub fn short_id(&self) -> String {
        self.0.to_string()[..8].to_string()
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
        let uuid = Uuid::from_str(s).map_err(|_| GroupIdParseError)?;
        Ok(Self(uuid))
    }
}

/// A signed group key rotation entry bound to a group and log index.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GroupRotation {
    pub group_id: GroupId,
    pub index: u64,
    pub signer: SigningPublic,
    pub new_admin_set: BTreeSet<SigningPublic>,
    pub gbk_rotation: HeaderEncrypted,
    pub signature: Signature,
}

impl Signable for GroupRotation {
    fn signed_value(&self) -> Vec<u8> {
        bcs::to_bytes(&(
            &self.group_id,
            &self.index,
            &self.signer,
            &self.new_admin_set,
            &self.gbk_rotation,
        ))
        .unwrap()
    }

    fn signature_mut(&mut self) -> &mut Signature {
        &mut self.signature
    }

    fn signature(&self) -> &Signature {
        &self.signature
    }
}
