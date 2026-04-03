use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::str::FromStr;

use nullspace_crypt::aead::AeadKey;
use nullspace_crypt::hash::Hash;
use nullspace_crypt::signing::{Signable, Signature, SigningPublic};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::e2ee::HeaderEncrypted;
use crate::mailbox::MailboxKey;
use crate::server::ServerName;
use crate::username::UserName;

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

/// A signed group key rotation entry.
///
/// Entries form a hash chain: each entry (except the first) includes the hash
/// of the previous entry, preventing the server from reordering, inserting,
/// or silently replacing entries. Position in the log is implicit; clients
/// track it locally.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GroupRotation {
    pub group_id: GroupId,
    pub prev_hash: Option<Hash>,
    pub signer: SigningPublic,
    pub new_admin_set: BTreeSet<SigningPublic>,
    pub gbk_rotation: HeaderEncrypted,
    pub signature: Signature,
}

impl GroupRotation {
    /// Compute the hash of this rotation entry (covers all fields including signature).
    pub fn hash(&self) -> Hash {
        Hash::digest(&bcs::to_bytes(self).unwrap())
    }
}

impl Signable for GroupRotation {
    fn signed_value(&self) -> Vec<u8> {
        bcs::to_bytes(&(
            &self.group_id,
            &self.prev_hash,
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

/// The bearer key that grants read/write access to a group's shared mailbox.
///
/// Possession of the GBK lets a device derive the mailbox key (for polling)
/// and the symmetric encryption key (for encrypting/decrypting messages).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupBearerKey {
    pub group_id: GroupId,
    pub server: ServerName,
    pub random_nonce: [u8; 32],
}

impl GroupBearerKey {
    /// Create a new GBK with a fresh random nonce.
    pub fn generate(group_id: GroupId, server: ServerName) -> Self {
        Self {
            group_id,
            server,
            random_nonce: rand::random(),
        }
    }

    /// Derive the mailbox key used to read/write the group's shared mailbox.
    pub fn mailbox_key(&self) -> MailboxKey {
        let digest = Hash::keyed_digest(b"ns-group-mailbox", &bcs::to_bytes(self).unwrap());
        let bytes = digest.to_bytes();
        let mut key = [0u8; 20];
        key.copy_from_slice(&bytes[..20]);
        MailboxKey::from_bytes(key)
    }

    /// Derive the symmetric key used to encrypt/decrypt group messages.
    pub fn symmetric_key(&self) -> AeadKey {
        let digest = Hash::keyed_digest(b"ns-group-symmetric", &bcs::to_bytes(self).unwrap());
        AeadKey::from_bytes(digest.to_bytes())
    }
}

/// The plaintext payload inside `GroupRotation::gbk_rotation`.
///
/// HeaderEncrypted to all members' medium-term keys, so every member can
/// decrypt and learn both the current GBK and the full group roster.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupRotationPayload {
    pub gbk: GroupBearerKey,
    pub roster: GroupRoster,
}

/// Complete group membership state, embedded in every rotation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupRoster {
    pub members: BTreeMap<UserName, MemberState>,
    pub banned: BTreeSet<UserName>,
    pub metadata: GroupMetadata,
    pub settings: GroupRosterSettings,
}

/// Per-member flags within a group roster.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MemberState {
    pub is_admin: bool,
    pub is_muted: bool,
}

/// Group title and description.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupMetadata {
    pub title: Option<String>,
    pub description: Option<String>,
}

/// Group-wide settings carried in the roster.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupRosterSettings {
    pub new_members_muted: bool,
    pub allow_new_members_to_see_history: bool,
}
