use nullspace_crypt::hash::Hash;
use serde::{Deserialize, Serialize};
use serde_with::hex::Hex;
use serde_with::{Bytes as SerdeBytes, IfIsHumanReadable, serde_as};

use crate::{Blob, timestamp::NanoTimestamp};

/// A mailbox ID at a server, wrapping a hash value.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(transparent)]
pub struct MailboxId(Hash);

impl MailboxId {
    pub fn from_key(key: &MailboxKey) -> Self {
        Self(Hash::keyed_digest(b"nullspace-mailbox", &key.to_bytes()))
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Hash::from_bytes(bytes))
    }
}

/// An entry stored in a mailbox, with metadata added by the server.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MailboxEntry {
    pub body: Blob,
    pub received_at: NanoTimestamp,
}

/// A mailbox read key.
#[serde_as]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize, PartialOrd, Ord)]
pub struct MailboxKey(#[serde_as(as = "IfIsHumanReadable<Hex, SerdeBytes>")] [u8; 20]);

impl MailboxKey {
    pub fn random() -> Self {
        Self(rand::random())
    }

    pub fn to_bytes(&self) -> [u8; 20] {
        self.0
    }

    pub fn mailbox_id(&self) -> MailboxId {
        MailboxId::from_key(self)
    }
}

/// Arguments for receiving messages from a single mailbox.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MailboxRecvArgs {
    pub mailbox: MailboxId,
    pub mailbox_key: MailboxKey,
    pub after: NanoTimestamp,
}
