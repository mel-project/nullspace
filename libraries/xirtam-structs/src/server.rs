use std::sync::LazyLock;
use std::{collections::BTreeMap, fmt, str::FromStr};

use async_trait::async_trait;
use nanorpc::nanorpc_derive;
use regex::Regex;
use serde::{Deserialize, Deserializer, Serialize};
use serde_with::hex::Hex;
use serde_with::{Bytes, IfIsHumanReadable, serde_as};
use smol_str::SmolStr;
use thiserror::Error;
use url::Url;
use xirtam_crypt::dh::DhPublic;
use xirtam_crypt::signing::{Signable, Signature};
use xirtam_crypt::{hash::Hash, signing::SigningPublic};

use crate::certificate::CertificateChain;
use crate::group::GroupId;
use crate::timestamp::Timestamp;
use crate::{Blob, username::UserName, timestamp::NanoTimestamp};

/// The RPC protocol implemented by servers.
#[nanorpc_derive]
#[async_trait]
pub trait ServerProtocol {
    /// Authenticates a device, returning the AuthToken proper to it. This is idempotent and should only return one AuthToken per unique device. If the device successfully authenticates, and this server is proper to the username, the device certificate chain served to others is updated for that device.
    async fn v1_device_auth(
        &self,
        username: UserName,
        cert: CertificateChain,
    ) -> Result<AuthToken, ServerRpcError>;

    /// Retrieve the devices for a given username.
    async fn v1_device_certs(
        &self,
        username: UserName,
    ) -> Result<Option<BTreeMap<Hash, CertificateChain>>, ServerRpcError>;

    /// Retrieve the medium-term keys for a given username.
    async fn v1_device_medium_pks(
        &self,
        username: UserName,
    ) -> Result<BTreeMap<Hash, SignedMediumPk>, ServerRpcError>;

    /// Store a device's medium-term public key.
    async fn v1_device_add_medium_pk(
        &self,
        auth: AuthToken,
        medium_pk: SignedMediumPk,
    ) -> Result<(), ServerRpcError>;

    /// Send a message into a mailbox.
    async fn v1_mailbox_send(
        &self,
        auth: AuthToken,
        mailbox: MailboxId,
        message: Blob,
    ) -> Result<NanoTimestamp, ServerRpcError>;

    /// Receive one or more messages, from one or many mailboxes. This is batched to make long-polling more efficient. The server may choose to limit the number of messages in the response, so clients should be prepared to repeat until getting an empty "page".
    async fn v1_mailbox_multirecv(
        &self,
        args: Vec<MailboxRecvArgs>,
        timeout_ms: u64,
    ) -> Result<BTreeMap<MailboxId, Vec<MailboxEntry>>, ServerRpcError>;

    /// Edit the mailbox ACL.
    async fn v1_mailbox_acl_edit(
        &self,
        auth: AuthToken,
        mailbox: MailboxId,
        arg: MailboxAcl,
    ) -> Result<(), ServerRpcError>;

    /// Create group mailboxes and grant the caller full ACL rights.
    async fn v1_register_group(
        &self,
        auth: AuthToken,
        group: GroupId,
    ) -> Result<(), ServerRpcError>;
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SignedMediumPk {
    pub medium_pk: DhPublic,
    pub created: Timestamp,
    pub signature: Signature,
}

impl Signable for SignedMediumPk {
    fn signed_value(&self) -> Vec<u8> {
        bcs::to_bytes(&(&self.medium_pk, &self.created)).unwrap()
    }

    fn signature_mut(&mut self) -> &mut Signature {
        &mut self.signature
    }

    fn signature(&self) -> &Signature {
        &self.signature
    }
}

/// Arguments for receiving messages from a single mailbox.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MailboxRecvArgs {
    pub auth: AuthToken,
    pub mailbox: MailboxId,
    pub after: NanoTimestamp,
}

/// A server name that matches the rules for server names.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, PartialOrd, Ord)]
#[serde(transparent)]
pub struct ServerName(SmolStr);

#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[error("invalid server name")]
pub struct ServerNameError;

impl ServerName {
    pub fn parse(name: impl AsRef<str>) -> Result<Self, ServerNameError> {
        let name = name.as_ref();
        if !SERVER_NAME_RE.is_match(name) {
            return Err(ServerNameError);
        }
        Ok(Self(SmolStr::new(name)))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for ServerName {
    type Err = ServerNameError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl fmt::Display for ServerName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl TryFrom<SmolStr> for ServerName {
    type Error = ServerNameError;

    fn try_from(value: SmolStr) -> Result<Self, Self::Error> {
        if !SERVER_NAME_RE.is_match(value.as_str()) {
            return Err(ServerNameError);
        }
        Ok(Self(value))
    }
}

impl<'de> Deserialize<'de> for ServerName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = SmolStr::deserialize(deserializer)?;
        ServerName::try_from(value).map_err(serde::de::Error::custom)
    }
}

static SERVER_NAME_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^~[A-Za-z0-9_]{5,15}$").expect("valid server name regex"));

/// A server descriptor stored at the directory.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ServerDescriptor {
    /// All the *publicly* available URLs for this server.
    pub public_urls: Vec<Url>,
    /// The public key of the server, used for authentication.
    pub server_pk: SigningPublic,
}

/// A mailbox ID at a server, wrapping a hash value.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(transparent)]
pub struct MailboxId(Hash);

impl MailboxId {
    /// Gets the mailbox ID for DMs to the given username
    pub fn direct(username: &UserName) -> Self {
        Self(Hash::keyed_digest(
            b"direct-mailbox",
            username.as_str().as_bytes(),
        ))
    }

    /// Gets the mailbox ID for a given group
    pub fn group(group: &GroupId) -> Self {
        Self::group_messages(group)
    }

    /// Gets the mailbox ID for group messages
    pub fn group_messages(group: &GroupId) -> Self {
        Self(Hash::keyed_digest(b"group-messages", &group.as_bytes()))
    }

    /// Gets the mailbox ID for group management messages
    pub fn group_management(group: &GroupId) -> Self {
        Self(Hash::keyed_digest(b"group-management", &group.as_bytes()))
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

/// An entry stored in a mailbox, with metadata added by the server.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MailboxEntry {
    pub message: Blob,
    pub received_at: NanoTimestamp,
    pub sender_auth_token_hash: Option<Hash>,
}

/// An ACL for a mailbox.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MailboxAcl {
    pub token_hash: Hash,
    pub can_edit_acl: bool,
    pub can_send: bool,
    pub can_recv: bool,
}

/// An opaque authentication token.
#[serde_as]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize, PartialOrd, Ord)]
pub struct AuthToken(#[serde_as(as = "IfIsHumanReadable<Hex, Bytes>")] [u8; 20]);

impl AuthToken {
    /// Generates a new random authentication token.
    pub fn random() -> Self {
        Self(rand::random())
    }

    /// Returns the all-zero authentication token for implicit ACL matching.
    pub fn anonymous() -> Self {
        Self(Default::default())
    }

    pub fn to_bytes(&self) -> [u8; 20] {
        self.0
    }
}

/// An error from the server.
#[derive(Error, Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ServerRpcError {
    #[error("access denied")]
    AccessDenied,
    #[error("rate limited, retry later")]
    RetryLater,
}

#[cfg(test)]
mod tests {
    use super::ServerName;

    #[test]
    fn server_name_roundtrip() {
        let name = ServerName::parse("~serv_01").expect("valid server name");
        assert_eq!(name.as_str(), "~serv_01");
    }
}
