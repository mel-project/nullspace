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
use crate::{Blob, handle::Handle, timestamp::NanoTimestamp};

/// The RPC protocol implemented by gateway servers.
#[nanorpc_derive]
#[async_trait]
pub trait GatewayProtocol {
    /// Authenticates a device, returning the AuthToken proper to it. This is idempotent and should only return one AuthToken per unique device. If the device successfully authenticates, and this gateway is proper to the handle, the certificate chain served to others is also updated by "merging".
    async fn v1_device_auth(
        &self,
        handle: Handle,
        cert: CertificateChain,
    ) -> Result<AuthToken, GatewayServerError>;

    /// Retrieve the devices for a given handle.
    async fn v1_device_certs(
        &self,
        handle: Handle,
    ) -> Result<Option<CertificateChain>, GatewayServerError>;

    /// Retrieve the medium-term keys for a given handle.
    async fn v1_device_medium_pks(
        &self,
        handle: Handle,
    ) -> Result<BTreeMap<Hash, SignedMediumPk>, GatewayServerError>;

    /// Store a device's medium-term public key.
    async fn v1_device_add_medium_pk(
        &self,
        auth: AuthToken,
        medium_pk: SignedMediumPk,
    ) -> Result<(), GatewayServerError>;

    /// Send a message into a mailbox.
    async fn v1_mailbox_send(
        &self,
        auth: AuthToken,
        mailbox: MailboxId,
        message: Blob,
    ) -> Result<NanoTimestamp, GatewayServerError>;

    /// Receive one or more messages, from one or many mailboxes. This is batched to make long-polling more efficient. The gateway may choose to limit the number of messages in the response, so clients should be prepared to repeat until getting an empty "page".
    async fn v1_mailbox_multirecv(
        &self,
        args: Vec<MailboxRecvArgs>,
        timeout_ms: u64,
    ) -> Result<BTreeMap<MailboxId, Vec<MailboxEntry>>, GatewayServerError>;

    /// Edit the mailbox ACL.
    async fn v1_mailbox_acl_edit(
        &self,
        auth: AuthToken,
        mailbox: MailboxId,
        arg: MailboxAcl,
    ) -> Result<(), GatewayServerError>;

    /// Create group mailboxes and grant the caller full ACL rights.
    async fn v1_register_group(
        &self,
        auth: AuthToken,
        group: GroupId,
    ) -> Result<(), GatewayServerError>;
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

/// A gateway name that matches the rules for gateway names.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, PartialOrd, Ord)]
#[serde(transparent)]
pub struct GatewayName(SmolStr);

#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[error("invalid gateway name")]
pub struct GatewayNameError;

impl GatewayName {
    pub fn parse(name: impl AsRef<str>) -> Result<Self, GatewayNameError> {
        let name = name.as_ref();
        if !GATEWAY_NAME_RE.is_match(name) {
            return Err(GatewayNameError);
        }
        Ok(Self(SmolStr::new(name)))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for GatewayName {
    type Err = GatewayNameError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl fmt::Display for GatewayName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl TryFrom<SmolStr> for GatewayName {
    type Error = GatewayNameError;

    fn try_from(value: SmolStr) -> Result<Self, Self::Error> {
        if !GATEWAY_NAME_RE.is_match(value.as_str()) {
            return Err(GatewayNameError);
        }
        Ok(Self(value))
    }
}

impl<'de> Deserialize<'de> for GatewayName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = SmolStr::deserialize(deserializer)?;
        GatewayName::try_from(value).map_err(serde::de::Error::custom)
    }
}

static GATEWAY_NAME_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^~[A-Za-z0-9_]{5,15}$").expect("valid gateway name regex"));

/// A gateway descriptor stored at the directory.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct GatewayDescriptor {
    /// All the *publicly* available URLs for this gateway.
    pub public_urls: Vec<Url>,
    /// The public key of the gateway, used for authentication.
    pub gateway_pk: SigningPublic,
}

/// A mailbox ID at a gateway, wrapping a hash value.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(transparent)]
pub struct MailboxId(Hash);

impl MailboxId {
    /// Gets the mailbox ID for DMs to the given handle
    pub fn direct(handle: &Handle) -> Self {
        Self(Hash::keyed_digest(
            b"direct-mailbox",
            handle.as_str().as_bytes(),
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

/// An entry stored in a mailbox, with metadata added by the gateway.
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

/// An error from the gateway server.
#[derive(Error, Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GatewayServerError {
    #[error("access denied")]
    AccessDenied,
    #[error("rate limited, retry later")]
    RetryLater,
}

#[cfg(test)]
mod tests {
    use super::GatewayName;

    #[test]
    fn gateway_name_roundtrip() {
        let name = GatewayName::parse("~gate_01").expect("valid gateway name");
        assert_eq!(name.as_str(), "~gate_01");
    }
}
