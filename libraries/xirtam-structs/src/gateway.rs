use std::str::FromStr;
use std::sync::LazyLock;

use async_trait::async_trait;
use nanorpc::nanorpc_derive;
use regex::Regex;
use serde::{Deserialize, Deserializer, Serialize};
use smol_str::SmolStr;
use thiserror::Error;
use url::Url;
use xirtam_crypt::{hash::Hash, signing::SigningPublic};

use crate::{Message, handle::Handle};

#[nanorpc_derive]
#[async_trait]
/// The RPC protocol implemented by gateway servers.
pub trait GatewayProtocol {
    /// Send a message into a mailbox.
    async fn v1_mailbox_send(
        &self,
        auth: AuthToken,
        mailbox: MailboxId,
        message: Message,
    ) -> Result<(), MailboxError>;

    /// Receive a message from a mailbox.
    async fn v1_mailbox_recv(
        &self,
        auth: AuthToken,
        mailbox: MailboxId,
        timeout_ms: u64,
    ) -> Result<Message, MailboxError>;
}

/// A gateway name that matches the rules for gateway names.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
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
pub struct GatewayDescriptor {
    /// All the *publicly* available URLs for this gateway.
    pub public_urls: Vec<Url>,
    /// The public key of the gateway, used for authentication.
    pub gateway_pk: SigningPublic,
}

/// A mailbox ID at a gateway, wrapping a hash value.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MailboxId(Hash);

impl MailboxId {
    /// Gets the mailbox ID for sending DMs to the given handle
    pub fn direct(handle: &Handle) -> Self {
        Self(Hash::keyed_digest(
            b"direct-mailbox",
            handle.as_str().as_bytes(),
        ))
    }
}

/// An opaque authentication token.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AuthToken(Hash);

impl AuthToken {
    /// Generates a new random authentication token.
    pub fn random() -> Self {
        Self(Hash::from_bytes(rand::random()))
    }
}

/// An error when handling mailboxes.
#[derive(Error, Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MailboxError {
    #[error("access denied to mailbox")]
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
