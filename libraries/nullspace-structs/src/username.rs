use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;
use std::sync::LazyLock;

use bytes::Bytes;
use nullspace_crypt::{
    hash::{BcsHashExt, Hash},
    signing::{Signable, Signature, SigningPublic},
};
use regex::Regex;
use serde::{Deserialize, Deserializer, Serialize};
use smol_str::{SmolStr, format_smolstr};
use thiserror::Error;

use crate::directory::DirectoryUpdate;
use crate::server::ServerName;
use crate::timestamp::Timestamp;

/// A username that matches the rules for usernames.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct UserName(SmolStr);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserDescriptor {
    pub server_name: Option<ServerName>,
    pub nonce_max: u64,
    pub devices: BTreeMap<Hash, DeviceState>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceState {
    pub device_pk: SigningPublic,
    pub can_issue: bool,
    pub expiry: Timestamp,
    pub active: bool,
}

impl DeviceState {
    pub fn hash(&self) -> Hash {
        self.device_pk.bcs_hash()
    }

    pub fn is_expired(&self, now_unix: u64) -> bool {
        self.expiry.0 <= now_unix
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum UserAction {
    AddDevice {
        device_pk: SigningPublic,
        can_issue: bool,
        expiry: Timestamp,
    },
    RemoveDevice {
        device_pk: SigningPublic,
    },
    BindServer {
        server_name: ServerName,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PreparedUserAction {
    pub username: UserName,
    pub nonce: u64,
    pub signer_pk: SigningPublic,
    pub action: UserAction,
    pub next_descriptor: UserDescriptor,
    pub signature: Signature,
}

impl PreparedUserAction {
    pub fn to_directory_update(&self) -> anyhow::Result<DirectoryUpdate> {
        let value = Some(Bytes::from(bcs::to_bytes(&self.next_descriptor)?));
        let owners = self.next_descriptor.owner_keys();
        Ok(DirectoryUpdate {
            key: self.username.as_str().to_owned(),
            nonce: self.nonce,
            signer_pk: self.signer_pk,
            owners,
            value,
            signature: self.signature,
        })
    }
}

impl Signable for PreparedUserAction {
    fn signed_value(&self) -> Vec<u8> {
        let value = Some(Bytes::from(
            bcs::to_bytes(&self.next_descriptor).expect("bcs serialization failed"),
        ));
        let owners = self.next_descriptor.owner_keys();
        bcs::to_bytes(&(
            &self.username.as_str(),
            &self.nonce,
            &self.signer_pk,
            &owners,
            &value,
        ))
        .expect("bcs serialization failed")
    }

    fn signature_mut(&mut self) -> &mut Signature {
        &mut self.signature
    }

    fn signature(&self) -> &Signature {
        &self.signature
    }
}

impl UserDescriptor {
    pub fn owner_keys(&self) -> Vec<SigningPublic> {
        let mut owners: Vec<SigningPublic> = self
            .devices
            .values()
            .filter(|state| state.active)
            .map(|state| state.device_pk)
            .collect();
        owners.sort_by(|a, b| a.to_bytes().cmp(&b.to_bytes()));
        owners.dedup();
        owners
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[error("invalid format for username")]
pub struct UserNameError;

impl UserName {
    pub fn parse(username: impl AsRef<str>) -> Result<Self, UserNameError> {
        let username = username.as_ref();
        if USERNAME_RE.is_match(username) {
            return Ok(Self(SmolStr::new(username)));
        }
        let username_with_at = format_smolstr!("@{username}");
        if USERNAME_RE.is_match(&username_with_at) {
            return Ok(Self(username_with_at));
        }
        Err(UserNameError)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for UserName {
    type Err = UserNameError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl fmt::Display for UserName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl TryFrom<SmolStr> for UserName {
    type Error = UserNameError;

    fn try_from(value: SmolStr) -> Result<Self, Self::Error> {
        if !USERNAME_RE.is_match(value.as_str()) {
            return Err(UserNameError);
        }
        Ok(Self(value))
    }
}

impl<'de> Deserialize<'de> for UserName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = SmolStr::deserialize(deserializer)?;
        UserName::try_from(value).map_err(serde::de::Error::custom)
    }
}

static USERNAME_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^@[A-Za-z0-9_]{5,15}$").expect("valid username regex"));

#[cfg(test)]
mod tests {
    use super::UserName;

    #[test]
    fn username_roundtrip() {
        let username = UserName::parse("@user_01").expect("valid username");
        assert_eq!(username.as_str(), "@user_01");
    }
}
