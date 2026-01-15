use std::fmt;
use std::str::FromStr;
use std::sync::LazyLock;

use regex::Regex;
use serde::{Deserialize, Deserializer, Serialize};
use smol_str::SmolStr;
use thiserror::Error;
use xirtam_crypt::hash::Hash;

use crate::server::ServerName;

/// A username that matches the rules for usernames.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct UserName(SmolStr);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserDescriptor {
    pub server_name: ServerName,
    pub root_cert_hash: Hash,
}

#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[error("invalid username")]
pub struct UserNameError;

impl UserName {
    pub fn parse(username: impl AsRef<str>) -> Result<Self, UserNameError> {
        let username = username.as_ref();
        if !USERNAME_RE.is_match(username) {
            return Err(UserNameError);
        }
        Ok(Self(SmolStr::new(username)))
    }

    pub fn placeholder() -> Self {
        Self(SmolStr::new("@placeholder"))
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
