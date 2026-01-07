use std::str::FromStr;
use std::sync::LazyLock;

use regex::Regex;
use serde::{Deserialize, Deserializer, Serialize};
use smol_str::SmolStr;
use thiserror::Error;

/// A user handle that matches the rules for user handles.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct Handle(SmolStr);

#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[error("invalid handle")]
pub struct HandleError;

impl Handle {
    pub fn parse(handle: impl AsRef<str>) -> Result<Self, HandleError> {
        let handle = handle.as_ref();
        if !HANDLE_RE.is_match(handle) {
            return Err(HandleError);
        }
        Ok(Self(SmolStr::new(handle)))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for Handle {
    type Err = HandleError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl TryFrom<SmolStr> for Handle {
    type Error = HandleError;

    fn try_from(value: SmolStr) -> Result<Self, Self::Error> {
        if !HANDLE_RE.is_match(value.as_str()) {
            return Err(HandleError);
        }
        Ok(Self(value))
    }
}

impl<'de> Deserialize<'de> for Handle {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = SmolStr::deserialize(deserializer)?;
        Handle::try_from(value).map_err(serde::de::Error::custom)
    }
}

static HANDLE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^@[A-Za-z0-9_]{5,15}$").expect("valid handle regex"));

#[cfg(test)]
mod tests {
    use super::Handle;

    #[test]
    fn handle_roundtrip() {
        let handle = Handle::parse("@user_01").expect("valid handle");
        assert_eq!(handle.as_str(), "@user_01");
    }
}
