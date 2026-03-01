use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use thiserror::Error;
use uuid::Uuid;

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Hash)]
#[serde(transparent)]
pub struct GroupId(Uuid);

#[derive(Debug, Error)]
#[error("invalid group id")]
pub struct GroupIdParseError;

impl GroupId {
    pub fn random() -> Self {
        Self(Uuid::new_v4())
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
