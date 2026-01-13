use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrefData {
    pub zoom_percent: u16,
}

impl Default for PrefData {
    fn default() -> Self {
        Self { zoom_percent: 100 }
    }
}
