use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConvoRowStyle {
    Text,
    Friendly,
}

impl ConvoRowStyle {
    pub fn label(self) -> &'static str {
        match self {
            Self::Text => "Text",
            Self::Friendly => "Friendly",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PrefData {
    pub zoom_percent: u16,
    pub max_auto_image_download_bytes: Option<u64>,
    pub convo_row_style: ConvoRowStyle,
}

impl Default for PrefData {
    fn default() -> Self {
        Self {
            zoom_percent: 100,
            max_auto_image_download_bytes: Some(1_000_000),
            convo_row_style: ConvoRowStyle::Friendly,
        }
    }
}
