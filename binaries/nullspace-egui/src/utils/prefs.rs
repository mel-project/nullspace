use serde::{Deserialize, Serialize};

const MB: u64 = 1_000_000;

pub const IMAGE_AUTO_DOWNLOAD_OPTIONS: &[(Option<u64>, &str)] = &[
    (None, "None"),
    (Some(MB), "1 MB"),
    (Some(5 * MB), "5 MB"),
    (Some(10 * MB), "10 MB"),
    (Some(20 * MB), "20 MB"),
    (Some(50 * MB), "50 MB"),
];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PrefData {
    pub zoom_percent: u16,
    pub max_auto_image_download_bytes: Option<u64>,
}

impl Default for PrefData {
    fn default() -> Self {
        Self {
            zoom_percent: 100,
            max_auto_image_download_bytes: Some(10 * MB),
        }
    }
}

pub fn label_for_auto_image_limit(limit: Option<u64>) -> &'static str {
    IMAGE_AUTO_DOWNLOAD_OPTIONS
        .iter()
        .find_map(|(bytes, label)| (*bytes == limit).then_some(*label))
        .unwrap_or("Custom")
}
