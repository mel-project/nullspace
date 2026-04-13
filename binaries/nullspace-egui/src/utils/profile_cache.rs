use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use nullspace_client::UserDetails;
use nullspace_structs::username::UserName;
use serde::{Deserialize, Serialize};
use tracing::warn;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CachedProfile {
    pub details: UserDetails,
    pub cached_at_unix_secs: u64,
}

pub fn path_for_user(dir: &Path, username: &UserName) -> PathBuf {
    dir.join(format!("{}.json", username.as_str()))
}

pub fn load_entry(dir: &Path, username: &UserName) -> Option<CachedProfile> {
    let path = path_for_user(dir, username);
    let data = fs::read_to_string(&path).ok()?;
    if let Ok(entry) = serde_json::from_str::<CachedProfile>(&data) {
        return Some(entry);
    }
    match serde_json::from_str::<UserDetails>(&data) {
        Ok(details) => Some(CachedProfile {
            details,
            // Legacy cache entries have no timestamp, so treat them as stale.
            cached_at_unix_secs: 0,
        }),
        Err(err) => {
            warn!(error = %err, path = %path.display(), "failed to parse cached profile");
            None
        }
    }
}

pub fn write_entry(dir: &Path, entry: &CachedProfile) {
    if dir.as_os_str().is_empty() {
        return;
    }
    if let Err(err) = fs::create_dir_all(dir) {
        warn!(error = %err, path = %dir.display(), "failed to create profile cache dir");
        return;
    }
    let path = path_for_user(dir, &entry.details.username);
    match serde_json::to_string_pretty(entry) {
        Ok(data) => {
            if let Err(err) = fs::write(&path, data) {
                warn!(error = %err, path = %path.display(), "failed to write cached profile");
            }
        }
        Err(err) => {
            warn!(error = %err, "failed to serialize cached profile");
        }
    }
}

pub fn fresh_entry(details: UserDetails) -> CachedProfile {
    CachedProfile {
        details,
        cached_at_unix_secs: current_unix_secs(),
    }
}

pub fn current_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
