use std::fs;
use std::path::{Path, PathBuf};

use nullspace_client::UserDetails;
use nullspace_structs::username::UserName;
use tracing::warn;

pub fn path_for_user(dir: &Path, username: &UserName) -> PathBuf {
    dir.join(format!("{}.json", username.as_str()))
}

pub fn load_entry(dir: &Path, username: &UserName) -> Option<UserDetails> {
    let path = path_for_user(dir, username);
    let data = fs::read_to_string(&path).ok()?;
    match serde_json::from_str::<UserDetails>(&data) {
        Ok(details) => Some(details),
        Err(err) => {
            warn!(error = %err, path = %path.display(), "failed to parse cached profile");
            None
        }
    }
}

pub fn write_entry(dir: &Path, details: &UserDetails) {
    if dir.as_os_str().is_empty() {
        return;
    }
    if let Err(err) = fs::create_dir_all(dir) {
        warn!(error = %err, path = %dir.display(), "failed to create profile cache dir");
        return;
    }
    let path = path_for_user(dir, &details.username);
    match serde_json::to_string_pretty(details) {
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
