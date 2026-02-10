use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use nullspace_client::internal::UserDetails;
use nullspace_structs::username::UserName;
use tracing::warn;

pub fn path_for_user(dir: &Path, username: &UserName) -> PathBuf {
    dir.join(format!("{}.json", username.as_str()))
}

pub fn load_all(dir: &Path) -> HashMap<UserName, UserDetails> {
    let mut out = HashMap::new();
    let Ok(entries) = fs::read_dir(dir) else {
        return out;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        match fs::read_to_string(&path)
            .ok()
            .and_then(|data| serde_json::from_str::<UserDetails>(&data).ok())
        {
            Some(details) => {
                out.insert(details.username.clone(), details);
            }
            None => {
                warn!(path = %path.display(), "failed to read cached profile");
            }
        }
    }

    out
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
