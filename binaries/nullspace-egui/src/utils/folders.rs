use std::path::{Path, PathBuf};
use std::sync::OnceLock;

static ROOT_DIR: OnceLock<PathBuf> = OnceLock::new();

pub fn init(override_dir: Option<PathBuf>) -> Result<&'static Path, String> {
    let dir = override_dir.unwrap_or_else(default_root_dir);
    if let Err(err) = std::fs::create_dir_all(&dir) {
        return Err(format!("failed to create app data dir: {err}"));
    }
    if ROOT_DIR.set(dir).is_err() {
        return Err("folders already initialized".to_string());
    }
    Ok(root_dir())
}

pub fn root_dir() -> &'static Path {
    ROOT_DIR
        .get()
        .map(|p| p.as_path())
        .expect("folders not initialized")
}

pub fn db_path() -> PathBuf {
    root_dir().join("nullspace-client.db")
}

pub fn prefs_path() -> PathBuf {
    root_dir().join("nullspace-egui.json")
}

pub fn profile_cache_dir() -> PathBuf {
    root_dir().join("profile-cache")
}

pub fn avatar_cache_dir() -> PathBuf {
    root_dir().join("avatars")
}

pub fn image_cache_dir() -> PathBuf {
    root_dir().join("images")
}

pub fn pasted_images_dir() -> PathBuf {
    root_dir().join("pasted-images")
}

fn default_root_dir() -> PathBuf {
    let base = dirs::data_local_dir()
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("nullspace-egui")
}
