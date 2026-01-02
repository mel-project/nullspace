use std::{collections::BTreeMap, sync::Arc};

use smol_str::SmolStr;
use sqlx::SqlitePool;
use tokio::sync::Mutex;
use xirtam_crypt::signing::SigningSecret;
use xirtam_structs::directory::DirectoryUpdate;

use crate::merkle::MeshaNodeStore;

#[derive(Debug, Default)]
pub struct StagingChunk {
    pub height: u64,
    pub updates: BTreeMap<String, Vec<DirectoryUpdate>>,
}

pub struct DirectoryState {
    pub pool: SqlitePool,
    pub merkle: Arc<MeshaNodeStore>,
    pub secret_key: SigningSecret,
    pub directory_id: SmolStr,
    pub staging: Mutex<StagingChunk>,
}
