use std::{collections::BTreeMap, sync::Arc};

use nullspace_crypt::signing::SigningSecret;
use nullspace_structs::directory::DirectoryUpdate;
use smol_str::SmolStr;
use sqlx::SqlitePool;
use tokio::sync::Mutex;

use crate::merkle::MeshaNodeStore;
use crate::mirror::MirrorState;

pub struct DirectoryState {
    pub pool: SqlitePool,
    pub merkle: Arc<MeshaNodeStore>,
    pub secret_key: Option<SigningSecret>,
    pub directory_id: SmolStr,
    pub staging: Mutex<BTreeMap<String, Vec<DirectoryUpdate>>>,
    pub mirror: Option<Arc<MirrorState>>,
}
