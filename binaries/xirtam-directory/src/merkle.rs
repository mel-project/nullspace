use std::{borrow::Cow, path::Path, path::PathBuf, sync::Arc};

use anyhow::Context;
use meshanina::Mapping;
use novasmt::{NodeStore, SmtError};

#[derive(Clone)]
pub struct MeshaNodeStore {
    mapping: Arc<Mapping>,
}

impl MeshaNodeStore {
    pub fn open(path: PathBuf) -> anyhow::Result<Self> {
        let mapping = Mapping::open(path).context("open meshanina mapping")?;
        Ok(Self {
            mapping: Arc::new(mapping),
        })
    }

    pub fn flush(&self) {
        self.mapping.flush();
    }
}

impl NodeStore for MeshaNodeStore {
    fn get(&self, key: &[u8]) -> Result<Option<Cow<'_, [u8]>>, SmtError> {
        let key = to_key(key)?;
        Ok(self.mapping.get(key))
    }

    fn insert(&self, key: &[u8], value: &[u8]) -> Result<(), SmtError> {
        let key = to_key(key)?;
        self.mapping.insert(key, value);
        Ok(())
    }
}

fn to_key(key: &[u8]) -> Result<[u8; 32], SmtError> {
    if key.len() != 32 {
        return Err(SmtError::DbCorrupt(anyhow::anyhow!(
            "invalid key length: {}",
            key.len()
        )));
    }
    let mut buf = [0u8; 32];
    buf.copy_from_slice(key);
    Ok(buf)
}

pub fn open_store(db_dir: &Path) -> anyhow::Result<Arc<MeshaNodeStore>> {
    let path = db_dir.join("merkle.db");
    MeshaNodeStore::open(path).map(Arc::new)
}
