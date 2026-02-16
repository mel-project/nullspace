use std::{
    sync::{Arc, LazyLock},
    time::Duration,
};

use anyhow::Context;
use nanorpc::DynRpcTransport;
use nullspace_crypt::hash::Hash;
use nullspace_rpc_pool::RpcPool;
use nullspace_structs::directory::{
    DirectoryAnchor, DirectoryChunk, DirectoryClient, DirectoryErr, DirectoryUpdate, PowSolution,
};
use tokio::sync::RwLock;
use url::Url;

use crate::{
    db,
    server::{apply_updates_for_key, load_value_from_smt},
    state::DirectoryState,
};

const MIRROR_POLL_SECS: u64 = 2;
static RPC_POOL: LazyLock<RpcPool> = LazyLock::new(RpcPool::new);

pub struct MirrorState {
    pub client: DirectoryClient<DynRpcTransport>,
    pub anchor: RwLock<Option<DirectoryAnchor>>,
}

impl MirrorState {
    pub fn new(endpoint: Url) -> Self {
        let transport = RPC_POOL.rpc(endpoint);
        let client = DirectoryClient::from(transport);
        Self {
            client,
            anchor: RwLock::new(None),
        }
    }
}

pub async fn forward_insert(
    mirror: &MirrorState,
    update: DirectoryUpdate,
    pow_solution: PowSolution,
) -> Result<(), DirectoryErr> {
    match mirror.client.v1_insert_update(update, pow_solution).await {
        Ok(res) => res,
        Err(err) => {
            tracing::warn!(error = ?err, "mirror insert upstream failed");
            Err(DirectoryErr::RetryLater)
        }
    }
}

pub async fn run_mirror_sync(state: Arc<DirectoryState>) {
    let Some(mirror) = state.mirror.clone() else {
        return;
    };
    loop {
        if let Err(err) = sync_once(&state, &mirror).await {
            tracing::warn!(error = ?err, "mirror sync failed");
        }
        tokio::time::sleep(Duration::from_secs(MIRROR_POLL_SECS)).await;
    }
}

async fn sync_once(state: &DirectoryState, mirror: &MirrorState) -> anyhow::Result<()> {
    let anchor = mirror
        .client
        .v1_get_anchor()
        .await?
        .map_err(|err| anyhow::anyhow!(err.to_string()))?;

    let (last_height, last_hash) = load_local_head(&state.pool).await?;
    if let Some(height) = last_height {
        if height > anchor.last_header_height {
            tracing::warn!(
                local_height = height,
                anchor_height = anchor.last_header_height,
                "local directory ahead of mirror anchor"
            );
            return Ok(());
        }
        if height == anchor.last_header_height {
            if last_hash != anchor.last_header_hash {
                anyhow::bail!("local header hash mismatch at anchor height");
            }
            *mirror.anchor.write().await = Some(anchor);
            return Ok(());
        }
    }

    let mut next = match last_height {
        Some(height) => height + 1,
        None => 0,
    };
    while next <= anchor.last_header_height {
        let chunk = mirror
            .client
            .v1_get_chunk(next)
            .await?
            .map_err(|err| anyhow::anyhow!(err.to_string()))?;
        apply_chunk(state, next, &chunk).await?;
        next += 1;
    }

    let (last_height, last_hash) = load_local_head(&state.pool).await?;
    if last_height == Some(anchor.last_header_height) && last_hash == anchor.last_header_hash {
        *mirror.anchor.write().await = Some(anchor);
    }

    Ok(())
}

async fn load_local_head(pool: &sqlx::SqlitePool) -> anyhow::Result<(Option<u64>, Hash)> {
    match db::load_last_header(pool).await? {
        Some((height, header)) => {
            let hash = Hash::digest(&bcs::to_bytes(&header)?);
            Ok((Some(height), hash))
        }
        None => Ok((None, Hash::from_bytes([0u8; 32]))),
    }
}

async fn apply_chunk(
    state: &DirectoryState,
    height: u64,
    chunk: &DirectoryChunk,
) -> anyhow::Result<()> {
    let last_header = db::load_last_header(&state.pool).await?;
    let (expected_height, expected_prev, previous_root) = match &last_header {
        Some((last_height, header)) => {
            let prev_hash = Hash::digest(&bcs::to_bytes(header)?);
            (*last_height + 1, prev_hash, Some(header.smt_root))
        }
        None => (0, Hash::from_bytes([0u8; 32]), None),
    };
    if height != expected_height {
        anyhow::bail!("unexpected chunk height {height}, expected {expected_height}");
    }
    if chunk.header.prev != expected_prev {
        anyhow::bail!("chunk prev hash mismatch at height {height}");
    }

    let mut tree = match previous_root {
        Some(root) => novasmt::Tree::open(state.merkle.as_ref(), root.to_bytes()),
        None => novasmt::Tree::empty(state.merkle.as_ref()),
    };
    for (key, updates) in &chunk.updates {
        let committed = match previous_root {
            Some(root) => load_value_from_smt(state, root, key)
                .await
                .map_err(|err| anyhow::anyhow!(err.to_string()))?
                .map(bytes::Bytes::from),
            None => None,
        };
        let next = apply_updates_for_key(key.as_str(), committed, updates)
            .map_err(|err| anyhow::anyhow!(err.to_string()))?;
        let key_hash = Hash::digest(key.as_bytes());
        let val = next.map(|value| value.to_vec()).unwrap_or_default();
        tree = tree.with(key_hash.to_bytes(), &val)?;
    }

    let smt_root = tree.commit()?;
    state.merkle.flush();
    let smt_hash = Hash::from_bytes(smt_root);
    if smt_hash != chunk.header.smt_root {
        anyhow::bail!("chunk smt root mismatch at height {height}");
    }

    let header_hash = Hash::digest(&bcs::to_bytes(&chunk.header)?);
    db::insert_chunk(&state.pool, height, &chunk.header, &header_hash, chunk)
        .await
        .context("insert mirrored chunk")?;
    tracing::debug!(height, "mirrored directory chunk");
    Ok(())
}
