use std::sync::Arc;

use axum::{
    extract::State,
    http::{StatusCode, header},
    response::IntoResponse,
};
use bytes::Bytes;
use nanorpc::{JrpcRequest, RpcService};
use serde_json::json;
use xirtam_crypt::hash::Hash;
use xirtam_structs::directory::{
    DirectoryAnchor, DirectoryChunk, DirectoryErr, DirectoryHeader, DirectoryHistoryIterExt,
    DirectoryProtocol, DirectoryResponse, DirectoryService, DirectoryUpdate, PowAlgo, PowSeed,
    PowSolution,
};
use xirtam_structs::timestamp::Timestamp;

use crate::{
    db, pow,
    state::{DirectoryState, StagingChunk},
};

#[derive(Clone)]
pub struct DirectoryServer {
    state: Arc<DirectoryState>,
}

impl DirectoryServer {
    pub fn new(state: Arc<DirectoryState>) -> Self {
        Self { state }
    }
}

pub async fn handle_rpc(
    State(state): State<Arc<DirectoryState>>,
    body: Bytes,
) -> impl IntoResponse {
    let req: JrpcRequest = match serde_json::from_slice(&body) {
        Ok(req) => req,
        Err(err) => {
            let resp = json!({
                "jsonrpc": "2.0",
                "error": { "code": -32700, "message": "Parse error", "data": err.to_string() },
                "id": json!(null),
            });
            return (
                StatusCode::BAD_REQUEST,
                [(header::CONTENT_TYPE, "application/json")],
                serde_json::to_vec(&resp).unwrap(),
            );
        }
    };
    let service = DirectoryService(DirectoryServer::new(state));
    let response = service.respond_raw(req).await;
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        serde_json::to_vec(&response).unwrap(),
    )
}

#[async_trait::async_trait]
impl DirectoryProtocol for DirectoryServer {
    async fn v1_get_pow_seed(&self) -> PowSeed {
        let seed = pow::new_seed();
        if let Err(err) = db::insert_pow_seed(&self.state.pool, &seed, pow::POW_EFFORT).await {
            tracing::warn!(error = ?err, "failed to insert pow seed");
        }
        if let Err(err) = db::purge_pow_seeds(&self.state.pool, unix_time()).await {
            tracing::warn!(error = ?err, "failed to purge pow seeds");
        }
        seed
    }

    async fn v1_get_anchor(&self) -> Result<DirectoryAnchor, DirectoryErr> {
        let (height, hash) = db::load_last_header(&self.state.pool)
            .await
            .map_err(map_db_err)?;
        let mut anchor = DirectoryAnchor {
            directory_id: self.state.directory_id.clone(),
            last_header_height: height,
            last_header_hash: hash,
            signature: xirtam_crypt::signing::Signature::from_bytes([0u8; 64]),
        };
        anchor.sign(&self.state.secret_key);
        Ok(anchor)
    }

    async fn v1_get_chunk(&self, height: u64) -> Result<DirectoryChunk, DirectoryErr> {
        db::load_chunk(&self.state.pool, height)
            .await
            .map_err(map_db_err)?
            .ok_or_else(|| DirectoryErr::UpdateRejected("chunk not found".into()))
    }

    async fn v1_get_headers(
        &self,
        first: u64,
        last: u64,
    ) -> Result<Vec<DirectoryHeader>, DirectoryErr> {
        db::load_headers(&self.state.pool, first, last)
            .await
            .map_err(map_db_err)
    }

    async fn v1_get_item(&self, key: String) -> Result<DirectoryResponse, DirectoryErr> {
        let (height, _) = db::load_last_header(&self.state.pool)
            .await
            .map_err(map_db_err)?;
        let history = db::load_updates_for_key(&self.state.pool, &key, height)
            .await
            .map_err(map_db_err)?;
        let root = match db::load_header(&self.state.pool, height)
            .await
            .map_err(map_db_err)?
        {
            Some(header) => header.smt_root,
            None => Hash::from_bytes([0u8; 32]),
        };
        let proof = build_proof(&self.state, &key, root).await?;
        Ok(DirectoryResponse {
            history,
            proof_height: height,
            proof_merkle_branch: proof,
        })
    }

    async fn v1_insert_update(
        &self,
        key: String,
        update: DirectoryUpdate,
        pow_solution: PowSolution,
    ) -> Result<(), DirectoryErr> {
        let now = unix_time();
        db::purge_pow_seeds(&self.state.pool, now)
            .await
            .map_err(map_db_err)?;
        let Some((use_before, effort)) = db::fetch_pow_seed(&self.state.pool, &pow_solution.seed)
            .await
            .map_err(map_db_err)?
        else {
            return Err(DirectoryErr::UpdateRejected("unknown pow seed".into()));
        };
        if use_before <= now {
            return Err(DirectoryErr::UpdateRejected("pow seed expired".into()));
        }
        let seed = PowSeed {
            algo: PowAlgo::EquiX { effort },
            seed: pow_solution.seed,
            use_before: Timestamp(use_before),
        };
        pow::validate_solution(&seed, effort, &pow_solution)?;

        let last_height = db::load_last_header(&self.state.pool)
            .await
            .map_err(map_db_err)?
            .0;
        let mut history = db::load_updates_for_key(&self.state.pool, &key, last_height)
            .await
            .map_err(map_db_err)?;
        let mut staging = self.state.staging.lock().await;
        if let Some(pending) = staging.updates.get(&key) {
            history.extend(pending.iter().cloned());
        }
        history.push(update.clone());
        history
            .iter()
            .verify_history()
            .map_err(|err| DirectoryErr::UpdateRejected(err.to_string()))?;
        staging.updates.entry(key).or_default().push(update);
        Ok(())
    }
}

pub async fn commit_chunk(state: Arc<DirectoryState>) -> anyhow::Result<()> {
    let chunk = {
        let mut staging = state.staging.lock().await;
        let chunk = StagingChunk {
            height: staging.height,
            updates: std::mem::take(&mut staging.updates),
        };
        staging.height += 1;
        chunk
    };

    if !chunk.updates.is_empty() {
        let (last_height, _) = db::load_last_header(&state.pool).await?;
        for (key, list) in &chunk.updates {
            let mut history = db::load_updates_for_key(&state.pool, key, last_height).await?;
            history.extend(list.iter().cloned());
            history
                .iter()
                .verify_history()
                .map_err(|err| anyhow::anyhow!(err.to_string()))?;
        }
    }

    let height = chunk.height;
    let updates = &chunk.updates;

    let prev_hash = db::load_last_header(&state.pool).await?.1;
    let mut tree = novasmt::Tree::empty(state.merkle.as_ref());
    for (key, list) in updates {
        let key_hash = Hash::digest(key.as_bytes());
        let val = bcs::to_bytes(list)?;
        tree = tree.with(key_hash.to_bytes(), &val)?;
    }
    let smt_root = tree.commit()?;
    state.merkle.flush();

    let update_count: usize = updates.values().map(|list| list.len()).sum();
    let header = DirectoryHeader {
        prev: prev_hash,
        smt_root: Hash::from_bytes(smt_root),
        time_unix: unix_time(),
    };
    let header_hash = Hash::digest(&bcs::to_bytes(&header)?);
    let chunk = DirectoryChunk {
        header,
        updates: chunk.updates,
    };
    db::insert_chunk(&state.pool, height, &chunk.header, &header_hash, &chunk).await?;
    tracing::debug!(height, update_count, "committed directory chunk");
    Ok(())
}

async fn build_proof(
    state: &DirectoryState,
    key: &str,
    root: Hash,
) -> Result<Vec<Hash>, DirectoryErr> {
    let tree = novasmt::Tree::open(state.merkle.as_ref(), root.to_bytes());
    let key_hash = Hash::digest(key.as_bytes());
    let (_val, proof) = tree
        .get_with_proof(key_hash.to_bytes())
        .map_err(|_| DirectoryErr::RetryLater)?;
    Ok(proof.0.into_iter().map(Hash::from_bytes).collect())
}

fn map_db_err(err: anyhow::Error) -> DirectoryErr {
    tracing::warn!(error = ?err, "database error");
    DirectoryErr::RetryLater
}

fn unix_time() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
