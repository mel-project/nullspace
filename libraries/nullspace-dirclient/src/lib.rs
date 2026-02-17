#![doc = include_str!(concat!(env!("OUT_DIR"), "/README-rustdocified.md"))]

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

use moka::future::Cache;
use nanorpc::{DynRpcTransport, RpcTransport};
use nullspace_crypt::{
    hash::Hash,
    signing::{Signable, SigningPublic, SigningSecret},
};
use nullspace_structs::directory::{
    DirectoryAnchor, DirectoryClient, DirectoryKeyState, DirectoryResponse, DirectoryUpdate,
    PowSolution,
};
use nullspace_structs::{
    server::{ServerDescriptor, ServerName},
    username::{UserDescriptor, UserName},
};
use sqlx::SqlitePool;
use tokio::sync::Mutex;

mod header_sync;
mod pow;

/// High-level directory client with local header storage and proof checks.
pub struct DirClient {
    raw: DirectoryClient<DynRpcTransport>,
    anchor_pk: SigningPublic,
    pool: SqlitePool,
    anchor_cache: Cache<u64, DirectoryAnchor>,
    local_pending: Mutex<BTreeMap<String, Vec<DirectoryUpdate>>>,
}

impl DirClient {
    /// Create a new client and ensure the local header schema is initialized.
    pub async fn new<T>(
        transport: T,
        anchor_pk: SigningPublic,
        pool: SqlitePool,
    ) -> anyhow::Result<Self>
    where
        T: RpcTransport,
        T::Error: Into<anyhow::Error>,
    {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS _dirclient_headers (\
            height INTEGER PRIMARY KEY,\
            header BLOB NOT NULL,\
            header_hash BLOB NOT NULL\
            )",
        )
        .execute(&pool)
        .await?;
        Ok(Self {
            raw: DirectoryClient::from(transport),
            anchor_pk,
            pool,
            anchor_cache: Cache::new(1024),
            local_pending: Mutex::new(BTreeMap::new()),
        })
    }

    /// Access the raw RPC client when direct protocol calls are needed.
    pub fn raw(&self) -> &DirectoryClient<DynRpcTransport> {
        &self.raw
    }

    /// Fetch and verify the raw state for a directory key.
    pub async fn query_key_state(
        &self,
        key: impl Into<String>,
    ) -> anyhow::Result<Option<DirectoryKeyState>> {
        let key = key.into();
        self.get_committed_key_state(&key).await
    }

    /// Fetch and verify raw value bytes for a directory key.
    pub async fn query_raw(&self, key: impl Into<String>) -> anyhow::Result<Option<Vec<u8>>> {
        let key = key.into();
        let state = self.get_committed_key_state(&key).await?;
        Ok(state.and_then(|state| {
            if state.value.is_empty() {
                None
            } else {
                Some(state.value.to_vec())
            }
        }))
    }

    /// Fetch and decode the user descriptor for a username.
    pub async fn get_user_descriptor(
        &self,
        username: &UserName,
    ) -> anyhow::Result<Option<UserDescriptor>> {
        let state = self.get_committed_key_state(username.as_str()).await?;
        decode_user_descriptor(state)
    }

    /// Backward-compatible alias for retrieving typed user state.
    pub async fn get_user_state(
        &self,
        username: &UserName,
    ) -> anyhow::Result<Option<UserDescriptor>> {
        self.get_user_descriptor(username).await
    }

    /// Fetch and decode the server descriptor for a server name.
    pub async fn get_server_descriptor(
        &self,
        server_name: &ServerName,
    ) -> anyhow::Result<Option<ServerDescriptor>> {
        let state = self.get_committed_key_state(server_name.as_str()).await?;
        let Some(state) = state else {
            return Ok(None);
        };
        if state.value.is_empty() {
            return Ok(None);
        }
        let descriptor: ServerDescriptor = bcs::from_bytes(&state.value)?;
        Ok(Some(descriptor))
    }

    /// Submit a server descriptor update.
    pub async fn set_server_descriptor(
        &self,
        server_name: &ServerName,
        descriptor: &ServerDescriptor,
        signer: &SigningSecret,
    ) -> anyhow::Result<()> {
        let signer_pk = signer.public_key();
        if descriptor.server_pk != signer_pk {
            anyhow::bail!("server descriptor public key must match signer key");
        }

        let current = self.get_effective_key_state(server_name.as_str()).await?;
        let mut update = DirectoryUpdate {
            key: server_name.as_str().to_owned(),
            nonce: next_nonce(current.nonce_max),
            signer_pk,
            owners: BTreeSet::from([signer_pk]),
            value: bcs::to_bytes(descriptor)?.into(),
            signature: nullspace_crypt::signing::Signature::from_bytes([0u8; 64]),
        };
        update.sign(signer);
        self.insert_raw(update).await?;
        self.wait_for_server_descriptor(server_name, descriptor)
            .await?;
        Ok(())
    }

    pub async fn add_device(
        &self,
        username: &UserName,
        device_pk: SigningPublic,
        nonce: u64,
        signer: &SigningSecret,
    ) -> anyhow::Result<()> {
        let mut descriptor = self
            .get_user_descriptor(username)
            .await?
            .ok_or_else(|| anyhow::anyhow!("username not found"))?;
        let signer_pk = signer.public_key();
        if !descriptor.devices.contains(&signer_pk) {
            anyhow::bail!("signer is not a known device for username");
        }
        descriptor.devices.insert(device_pk);
        self.submit_user_descriptor(username, nonce, signer, descriptor)
            .await
    }

    pub async fn remove_device(
        &self,
        username: &UserName,
        device_pk: SigningPublic,
        nonce: u64,
        signer: &SigningSecret,
    ) -> anyhow::Result<()> {
        let mut descriptor = self
            .get_user_descriptor(username)
            .await?
            .ok_or_else(|| anyhow::anyhow!("username not found"))?;
        let signer_pk = signer.public_key();
        if !descriptor.devices.contains(&signer_pk) {
            anyhow::bail!("signer is not a known device for username");
        }
        if !descriptor.devices.remove(&device_pk) {
            anyhow::bail!("cannot remove unknown device");
        }
        if descriptor.devices.is_empty() {
            anyhow::bail!("cannot remove the last device");
        }
        self.submit_user_descriptor(username, nonce, signer, descriptor)
            .await
    }

    pub async fn bind_server(
        &self,
        username: &UserName,
        server_name: &ServerName,
        nonce: u64,
        signer: &SigningSecret,
    ) -> anyhow::Result<()> {
        let signer_pk = signer.public_key();
        let mut descriptor = match self.get_user_descriptor(username).await? {
            Some(mut descriptor) => {
                if !descriptor.devices.contains(&signer_pk) {
                    anyhow::bail!("signer is not a known device for username");
                }
                descriptor.server_name = server_name.clone();
                descriptor
            }
            None => {
                let mut devices = BTreeSet::new();
                devices.insert(signer_pk);
                UserDescriptor {
                    server_name: server_name.clone(),
                    devices,
                }
            }
        };
        descriptor.devices.insert(signer_pk);
        self.submit_user_descriptor(username, nonce, signer, descriptor)
            .await
    }

    async fn submit_user_descriptor(
        &self,
        username: &UserName,
        nonce: u64,
        signer: &SigningSecret,
        descriptor: UserDescriptor,
    ) -> anyhow::Result<()> {
        let signer_pk = signer.public_key();
        let state = self.get_effective_key_state(username.as_str()).await?;
        if nonce <= state.nonce_max {
            anyhow::bail!(
                "nonce {} must be greater than current nonce {}",
                nonce,
                state.nonce_max
            );
        }
        if state.owners.is_empty() {
            if !descriptor.devices.contains(&signer_pk) {
                anyhow::bail!("first update must include signer in owners");
            }
        } else if !state.owners.contains(&signer_pk) {
            anyhow::bail!("signer is not an owner of this key");
        }

        let mut update = DirectoryUpdate {
            key: username.as_str().to_owned(),
            nonce,
            signer_pk,
            owners: descriptor.devices.clone(),
            value: bcs::to_bytes(&descriptor)?.into(),
            signature: nullspace_crypt::signing::Signature::from_bytes([0u8; 64]),
        };
        update.sign(signer);
        self.insert_raw(update).await?;
        self.wait_for_user_nonce(username, nonce).await
    }

    async fn fetch_verified_response(&self, key: &str) -> anyhow::Result<DirectoryResponse> {
        let response = self
            .raw
            .v1_get_item(key.to_string())
            .await?
            .map_err(|err| anyhow::anyhow!(err.to_string()))?;
        let cache_key = response.proof_height;
        let anchor = self
            .anchor_cache
            .try_get_with(cache_key, async {
                let mut anchor = self
                    .raw
                    .v1_get_anchor()
                    .await?
                    .map_err(|err| anyhow::anyhow!(err.to_string()))?;
                anchor.verify(self.anchor_pk)?;
                while anchor.last_header_height < cache_key {
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    anchor = self
                        .raw
                        .v1_get_anchor()
                        .await?
                        .map_err(|err| anyhow::anyhow!(err.to_string()))?;
                    anchor.verify(self.anchor_pk)?;
                }
                Ok(anchor)
            })
            .await
            .map_err(|err: std::sync::Arc<anyhow::Error>| anyhow::anyhow!(err.to_string()))?;
        header_sync::sync_headers(&self.raw, &self.pool, &anchor).await?;
        verify_response(&self.pool, key, &anchor, &response).await?;
        Ok(response)
    }

    async fn get_committed_key_state(
        &self,
        key: &str,
    ) -> anyhow::Result<Option<DirectoryKeyState>> {
        let response = self.fetch_verified_response(key).await?;
        let state = decode_key_state_from_response(&response)?;
        if let Some(state) = &state {
            self.prune_local_pending_to_nonce(key, state.nonce_max)
                .await;
        }
        Ok(state)
    }

    async fn get_effective_key_state(&self, key: &str) -> anyhow::Result<DirectoryKeyState> {
        let committed = self.get_committed_key_state(key).await?.unwrap_or_default();
        let pending = {
            let pending_map = self.local_pending.lock().await;
            pending_map.get(key).cloned().unwrap_or_default()
        };
        if pending.is_empty() {
            return Ok(committed);
        }

        let mut state = committed;
        let mut sorted = pending;
        sorted.sort_by_key(|update| update.nonce);
        for update in &sorted {
            apply_directory_update(&mut state, key, update)?;
        }
        Ok(state)
    }

    async fn prune_local_pending_to_nonce(&self, key: &str, nonce_max: u64) {
        let mut pending = self.local_pending.lock().await;
        if let Some(list) = pending.get_mut(key) {
            list.retain(|update| update.nonce > nonce_max);
            if list.is_empty() {
                pending.remove(key);
            }
        }
    }

    async fn push_local_pending(&self, key: String, update: DirectoryUpdate) {
        let mut pending = self.local_pending.lock().await;
        pending.entry(key).or_default().push(update);
    }

    /// Submit a raw directory update for a key.
    pub async fn insert_raw(&self, update: DirectoryUpdate) -> anyhow::Result<()> {
        let key = update.key.clone();
        let pow = self.solve_pow().await?;
        self.raw
            .v1_insert_update(update.clone(), pow)
            .await?
            .map_err(|err| anyhow::anyhow!(err.to_string()))?;
        self.push_local_pending(key, update).await;
        Ok(())
    }

    /// Report local header sync progress as `(stored_height, anchor_height)`.
    pub async fn sync_progress(&self) -> anyhow::Result<(u64, u64)> {
        let stored = header_sync::max_stored_height(&self.pool)
            .await?
            .unwrap_or_default();
        let anchor = self
            .raw
            .v1_get_anchor()
            .await?
            .map_err(|err| anyhow::anyhow!(err.to_string()))?
            .last_header_height;
        Ok((stored, anchor))
    }

    async fn solve_pow(&self) -> anyhow::Result<PowSolution> {
        let seed = self.raw.v1_get_pow_seed().await?;
        pow::solve_pow(&seed)
    }

    pub async fn wait_for_user_nonce(&self, username: &UserName, nonce: u64) -> anyhow::Result<()> {
        let start = Instant::now();
        let timeout = Duration::from_secs(90);
        let poll = Duration::from_millis(500);
        loop {
            if let Some(state) = self.get_committed_key_state(username.as_str()).await?
                && state.nonce_max >= nonce
            {
                self.prune_local_pending_to_nonce(username.as_str(), state.nonce_max)
                    .await;
                return Ok(());
            }
            if start.elapsed() > timeout {
                anyhow::bail!("user action did not land before timeout");
            }
            tokio::time::sleep(poll).await;
        }
    }

    async fn wait_for_server_descriptor(
        &self,
        server_name: &ServerName,
        expected: &ServerDescriptor,
    ) -> anyhow::Result<()> {
        let start = Instant::now();
        let timeout = Duration::from_secs(90);
        let poll = Duration::from_millis(500);
        loop {
            if let Some(current) = self.get_server_descriptor(server_name).await?
                && &current == expected
            {
                return Ok(());
            }
            if start.elapsed() > timeout {
                anyhow::bail!("server descriptor update did not land before timeout");
            }
            tokio::time::sleep(poll).await;
        }
    }
}

fn decode_key_state_from_response(
    response: &DirectoryResponse,
) -> anyhow::Result<Option<DirectoryKeyState>> {
    match &response.value {
        Some(value) => Ok(Some(bcs::from_bytes(value)?)),
        None => Ok(None),
    }
}

fn decode_user_descriptor(
    state: Option<DirectoryKeyState>,
) -> anyhow::Result<Option<UserDescriptor>> {
    let Some(state) = state else {
        return Ok(None);
    };
    if state.value.is_empty() {
        return Ok(None);
    }
    let descriptor: UserDescriptor = bcs::from_bytes(&state.value)?;
    Ok(Some(descriptor))
}

fn apply_directory_update(
    state: &mut DirectoryKeyState,
    key: &str,
    update: &DirectoryUpdate,
) -> anyhow::Result<()> {
    if update.key != key {
        anyhow::bail!("update key mismatch");
    }
    update.verify(update.signer_pk)?;
    if update.nonce <= state.nonce_max {
        anyhow::bail!(
            "nonce {} must be greater than current nonce {}",
            update.nonce,
            state.nonce_max
        );
    }

    if state.owners.is_empty() {
        if !update.owners.contains(&update.signer_pk) {
            anyhow::bail!("first update must include signer in owners list");
        }
    } else if !state.owners.contains(&update.signer_pk) {
        anyhow::bail!("signer is not an owner of this key");
    }

    state.nonce_max = update.nonce;
    state.owners = update.owners.clone();
    state.value = update.value.clone();
    Ok(())
}

async fn verify_response(
    pool: &SqlitePool,
    key: &str,
    anchor: &nullspace_structs::directory::DirectoryAnchor,
    response: &DirectoryResponse,
) -> anyhow::Result<()> {
    if response.proof_height > anchor.last_header_height {
        anyhow::bail!("header chain mismatch");
    }
    let header = header_sync::load_header(pool, response.proof_height).await?;
    let root = header.smt_root;
    let compressed = novasmt::CompressedProof(response.proof_merkle_branch.to_vec());
    let proof = compressed
        .decompress()
        .ok_or_else(|| anyhow::anyhow!("failed to decompress proof"))?;
    let key_hash = Hash::digest(key.as_bytes());
    let value = response
        .value
        .clone()
        .map(|value| value.to_vec())
        .unwrap_or_default();
    if !proof.verify(root.to_bytes(), key_hash.to_bytes(), &value) {
        anyhow::bail!("invalid proof");
    }
    Ok(())
}

fn next_nonce(previous: u64) -> u64 {
    let now = nullspace_structs::timestamp::NanoTimestamp::now().0;
    now.max(previous.saturating_add(1))
}
