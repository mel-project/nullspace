#![doc = include_str!(concat!(env!("OUT_DIR"), "/README-rustdocified.md"))]

use nanorpc::{DynRpcTransport, RpcTransport};
use sqlx::SqlitePool;
use std::time::{Duration, Instant};
use xirtam_crypt::{
    hash::Hash,
    signing::{Signable, Signature, SigningPublic, SigningSecret},
};
use xirtam_structs::directory::{
    DirectoryClient, DirectoryHistoryIterExt, DirectoryResponse, DirectoryUpdate,
    DirectoryUpdateInner, PowSolution,
};
use xirtam_structs::{
    Blob,
    gateway::{GatewayDescriptor, GatewayName},
    handle::{Handle, HandleDescriptor},
};
mod header_sync;
mod pow;

/// High-level directory client with local header storage and proof checks.
pub struct DirClient {
    raw: DirectoryClient<DynRpcTransport>,
    anchor_pk: SigningPublic,
    pool: SqlitePool,
}

/// Derived listing information for a directory key.
#[derive(Clone, Debug)]
pub struct DirectoryListing {
    /// Latest content message for the key, if present.
    pub latest: Option<Blob>,
    /// Current owners for the key, after applying ownership updates in order.
    pub owners: Vec<SigningPublic>,
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
        })
    }

    /// Access the raw RPC client when direct protocol calls are needed.
    pub fn raw(&self) -> &DirectoryClient<DynRpcTransport> {
        &self.raw
    }

    /// Fetch and verify a directory item by key.
    ///
    /// This validates the signed anchor, syncs headers, checks the SMT proof,
    /// and returns a derived listing.
    pub async fn query_raw(&self, key: impl Into<String>) -> anyhow::Result<DirectoryListing> {
        let key = key.into();
        let response = self.fetch_verified_response(&key).await?;
        let listing = build_listing(&response)?;
        Ok(listing)
    }

    /// Fetch and decode the handle descriptor for a user handle.
    pub async fn get_handle_descriptor(
        &self,
        handle: &Handle,
    ) -> anyhow::Result<Option<HandleDescriptor>> {
        let listing = self.query_raw(handle.as_str()).await?;
        let latest = match listing.latest {
            Some(latest) => latest,
            None => return Ok(None),
        };
        if latest.kind != Blob::V1_HANDLE_DESCRIPTOR {
            anyhow::bail!("unexpected message kind: {}", latest.kind);
        }
        let descriptor: HandleDescriptor = bcs::from_bytes(&latest.inner)?;
        Ok(Some(descriptor))
    }

    /// Fetch and decode the gateway descriptor for a gateway name.
    pub async fn get_gateway_descriptor(
        &self,
        gateway_name: &GatewayName,
    ) -> anyhow::Result<Option<GatewayDescriptor>> {
        let listing = self.query_raw(gateway_name.as_str()).await?;
        let latest = match listing.latest {
            Some(latest) => latest,
            None => return Ok(None),
        };
        if latest.kind != Blob::V1_GATEWAY_DESCRIPTOR {
            anyhow::bail!("unexpected message kind: {}", latest.kind);
        }
        let descriptor: GatewayDescriptor = bcs::from_bytes(&latest.inner)?;
        Ok(Some(descriptor))
    }

    /// Build and submit a handle descriptor update for a user handle.
    pub async fn insert_handle_descriptor(
        &self,
        handle: &Handle,
        descriptor: &HandleDescriptor,
        signer: &SigningSecret,
    ) -> anyhow::Result<()> {
        let response = self.fetch_verified_response(handle.as_str()).await?;
        response
            .history
            .iter()
            .verify_history()
            .map_err(|err| anyhow::anyhow!(err.to_string()))?;
        let prev_update_hash = prev_update_hash(&response.history)?;
        let update = signed_update(
            prev_update_hash,
            DirectoryUpdateInner::Update(Blob {
                kind: Blob::V1_HANDLE_DESCRIPTOR.into(),
                inner: bcs::to_bytes(descriptor)?.into(),
            }),
            signer,
        );
        self.insert_raw(handle.as_str(), update).await?;
        Ok(())
    }

    /// Build and submit a gateway descriptor update for a gateway name.
    pub async fn insert_gateway_descriptor(
        &self,
        gateway_name: &GatewayName,
        descriptor: &GatewayDescriptor,
        signer: &SigningSecret,
    ) -> anyhow::Result<()> {
        let response = self.fetch_verified_response(gateway_name.as_str()).await?;
        response
            .history
            .iter()
            .verify_history()
            .map_err(|err| anyhow::anyhow!(err.to_string()))?;
        let prev_update_hash = prev_update_hash(&response.history)?;
        let update = signed_update(
            prev_update_hash,
            DirectoryUpdateInner::Update(Blob {
                kind: Blob::V1_GATEWAY_DESCRIPTOR.into(),
                inner: bcs::to_bytes(descriptor)?.into(),
            }),
            signer,
        );
        self.insert_raw(gateway_name.as_str(), update).await?;
        Ok(())
    }

    /// Add an owner to a user handle.
    pub async fn add_owner(
        &self,
        handle: &Handle,
        owner: SigningPublic,
        signer: &SigningSecret,
    ) -> anyhow::Result<()> {
        let response = self.fetch_verified_response(handle.as_str()).await?;
        response
            .history
            .iter()
            .verify_history()
            .map_err(|err| anyhow::anyhow!(err.to_string()))?;
        let prev_update_hash = prev_update_hash(&response.history)?;
        let update = signed_update(
            prev_update_hash,
            DirectoryUpdateInner::AddOwner(owner),
            signer,
        );
        self.insert_raw(handle.as_str(), update).await?;
        Ok(())
    }

    /// Add an owner to a gateway name.
    pub async fn add_gateway_owner(
        &self,
        gateway_name: &GatewayName,
        owner: SigningPublic,
        signer: &SigningSecret,
    ) -> anyhow::Result<()> {
        let response = self.fetch_verified_response(gateway_name.as_str()).await?;
        response
            .history
            .iter()
            .verify_history()
            .map_err(|err| anyhow::anyhow!(err.to_string()))?;
        let prev_update_hash = prev_update_hash(&response.history)?;
        let update = signed_update(
            prev_update_hash,
            DirectoryUpdateInner::AddOwner(owner),
            signer,
        );
        self.insert_raw(gateway_name.as_str(), update).await?;
        Ok(())
    }

    /// Remove an owner from a user handle.
    pub async fn del_owner(
        &self,
        handle: &Handle,
        owner: SigningPublic,
        signer: &SigningSecret,
    ) -> anyhow::Result<()> {
        let response = self.fetch_verified_response(handle.as_str()).await?;
        response
            .history
            .iter()
            .verify_history()
            .map_err(|err| anyhow::anyhow!(err.to_string()))?;
        let prev_update_hash = prev_update_hash(&response.history)?;
        let update = signed_update(
            prev_update_hash,
            DirectoryUpdateInner::DelOwner(owner),
            signer,
        );
        self.insert_raw(handle.as_str(), update).await?;
        Ok(())
    }

    /// Remove an owner from a gateway name.
    pub async fn del_gateway_owner(
        &self,
        gateway_name: &GatewayName,
        owner: SigningPublic,
        signer: &SigningSecret,
    ) -> anyhow::Result<()> {
        let response = self.fetch_verified_response(gateway_name.as_str()).await?;
        response
            .history
            .iter()
            .verify_history()
            .map_err(|err| anyhow::anyhow!(err.to_string()))?;
        let prev_update_hash = prev_update_hash(&response.history)?;
        let update = signed_update(
            prev_update_hash,
            DirectoryUpdateInner::DelOwner(owner),
            signer,
        );
        self.insert_raw(gateway_name.as_str(), update).await?;
        Ok(())
    }

    async fn fetch_verified_response(&self, key: &str) -> anyhow::Result<DirectoryResponse> {
        let anchor = self
            .raw
            .v1_get_anchor()
            .await?
            .map_err(|err| anyhow::anyhow!(err.to_string()))?;
        anchor.verify(self.anchor_pk)?;
        header_sync::sync_headers(&self.raw, &self.pool, &anchor).await?;
        let response = self
            .raw
            .v1_get_item(key.to_string())
            .await?
            .map_err(|err| anyhow::anyhow!(err.to_string()))?;
        verify_response(&self.pool, key, &anchor, &response).await?;
        Ok(response)
    }

    /// Submit a raw directory update for a key.
    pub async fn insert_raw(
        &self,
        key: impl Into<String>,
        update: DirectoryUpdate,
    ) -> anyhow::Result<()> {
        let key = key.into();
        let update_hash = update_hash(&update)?;
        let pow = self.solve_pow().await?;
        self.raw
            .v1_insert_update(key.clone(), update, pow)
            .await?
            .map_err(|err| anyhow::anyhow!(err.to_string()))?;
        self.wait_for_update(&key, update_hash).await?;
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

    async fn wait_for_update(&self, key: &str, expected_hash: Hash) -> anyhow::Result<()> {
        let start = Instant::now();
        let timeout = Duration::from_secs(90);
        let poll = Duration::from_millis(500);
        loop {
            let response = self.fetch_verified_response(key).await?;
            for update in &response.history {
                if update_hash(update)? == expected_hash {
                    return Ok(());
                }
            }
            if start.elapsed() > timeout {
                anyhow::bail!("update did not land before timeout");
            }
            tokio::time::sleep(poll).await;
        }
    }
}

async fn verify_response(
    pool: &SqlitePool,
    key: &str,
    anchor: &xirtam_structs::directory::DirectoryAnchor,
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
    // an empty history means simply *absence* in the SMT
    let value = if response.history.is_empty() {
        vec![]
    } else {
        bcs::to_bytes(&response.history)?
    };
    if !proof.verify(root.to_bytes(), key_hash.to_bytes(), &value) {
        anyhow::bail!("invalid proof");
    }
    Ok(())
}

fn build_listing(response: &DirectoryResponse) -> anyhow::Result<DirectoryListing> {
    response
        .history
        .iter()
        .verify_history()
        .map_err(|err| anyhow::anyhow!(err.to_string()))?;
    let mut owners = Vec::new();
    let mut latest = None;
    for update in &response.history {
        match &update.update_type {
            DirectoryUpdateInner::AddOwner(owner) => {
                if !owners.contains(owner) {
                    owners.push(*owner);
                }
            }
            DirectoryUpdateInner::DelOwner(owner) => {
                owners.retain(|existing| existing != owner);
            }
            DirectoryUpdateInner::Update(message) => {
                latest = Some(message.clone());
            }
        }
    }
    Ok(DirectoryListing { latest, owners })
}

fn update_hash(update: &DirectoryUpdate) -> anyhow::Result<Hash> {
    let bytes = bcs::to_bytes(update)?;
    Ok(Hash::digest(&bytes))
}

fn prev_update_hash(history: &[DirectoryUpdate]) -> anyhow::Result<Hash> {
    match history.last() {
        Some(update) => update_hash(update),
        None => Ok(Hash::from_bytes([0u8; 32])),
    }
}

fn signed_update(
    prev_update_hash: Hash,
    update_type: DirectoryUpdateInner,
    signer: &SigningSecret,
) -> DirectoryUpdate {
    let mut update = DirectoryUpdate {
        prev_update_hash,
        update_type,
        signature: Signature::from_bytes([0u8; 64]),
    };
    update.sign(signer);
    update
}
