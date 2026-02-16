use std::collections::BTreeMap;

use async_trait::async_trait;
use bytes::Bytes;
use nanorpc::nanorpc_derive;
use nullspace_crypt::{
    hash::Hash,
    signing::{Signable, Signature, SigningPublic},
};
use serde::{Deserialize, Serialize};
use serde_with::base64::{Base64, UrlSafe};
use serde_with::formats::Unpadded;
use serde_with::{FromInto, IfIsHumanReadable, serde_as};
use smol_str::SmolStr;
use thiserror::Error;

use crate::timestamp::Timestamp;

#[nanorpc_derive]
#[async_trait]
/// The RPC protocol for accessing the directory.
pub trait DirectoryProtocol {
    async fn v1_get_pow_seed(&self) -> PowSeed;
    async fn v1_get_anchor(&self) -> Result<DirectoryAnchor, DirectoryErr>;
    async fn v1_get_chunk(&self, height: u64) -> Result<DirectoryChunk, DirectoryErr>;
    async fn v1_get_headers(
        &self,
        first: u64,
        last: u64,
    ) -> Result<Vec<DirectoryHeader>, DirectoryErr>;
    async fn v1_get_item(&self, key: String) -> Result<DirectoryResponse, DirectoryErr>;
    async fn v1_insert_update(
        &self,
        key: String,
        update: DirectoryUpdate,
        pow: PowSolution,
    ) -> Result<(), DirectoryErr>;
}

#[derive(Error, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum DirectoryErr {
    #[error("retry later")]
    RetryLater,

    #[error("update rejected (reason: {0})")]
    UpdateRejected(String),
}

/// A proof-of-work seed.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct PowSeed {
    pub algo: PowAlgo,
    pub seed: Hash,
    pub use_before: Timestamp,
}

#[derive(Clone, Debug, Serialize, Deserialize, Copy, PartialEq, Eq, Hash)]
pub enum PowAlgo {
    EquiX { effort: u64 },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct PowSolution {
    pub seed: Hash,
    pub nonce: u64,
    pub solution: Bytes,
}

/// The trust anchor of the entire directory at a given time.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectoryAnchor {
    pub directory_id: SmolStr,
    pub last_header_height: u64,
    pub last_header_hash: Hash,
    pub signature: Signature,
}

impl DirectoryAnchor {
    fn signed_tuple(&self) -> (&SmolStr, &u64, &Hash) {
        (
            &self.directory_id,
            &self.last_header_height,
            &self.last_header_hash,
        )
    }
}

/// The header of the a directory snapshot at a particular time.
#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct DirectoryHeader {
    pub prev: Hash,
    pub smt_root: Hash,
    pub time_unix: u64,
}

/// A whole chunk of directory updates.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectoryChunk {
    pub header: DirectoryHeader,
    pub updates: BTreeMap<String, Vec<DirectoryUpdate>>,
}

/// State of a key in the raw directory key-value store.
#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DirectoryKeyState {
    pub nonce_max: u64,
    pub owners: Vec<SigningPublic>,
    #[serde_as(as = "Option<IfIsHumanReadable<Base64<UrlSafe, Unpadded>, FromInto<Vec<u8>>>>")]
    pub value: Option<Bytes>,
}

impl Default for DirectoryKeyState {
    fn default() -> Self {
        Self {
            nonce_max: 0,
            owners: Vec::new(),
            value: None,
        }
    }
}

/// Signed update that replaces a key's current state (owners + value).
#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectoryUpdate {
    pub nonce: u64,
    pub signer_pk: SigningPublic,
    pub owners: Vec<SigningPublic>,
    #[serde_as(as = "Option<IfIsHumanReadable<Base64<UrlSafe, Unpadded>, FromInto<Vec<u8>>>>")]
    pub value: Option<Bytes>,
    pub signature: Signature,
}

impl DirectoryUpdate {
    pub fn hash(&self) -> Hash {
        Hash::digest(&bcs::to_bytes(self).expect("bcs serialization failed"))
    }
}

impl Signable for DirectoryUpdate {
    fn signed_value(&self) -> Vec<u8> {
        bcs::to_bytes(&(&self.nonce, &self.signer_pk, &self.owners, &self.value))
            .expect("bcs serialization failed")
    }

    fn signature_mut(&mut self) -> &mut Signature {
        &mut self.signature
    }

    fn signature(&self) -> &Signature {
        &self.signature
    }
}

impl Signable for DirectoryAnchor {
    fn signed_value(&self) -> Vec<u8> {
        bcs::to_bytes(&self.signed_tuple()).expect("bcs serialization failed")
    }

    fn signature_mut(&mut self) -> &mut Signature {
        &mut self.signature
    }

    fn signature(&self) -> &Signature {
        &self.signature
    }
}

/// A response to a directory query.
#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectoryResponse {
    #[serde_as(as = "Option<IfIsHumanReadable<Base64<UrlSafe, Unpadded>, FromInto<Vec<u8>>>>")]
    pub value: Option<Bytes>,
    pub proof_height: u64,
    #[serde_as(as = "IfIsHumanReadable<Base64<UrlSafe, Unpadded>, FromInto<Vec<u8>>>")]
    pub proof_merkle_branch: Bytes,
}
