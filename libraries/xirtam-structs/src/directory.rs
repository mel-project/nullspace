use nanorpc::nanorpc_derive;
use serde::{Deserialize, Serialize};
use smol_str::SmolStr;
use thiserror::Error;
use xirtam_crypt::{hash::Hash, signing::Signature};

/// The trust anchor of the entire directory at a given time.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectoryAnchor {
    pub directory_id: SmolStr,
    pub last_header_height: u64,
    pub last_header_hash: Hash,
    pub signature: Signature,
}

/// The header of the a directory snapshot at a particular time.
#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct DirectoryHeader {
    pub prev: Hash,
    pub smt_root: Hash,
    pub time_unix: u64,
}

#[nanorpc_derive]
pub trait DirectoryProtocol {
    async fn get_anchor(&self) -> Result<DirectoryAnchor, DirectoryErr>;
}

#[derive(Error, Serialize, Deserialize, Debug)]
pub enum DirectoryErr {
    #[error("retry later")]
    RetryLater,
}
