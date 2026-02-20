use anyctx::AnyCtx;
use std::path::PathBuf;

use nullspace_crypt::signing::SigningPublic;
use serde::{Deserialize, Serialize};
use url::Url;

/// Configuration required to start a [`Client`](crate::Client).
///
/// Typically deserialized from a TOML file (the C FFI accepts a TOML string
/// directly).  All fields are mandatory.
///
/// # Example (TOML)
///
/// ```toml
/// db_path = "/home/user/.local/share/nullspace/client.db"
/// dir_endpoint = "https://directory.example.com"
/// dir_anchor_pk = "<base64-encoded signing public key>"
/// ```
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    /// Path to the SQLite database file.
    ///
    /// The database will be created (with WAL journaling) if it does not
    /// exist.  All client state -- identity, conversations, messages,
    /// mailbox cursors, attachment metadata -- is stored here.
    pub db_path: PathBuf,

    /// URL of the nullspace directory service.
    ///
    /// The directory maps usernames to server names and device chains.  The
    /// client contacts this endpoint to look up peers, bind new users, and
    /// verify device ownership.
    pub dir_endpoint: Url,

    /// Public key used to verify signatures from the directory service.
    ///
    /// This acts as the trust anchor: the client will reject any directory
    /// response whose signature does not match this key.
    pub dir_anchor_pk: SigningPublic,
}

pub type Ctx<T> = fn(&AnyCtx<Config>) -> T;
