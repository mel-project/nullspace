use anyctx::AnyCtx;
use std::path::PathBuf;

use nullspace_crypt::signing::SigningPublic;
use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub db_path: PathBuf,
    pub dir_endpoint: Url,
    pub dir_anchor_pk: SigningPublic,
}

pub type Ctx<T> = fn(&AnyCtx<Config>) -> T;
