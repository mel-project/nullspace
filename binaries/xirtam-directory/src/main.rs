mod config;
mod db;
mod merkle;
mod mirror;
mod pow;
mod server;
mod state;

use std::{path::PathBuf, sync::Arc, time::Duration};

use anyhow::Context;
use axum::{Router, routing::post};
use clap::Parser;
use futures_concurrency::future::Join;
use rand::RngCore;
use std::os::unix::fs::PermissionsExt;
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;
use xirtam_crypt::signing::SigningSecret;
use url::Url;

use crate::{config::Args, mirror::MirrorState, state::DirectoryState};

const DIRECTORY_ID: &str = "xirtam-directory";
const CHUNK_SECONDS: u64 = 30;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("xirtam_directory=debug"));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    let args = Args::parse();
    let db_path = args.db_path.clone();
    std::fs::create_dir_all(&db_path)?;

    let (pool_res, merkle_res) = (db::init_sqlite(&db_path), async {
        merkle::open_store(&db_path)
    })
        .join()
        .await;
    let pool = pool_res?;
    let merkle = merkle_res?;

    let mirror = if let Some(endpoint) = args.mirror {
        tracing::info!(endpoint = %endpoint, "directory mirror enabled");
        let endpoint = Url::parse(&endpoint).context("invalid mirror endpoint URL")?;
        Some(Arc::new(MirrorState::new(endpoint)))
    } else {
        None
    };
    let secret_key = if mirror.is_some() {
        None
    } else {
        let key_path = args
            .secret_key
            .as_ref()
            .context("secret key required when not mirroring")?;
        let secret_key = load_secret_key(key_path)?;
        let public_key = secret_key.public_key();
        tracing::info!(
            anchor_public_key = %public_key,
            "directory anchor public key"
        );
        Some(secret_key)
    };
    let state = Arc::new(DirectoryState {
        pool,
        merkle,
        secret_key,
        directory_id: DIRECTORY_ID.into(),
        staging: tokio::sync::Mutex::new(Default::default()),
        mirror,
    });

    if state.mirror.is_some() {
        tokio::spawn(mirror::run_mirror_sync(state.clone()));
    } else {
        tokio::spawn(run_chunker(state.clone()));
    }

    let app = Router::new()
        .route("/", post(server::rpc_handler))
        .with_state(state);

    let listener = TcpListener::bind(args.listen).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

fn load_secret_key(path: &PathBuf) -> anyhow::Result<SigningSecret> {
    if !path.exists() {
        let mut bytes = [0u8; 32];
        rand::rng().fill_bytes(&mut bytes);
        std::fs::write(path, bytes)
            .with_context(|| format!("write secret key {}", path.display()))?;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(path, perms)
            .with_context(|| format!("chmod secret key {}", path.display()))?;
    }
    let data =
        std::fs::read(path).with_context(|| format!("read secret key {}", path.display()))?;
    if data.len() != 32 {
        anyhow::bail!("secret key must be exactly 32 raw bytes")
    }
    let bytes: [u8; 32] = data.try_into().unwrap();
    Ok(SigningSecret::from_bytes(bytes))
}

async fn run_chunker(state: Arc<DirectoryState>) {
    loop {
        let now = unix_time();
        let wait = CHUNK_SECONDS - (now % CHUNK_SECONDS);
        tokio::time::sleep(Duration::from_secs(wait)).await;
        if let Err(err) = server::commit_chunk(state.clone()).await {
            tracing::error!(error = ?err, "failed to commit chunk");
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }
}

fn unix_time() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
