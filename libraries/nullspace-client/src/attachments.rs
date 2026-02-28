use std::collections::HashSet;
use std::future::Future;
use std::io::SeekFrom;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, LazyLock};

use anyctx::AnyCtx;
use futures_util::stream::{self, StreamExt, TryStreamExt};
use nullspace_crypt::hash::{BcsHashExt, Hash};
use nullspace_structs::fragment::{Attachment, Fragment};
use nullspace_structs::server::ServerClient;
use nullspace_structs::username::UserName;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncSeekExt, AsyncWriteExt};

use crate::Config;
use crate::database::DATABASE;
use crate::events::emit_event;
use crate::identity::identity_exists;
use crate::internal::{Event, InternalRpcError};
use crate::server::get_server_client;

const TRANSFER_CONCURRENCY: usize = 16;

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

mod images;
mod upload;
pub use upload::{attachment_upload, image_attachment_upload};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AttachmentStatus {
    pub frag_root: Attachment,
    pub saved_to: Option<PathBuf>,
}

pub async fn attachment_download(
    ctx: &AnyCtx<Config>,
    attachment_id: Hash,
    save_path: PathBuf,
) -> anyhow::Result<Hash> {
    if !save_path.is_absolute() {
        return Err(anyhow::anyhow!("save path must be absolute"));
    }
    let ctx = ctx.clone();
    tokio::spawn(async move {
        if let Err(err) = download_inner(&ctx, attachment_id, save_path).await {
            emit_event(
                &ctx,
                Event::DownloadFailed {
                    attachment_id,
                    error: err.to_string(),
                },
            );
        }
    });
    Ok(attachment_id)
}

pub async fn attachment_download_oneshot(
    ctx: &AnyCtx<Config>,
    _sender: UserName,
    attachment: Attachment,
    save_to: PathBuf,
) -> anyhow::Result<()> {
    if !save_to.is_absolute() {
        return Err(anyhow::anyhow!("save path must be absolute"));
    }
    if let Ok(metadata) = tokio::fs::metadata(&save_to).await
        && metadata.is_file()
    {
        return Ok(());
    }
    let parent = save_to
        .parent()
        .ok_or_else(|| anyhow::anyhow!("save path must have a parent directory"))?;
    tokio::fs::create_dir_all(parent).await?;

    let client = get_server_client(ctx, &attachment.server_name).await?;
    download_attachment_to_path(ctx, client, &attachment, None, &save_to).await
}

async fn download_inner(
    ctx: &AnyCtx<Config>,
    attachment_id: Hash,
    save_path: PathBuf,
) -> anyhow::Result<()> {
    static IN_PROGRESS: LazyLock<Mutex<HashSet<Hash>>> = LazyLock::new(Default::default);
    {
        let mut prog = IN_PROGRESS.lock();
        if prog.contains(&attachment_id) {
            return Ok(());
        }
        prog.insert(attachment_id);
    }
    scopeguard::defer!({
        IN_PROGRESS.lock().remove(&attachment_id);
    });
    let db = ctx.get(DATABASE);
    if !identity_exists(&mut *db.acquire().await?).await? {
        return Err(InternalRpcError::NotReady.into());
    }
    let (_sender_username, root) =
        load_attachment_root(&mut *db.acquire().await?, attachment_id).await?;
    let client = get_server_client(ctx, &root.server_name).await?;

    if let Some(parent) = save_path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    download_attachment_to_path(ctx, client, &root, Some(attachment_id), &save_path).await?;
    sqlx::query("insert or replace into attachment_paths (hash, download_path) values ($1, $2)")
        .bind(attachment_id.to_bytes().as_slice())
        .bind(save_path.to_string_lossy())
        .execute(ctx.get(DATABASE))
        .await?;
    emit_event(
        ctx,
        Event::DownloadDone {
            attachment_id,
            absolute_path: save_path,
        },
    );
    Ok(())
}

struct ProgressEmitter<'a> {
    ctx: &'a AnyCtx<Config>,
    attachment_id: Hash,
    total_size: u64,
}

impl<'a> ProgressEmitter<'a> {
    fn emit(&self, downloaded: u64) {
        emit_event(
            self.ctx,
            Event::DownloadProgress {
                attachment_id: self.attachment_id,
                downloaded_size: downloaded,
                total_size: self.total_size,
            },
        );
    }
}

async fn download_attachment_to_path(
    ctx: &AnyCtx<Config>,
    client: Arc<ServerClient>,
    attachment: &Attachment,
    attachment_id: Option<Hash>,
    final_path: &Path,
) -> anyhow::Result<()> {
    let parent = final_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("save path must have a parent directory"))?;
    tokio::fs::create_dir_all(parent).await?;

    let stem = final_path
        .file_name()
        .map(|name| name.to_string_lossy())
        .unwrap_or_default();
    let temp_file = tempfile::Builder::new()
        .prefix(&format!("{stem}.part."))
        .tempfile_in(parent)?;
    let temp_path = temp_file.path().to_path_buf();
    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .open(&temp_path)
        .await?;

    let total_size = attachment.total_size();
    let emitter = attachment_id.map(|id| ProgressEmitter {
        ctx,
        attachment_id: id,
        total_size,
    });
    if let Some(emitter) = &emitter {
        emitter.emit(0);
    }

    if attachment.children.is_empty() {
        file.flush().await?;
        finalize_atomic_file(&temp_path, final_path).await?;
        return Ok(());
    }

    file.set_len(total_size).await?;

    let downloaded_size = Arc::new(AtomicU64::new(0));
    let child_offsets = child_offsets(attachment);

    stream::iter(child_offsets)
        .map(|(hash, start_offset)| {
            let client = client.clone();
            let root = attachment.clone();
            let downloaded_size = downloaded_size.clone();
            let temp_path = temp_path.clone();
            let emitter = emitter.as_ref();
            async move {
                let mut file = tokio::fs::OpenOptions::new()
                    .write(true)
                    .open(&temp_path)
                    .await?;
                download_fragment(
                    client.as_ref(),
                    &root,
                    &mut file,
                    &downloaded_size,
                    hash,
                    start_offset,
                    emitter,
                )
                .await?;
                Ok::<(), anyhow::Error>(())
            }
        })
        .buffer_unordered(TRANSFER_CONCURRENCY)
        .try_collect::<Vec<_>>()
        .await?;

    if downloaded_size.load(std::sync::atomic::Ordering::Relaxed) != total_size {
        return Err(anyhow::anyhow!("download size mismatch"));
    }

    file.flush().await?;
    std::fs::File::open(&temp_path)?.sync_all()?;
    finalize_atomic_file(&temp_path, final_path).await?;
    drop(temp_file);
    Ok(())
}

fn child_offsets(attachment: &Attachment) -> Vec<(Hash, u64)> {
    attachment
        .children
        .iter()
        .copied()
        .scan(0u64, |offset, (hash, size)| {
            let start_offset = *offset;
            *offset = offset.saturating_add(size);
            Some((hash, start_offset))
        })
        .collect()
}

fn download_fragment<'a>(
    client: &'a ServerClient,
    root: &'a Attachment,
    file: &'a mut tokio::fs::File,
    downloaded_size: &'a AtomicU64,
    hash: Hash,
    start_offset: u64,
    emitter: Option<&'a ProgressEmitter<'a>>,
) -> BoxFuture<'a, anyhow::Result<()>> {
    Box::pin(async move {
        let response = client.frag_download(hash).await?;
        let frag = response
            .map_err(|err| anyhow::anyhow!(err.to_string()))?
            .ok_or_else(|| anyhow::anyhow!("missing fragment"))?;
        if frag.bcs_hash() != hash {
            return Err(anyhow::anyhow!("fragment hash mismatch"));
        }
        match frag {
            Fragment::Node(node) => {
                let mut offset = start_offset;
                for (child, size) in node.children.iter().copied() {
                    download_fragment(client, root, file, downloaded_size, child, offset, emitter)
                        .await?;
                    offset = offset.saturating_add(size);
                }
                Ok(())
            }
            Fragment::Leaf(leaf) => {
                let plaintext = root
                    .content_key
                    .decrypt(leaf.nonce, &leaf.data, &[])
                    .map_err(|_| anyhow::anyhow!("chunk decryption failed"))?;
                file.seek(SeekFrom::Start(start_offset)).await?;
                file.write_all(&plaintext).await?;
                let downloaded_size = downloaded_size
                    .fetch_add(plaintext.len() as u64, std::sync::atomic::Ordering::Relaxed)
                    .saturating_add(plaintext.len() as u64);
                if let Some(emitter) = emitter {
                    emitter.emit(downloaded_size);
                }
                Ok(())
            }
        }
    })
}

pub async fn attachment_status(ctx: &AnyCtx<Config>, id: Hash) -> anyhow::Result<AttachmentStatus> {
    let dl_path: Option<String> =
        sqlx::query_scalar("select download_path from attachment_paths where hash = $1")
            .bind(id.to_bytes().as_slice())
            .fetch_optional(ctx.get(DATABASE))
            .await?;
    let root_bytes: Vec<u8> =
        sqlx::query_scalar("select root from attachment_roots where hash = $1")
            .bind(id.to_bytes().as_slice())
            .fetch_one(ctx.get(DATABASE))
            .await?;
    let frag_root: Attachment = bcs::from_bytes(&root_bytes)?;
    let saved_to = if let Some(path) = dl_path.map(PathBuf::from) {
        match tokio::fs::metadata(&path).await {
            Ok(metadata) if metadata.is_file() && metadata.len() == frag_root.total_size() => {
                Some(path)
            }
            _ => None,
        }
    } else {
        None
    };
    Ok(AttachmentStatus {
        frag_root,
        saved_to,
    })
}

pub async fn store_attachment_root(
    conn: &mut sqlx::SqliteConnection,
    sender: &UserName,
    root: &Attachment,
) -> anyhow::Result<Hash> {
    let hash = root.bcs_hash();
    let root_bcs = bcs::to_bytes(root)?;
    sqlx::query(
        "INSERT INTO attachment_roots (hash, root, sender_username) \
         VALUES (?, ?, ?) \
         ON CONFLICT(hash) DO UPDATE SET \
           root = excluded.root, \
           sender_username = excluded.sender_username",
    )
    .bind(hash.to_bytes().to_vec())
    .bind(root_bcs)
    .bind(sender.as_str())
    .execute(conn)
    .await?;
    Ok(hash)
}

pub async fn load_attachment_root(
    db: &mut sqlx::SqliteConnection,
    attachment_id: Hash,
) -> anyhow::Result<(String, Attachment)> {
    let row = sqlx::query_as::<_, (String, Vec<u8>)>(
        "SELECT sender_username, root FROM attachment_roots WHERE hash = ?",
    )
    .bind(attachment_id.to_bytes().to_vec())
    .fetch_optional(db)
    .await?;
    let Some((sender_username, root_bytes)) = row else {
        return Err(anyhow::anyhow!("attachment not found"));
    };
    let root: Attachment = bcs::from_bytes(&root_bytes)?;
    Ok((sender_username, root))
}

async fn finalize_atomic_file(temp_path: &Path, target: &Path) -> anyhow::Result<()> {
    if let Ok(metadata) = tokio::fs::metadata(target).await
        && metadata.is_file()
    {
        let _ = tokio::fs::remove_file(temp_path).await;
        return Ok(());
    }
    match tokio::fs::rename(temp_path, target).await {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            let _ = tokio::fs::remove_file(temp_path).await;
            Ok(())
        }
        Err(err) => Err(err.into()),
    }
}
