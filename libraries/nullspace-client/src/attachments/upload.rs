use std::io::SeekFrom;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use anyctx::AnyCtx;
use bytes::Bytes;
use futures_util::stream::{self, StreamExt, TryStreamExt};
use nullspace_crypt::aead::AeadKey;
use nullspace_crypt::hash::{BcsHashExt, BytesHashExt, Hash};
use nullspace_structs::fragment::{
    Attachment, Fragment, FragmentLeaf, FragmentNode, ImageAttachment,
};
use rand::RngCore;
use smol_str::SmolStr;
use tokio::io::{AsyncReadExt, AsyncSeekExt};

use crate::Config;
use crate::auth_tokens::get_auth_token;
use crate::database::DATABASE;
use crate::events::emit_event;
use crate::identity::{Identity, identity_exists};
use crate::internal::{Event, InternalRpcError, UploadedRoot};
use crate::server::get_server_client;

use super::images;

const MAX_CHUNK_SIZE: usize = 512 * 1024;
const MAX_FANOUT: usize = 16;
const TRANSFER_CONCURRENCY: usize = 16;

pub async fn attachment_upload(
    ctx: &AnyCtx<Config>,
    absolute_path: PathBuf,
    mime: SmolStr,
) -> anyhow::Result<i64> {
    let upload_id = rand::random();
    let ctx = ctx.clone();
    tokio::spawn(async move {
        match upload_file(&ctx, absolute_path, mime, upload_id).await {
            Ok(root) => emit_event(
                &ctx,
                Event::UploadDone {
                    id: upload_id,
                    root: UploadedRoot::Attachment(root),
                },
            ),
            Err(err) => emit_event(
                &ctx,
                Event::UploadFailed {
                    id: upload_id,
                    error: err.to_string(),
                },
            ),
        }
    });
    Ok(upload_id)
}

pub async fn image_attachment_upload(
    ctx: &AnyCtx<Config>,
    absolute_path: PathBuf,
) -> anyhow::Result<i64> {
    let upload_id = rand::random();
    let ctx = ctx.clone();
    tokio::spawn(async move {
        match upload_image_attachment(&ctx, absolute_path, upload_id).await {
            Ok(root) => emit_event(
                &ctx,
                Event::UploadDone {
                    id: upload_id,
                    root: UploadedRoot::ImageAttachment(root),
                },
            ),
            Err(err) => emit_event(
                &ctx,
                Event::UploadFailed {
                    id: upload_id,
                    error: err.to_string(),
                },
            ),
        }
    });
    Ok(upload_id)
}

async fn upload_image_attachment(
    ctx: &AnyCtx<Config>,
    absolute_path: PathBuf,
    upload_id: i64,
) -> anyhow::Result<ImageAttachment> {
    let source_bytes = tokio::fs::read(&absolute_path).await?;
    let prepared =
        tokio::task::spawn_blocking(move || images::prepare_webp_and_thumbhash(&source_bytes))
            .await
            .map_err(|err| anyhow::anyhow!("image preprocessing task failed: {err}"))??;

    let filename_hash = prepared.webp_bytes.bytes_hash();
    let temp_file = tempfile::Builder::new()
        .prefix(&format!("nullspace-{filename_hash}-"))
        .suffix(".webp")
        .tempfile()?;
    let temp_path = temp_file.path().to_path_buf();
    tokio::fs::write(&temp_path, &prepared.webp_bytes).await?;

    let upload_result = upload_file(
        ctx,
        temp_path.clone(),
        SmolStr::new("image/webp"),
        upload_id,
    )
    .await;
    drop(temp_file);
    let inner = upload_result?;

    Ok(ImageAttachment {
        width: prepared.width,
        height: prepared.height,
        thumbhash: prepared.thumbhash,
        inner,
    })
}

async fn upload_file(
    ctx: &AnyCtx<Config>,
    absolute_path: PathBuf,
    mime: SmolStr,
    upload_id: i64,
) -> anyhow::Result<Attachment> {
    let db = ctx.get(DATABASE);
    let mut conn = db.acquire().await?;
    if !identity_exists(&mut conn).await? {
        return Err(InternalRpcError::NotReady.into());
    }
    let filename = file_basename(&absolute_path)?;
    let total_size = tokio::fs::metadata(&absolute_path).await?.len();
    emit_event(
        ctx,
        Event::UploadProgress {
            id: upload_id,
            uploaded_size: 0,
            total_size,
        },
    );

    let identity = Identity::load(&mut conn).await?;
    let server_name = identity
        .server_name
        .clone()
        .ok_or_else(|| anyhow::anyhow!("server name not available"))?;
    let client = get_server_client(ctx, &server_name).await?;
    let auth = get_auth_token(ctx).await?;

    let content_key = AeadKey::random();
    let uploaded_size = Arc::new(AtomicU64::new(0));
    let chunk_size = MAX_CHUNK_SIZE.min((total_size / 20) as usize).max(16384) as u64;
    let chunk_count = total_size.div_ceil(chunk_size);
    let offsets = (0..chunk_count)
        .map(|index| (index as usize, index * chunk_size))
        .collect::<Vec<_>>();

    let mut chunk_results = stream::iter(offsets)
        .map(|(index, offset)| {
            let ctx = ctx.clone();
            let client = client.clone();
            let auth = auth;
            let absolute_path = absolute_path.clone();
            let uploaded_size = uploaded_size.clone();
            let content_key = content_key.clone();
            async move {
                let mut file = tokio::fs::File::open(&absolute_path).await?;
                file.seek(SeekFrom::Start(offset)).await?;
                let chunk_len = (total_size - offset).min(chunk_size) as usize;
                let mut buf = vec![0u8; chunk_len];
                file.read_exact(&mut buf).await?;
                let mut nonce = [0u8; 24];
                rand::thread_rng().fill_bytes(&mut nonce);
                let ciphertext = content_key
                    .encrypt(nonce, &buf, &[])
                    .map_err(|_| anyhow::anyhow!("chunk encryption failed"))?;
                let leaf = FragmentLeaf {
                    nonce,
                    data: Bytes::from(ciphertext),
                };
                let hash = Fragment::Leaf(leaf.clone()).bcs_hash();
                let response = client.frag_upload(auth, Fragment::Leaf(leaf), 0).await?;
                if let Err(err) = response {
                    return Err(anyhow::anyhow!(err.to_string()));
                }
                let uploaded_size = uploaded_size
                    .fetch_add(chunk_len as u64, std::sync::atomic::Ordering::Relaxed)
                    .saturating_add(chunk_len as u64);
                emit_event(
                    &ctx,
                    Event::UploadProgress {
                        id: upload_id,
                        uploaded_size,
                        total_size,
                    },
                );
                Ok((index, hash, chunk_len as u64))
            }
        })
        .buffer_unordered(TRANSFER_CONCURRENCY)
        .try_collect::<Vec<_>>()
        .await?;

    chunk_results.sort_by_key(|(index, _, _)| *index);
    let mut current_level = chunk_results
        .into_iter()
        .map(|(_, hash, size)| (hash, size))
        .collect::<Vec<_>>();

    let mut nodes: Vec<FragmentNode> = Vec::new();
    while current_level.len() > MAX_FANOUT {
        let mut next_level = Vec::new();
        for group in current_level.chunks(MAX_FANOUT) {
            let children: Vec<(Hash, u64)> = group.to_vec();
            let node = FragmentNode { children };
            let hash = Fragment::Node(node.clone()).bcs_hash();
            let size = node.total_size();
            next_level.push((hash, size));
            nodes.push(node);
        }
        current_level = next_level;
    }

    for node in nodes {
        let response = client.frag_upload(auth, Fragment::Node(node), 0).await?;
        if let Err(err) = response {
            return Err(anyhow::anyhow!(err.to_string()));
        }
    }

    Ok(Attachment {
        server_name,
        filename: SmolStr::new(filename),
        mime,
        children: current_level,
        content_key,
    })
}

fn file_basename(path: &Path) -> anyhow::Result<String> {
    let name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("missing filename"))?;
    let name = name
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("filename is not valid utf-8"))?;
    Ok(name.to_string())
}
