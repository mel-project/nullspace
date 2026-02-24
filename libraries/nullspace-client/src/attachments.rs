use std::collections::HashSet;
use std::future::Future;
use std::io::SeekFrom;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, LazyLock};

use anyctx::AnyCtx;
use bytes::Bytes;
use fast_image_resize as fr;
use fast_thumbhash::rgba_to_thumb_hash_b91;

use futures_util::stream::{self, StreamExt, TryStreamExt};
use nullspace_crypt::aead::AeadKey;
use nullspace_crypt::hash::{BcsHashExt, BytesHashExt, Hash};
use nullspace_structs::fragment::{
    Attachment, Fragment, FragmentLeaf, FragmentNode, ImageAttachment,
};
use nullspace_structs::server::ServerClient;
use nullspace_structs::username::UserName;
use parking_lot::Mutex;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use smol_str::SmolStr;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

use crate::Config;
use crate::auth_tokens::get_auth_token;
use crate::database::{DATABASE, identity_exists};
use crate::directory::DIR_CLIENT;
use crate::events::emit_event;
use crate::identity::Identity;
use crate::internal::{Event, InternalRpcError, UploadedRoot};
use crate::server::get_server_client;

const MAX_CHUNK_SIZE: usize = 512 * 1024;
const MAX_FANOUT: usize = 16;

const TRANSFER_CONCURRENCY: usize = 16;
const IMAGE_MAX_DIMENSION: u32 = 2000;
const IMAGE_TARGET_SIZE_BYTES: usize = 500_000;
const IMAGE_WEBP_QUALITY: f32 = 70.0;
const THUMBHASH_MAX_DIMENSION: u32 = 100;

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AttachmentStatus {
    pub frag_root: Attachment,
    pub saved_to: Option<PathBuf>,
}

pub async fn attachment_upload(
    ctx: &AnyCtx<Config>,
    absolute_path: PathBuf,
    mime: SmolStr,
) -> anyhow::Result<i64> {
    let upload_id = rand::random();
    let ctx = ctx.clone();
    tokio::spawn(async move {
        match upload_inner(&ctx, absolute_path, mime, upload_id).await {
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
        match upload_image_inner(&ctx, absolute_path, upload_id).await {
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

async fn upload_inner(
    ctx: &AnyCtx<Config>,
    absolute_path: PathBuf,
    mime: SmolStr,
    upload_id: i64,
) -> anyhow::Result<Attachment> {
    let db = ctx.get(DATABASE);
    if !identity_exists(db).await? {
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

    let identity = Identity::load(db).await?;
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
                let response = client.v1_upload_frag(auth, Fragment::Leaf(leaf), 0).await?;
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
        let response = client.v1_upload_frag(auth, Fragment::Node(node), 0).await?;
        if let Err(err) = response {
            return Err(anyhow::anyhow!(err.to_string()));
        }
    }

    Ok(Attachment {
        filename: SmolStr::new(filename),
        mime,
        children: current_level,
        content_key,
    })
}

async fn upload_image_inner(
    ctx: &AnyCtx<Config>,
    absolute_path: PathBuf,
    upload_id: i64,
) -> anyhow::Result<ImageAttachment> {
    let source_bytes = tokio::fs::read(&absolute_path).await?;
    let (webp_bytes, thumbhash, width, height) =
        tokio::task::spawn_blocking(move || prepare_webp_and_thumbhash(&source_bytes))
            .await
            .map_err(|err| anyhow::anyhow!("image preprocessing task failed: {err}"))??;

    let filename_hash = webp_bytes.bytes_hash();
    let filename = format!("nullspace-{filename_hash}.webp");
    let temp_path = std::env::temp_dir()
        .join("nullspace-image-upload")
        .join(&filename);
    let parent = temp_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("invalid temporary upload path"))?;
    tokio::fs::create_dir_all(parent).await?;
    tokio::fs::write(&temp_path, &webp_bytes).await?;

    let upload_result = upload_inner(
        ctx,
        temp_path.clone(),
        SmolStr::new("image/webp"),
        upload_id,
    )
    .await;
    let _ = tokio::fs::remove_file(&temp_path).await;
    let inner = upload_result?;

    Ok(ImageAttachment {
        width,
        height,
        thumbhash,
        inner,
    })
}

fn prepare_webp_and_thumbhash(source_bytes: &[u8]) -> anyhow::Result<(Vec<u8>, String, u32, u32)> {
    let decoded = image::load_from_memory(source_bytes)?;
    let (src_w, src_h) = (decoded.width(), decoded.height());
    if src_w == 0 || src_h == 0 {
        return Err(anyhow::anyhow!("image has invalid dimensions"));
    }

    // Use native pixel format to avoid a full-resolution RGBA conversion.
    let (src_buf, pixel_type) = match decoded {
        image::DynamicImage::ImageRgb8(img) => (img.into_raw(), fr::PixelType::U8x3),
        image::DynamicImage::ImageRgba8(img) => (img.into_raw(), fr::PixelType::U8x4),
        other => (other.into_rgba8().into_raw(), fr::PixelType::U8x4),
    };

    // Linearize the source image once, then reuse for all resize iterations.
    let mut src_image = fr::images::Image::from_vec_u8(src_w, src_h, src_buf, pixel_type)
        .map_err(|err| anyhow::anyhow!("failed to prepare source image: {err}"))?;
    let srgb_mapper = fr::create_srgb_mapper();
    srgb_mapper
        .forward_map_inplace(&mut src_image)
        .map_err(|err| anyhow::anyhow!("failed to linearize source image: {err}"))?;

    let (mut width, mut height) = fit_within(src_w, src_h, IMAGE_MAX_DIMENSION);
    tracing::debug!(
        width,
        height,
        quality = IMAGE_WEBP_QUALITY,
        "image upload compression parameters"
    );

    loop {
        let resized = resize_linear(&src_image, &srgb_mapper, width, height)?;
        let webp_bytes = encode_webp(pixel_type, &resized, width, height)?;
        if webp_bytes.len() <= IMAGE_TARGET_SIZE_BYTES || (width == 1 && height == 1) {
            let thumbhash = make_thumbhash_b91(pixel_type, &resized, width, height)?;
            return Ok((webp_bytes, thumbhash, src_w, src_h));
        }
        width = (width / 2).max(1);
        height = (height / 2).max(1);
    }
}

fn fit_within(width: u32, height: u32, max_side: u32) -> (u32, u32) {
    let longest = width.max(height);
    if longest <= max_side {
        return (width, height);
    }
    let scale = max_side as f64 / longest as f64;
    let new_w = ((width as f64) * scale).round().max(1.0) as u32;
    let new_h = ((height as f64) * scale).round().max(1.0) as u32;
    (new_w, new_h)
}

/// Resize an already-linearized source image and convert the result back to sRGB.
fn resize_linear(
    src: &fr::images::Image,
    srgb_mapper: &fr::PixelComponentMapper,
    dst_w: u32,
    dst_h: u32,
) -> anyhow::Result<fr::images::Image<'static>> {
    if src.width() == dst_w && src.height() == dst_h {
        let mut out = src.copy();
        srgb_mapper
            .backward_map_inplace(&mut out)
            .map_err(|err| anyhow::anyhow!("failed to convert from linear: {err}"))?;
        return Ok(out);
    }
    let mut dst = fr::images::Image::new(dst_w, dst_h, src.pixel_type());
    let options =
        fr::ResizeOptions::new().resize_alg(fr::ResizeAlg::Convolution(fr::FilterType::Lanczos3));
    let mut resizer = fr::Resizer::new();
    resizer
        .resize(src, &mut dst, Some(&options))
        .map_err(|err| anyhow::anyhow!("failed to resize image: {err}"))?;
    srgb_mapper
        .backward_map_inplace(&mut dst)
        .map_err(|err| anyhow::anyhow!("failed to convert from linear: {err}"))?;
    Ok(dst)
}

fn encode_webp(
    pixel_type: fr::PixelType,
    image: &fr::images::Image,
    width: u32,
    height: u32,
) -> anyhow::Result<Vec<u8>> {
    let encoder = match pixel_type {
        fr::PixelType::U8x3 => webp::Encoder::from_rgb(image.buffer(), width, height),
        _ => webp::Encoder::from_rgba(image.buffer(), width, height),
    };
    Ok(encoder.encode(IMAGE_WEBP_QUALITY).to_vec())
}

fn make_thumbhash_b91(
    pixel_type: fr::PixelType,
    image: &fr::images::Image,
    width: u32,
    height: u32,
) -> anyhow::Result<String> {
    let (thumb_w, thumb_h) = fit_within(width, height, THUMBHASH_MAX_DIMENSION);
    // Thumbhash needs RGBA. Convert only this small image.
    let rgba_buf = if thumb_w == width && thumb_h == height {
        to_rgba_buf(pixel_type, image.buffer())
    } else {
        // Re-linearize the (already sRGB) resized image for a second resize.
        let srgb_mapper = fr::create_srgb_mapper();
        let mut src = fr::images::Image::from_vec_u8(
            width,
            height,
            image.buffer().to_vec(),
            pixel_type,
        )
        .map_err(|err| anyhow::anyhow!("failed to prepare thumbhash source: {err}"))?;
        srgb_mapper.forward_map_inplace(&mut src).ok();
        let preview = resize_linear(&src, &srgb_mapper, thumb_w, thumb_h)?;
        to_rgba_buf(pixel_type, preview.buffer())
    };
    Ok(rgba_to_thumb_hash_b91(
        thumb_w as usize,
        thumb_h as usize,
        &rgba_buf,
    ))
}

fn to_rgba_buf(pixel_type: fr::PixelType, buf: &[u8]) -> Vec<u8> {
    match pixel_type {
        fr::PixelType::U8x4 => buf.to_vec(),
        _ => {
            let mut rgba = Vec::with_capacity(buf.len() / 3 * 4);
            for chunk in buf.chunks_exact(3) {
                rgba.extend_from_slice(chunk);
                rgba.push(255);
            }
            rgba
        }
    }
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
    sender: UserName,
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

    let server_name = ctx
        .get(DIR_CLIENT)
        .get_user_descriptor(&sender)
        .await?
        .ok_or_else(|| anyhow::anyhow!("sender not in directory"))?
        .server_name;
    let client = get_server_client(ctx, &server_name).await?;
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
    if !identity_exists(db).await? {
        return Err(InternalRpcError::NotReady.into());
    }
    let (sender_username, root) =
        load_attachment_root(&mut *db.acquire().await?, attachment_id).await?;
    let sender = UserName::parse(&sender_username)?;
    let server_name = ctx
        .get(DIR_CLIENT)
        .get_user_descriptor(&sender)
        .await?
        .ok_or_else(|| anyhow::anyhow!("sender not in directory"))?
        .server_name;
    let client = get_server_client(ctx, &server_name).await?;

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

    let (temp_path, mut file) = loop {
        let temp_path = create_temp_path(parent, final_path);
        match tokio::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temp_path)
            .await
        {
            Ok(file) => break (temp_path, file),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(err.into()),
        }
    };

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
        let response = client.v1_download_frag(hash).await?;
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

fn create_temp_path(parent: &Path, target: &Path) -> PathBuf {
    let mut nonce = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut nonce);
    let nonce = u64::from_le_bytes(nonce);
    let stem = target
        .file_name()
        .map(|name| name.to_string_lossy())
        .unwrap_or_default();
    let filename = format!("{stem}.part.{nonce:016x}");
    parent.join(filename)
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

fn file_basename(path: &Path) -> anyhow::Result<String> {
    let name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("missing filename"))?;
    let name = name
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("filename is not valid utf-8"))?;
    Ok(name.to_string())
}

