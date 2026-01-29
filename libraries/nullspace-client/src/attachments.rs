use std::path::{Path, PathBuf};

use anyctx::AnyCtx;
use bytes::Bytes;
use nullspace_crypt::aead::AeadKey;
use nullspace_crypt::hash::{BcsHashExt, Hash};
use nullspace_structs::fragment::{Fragment, FragmentLeaf, FragmentNode, FragmentRoot};
use nullspace_structs::username::UserName;
use serde::{Deserialize, Serialize};
use smol_str::SmolStr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::Config;
use crate::database::{DATABASE, identity_exists};
use crate::directory::DIR_CLIENT;
use crate::events::emit_event;
use crate::identity::Identity;
use crate::internal::{Event, InternalRpcError, device_auth};
use crate::server::get_server_client;

const CHUNK_SIZE_BYTES: usize = 256 * 1024;
const MAX_FANOUT: usize = 4096;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AttachmentStatus {
    pub frag_root: FragmentRoot,
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
        if let Err(err) = upload_inner(&ctx, absolute_path, mime, upload_id).await {
            emit_event(
                &ctx,
                Event::UploadFailed {
                    id: upload_id,
                    error: err.to_string(),
                },
            );
        }
    });
    Ok(upload_id)
}

fn nonce_for_leaf(index: u64) -> [u8; 24] {
    let mut nonce = [0u8; 24];
    nonce[..8].copy_from_slice(b"NSFRAG01");
    nonce[8..16].copy_from_slice(&index.to_le_bytes());
    nonce
}

async fn upload_inner(
    ctx: &AnyCtx<Config>,
    absolute_path: PathBuf,
    mime: SmolStr,
    upload_id: i64,
) -> anyhow::Result<()> {
    let db = ctx.get(DATABASE);
    if !identity_exists(db).await? {
        return Err(InternalRpcError::NotReady.into());
    }

    let identity = Identity::load(db).await?;
    let server_name = identity
        .server_name
        .clone()
        .ok_or_else(|| anyhow::anyhow!("server name not available"))?;
    let client = get_server_client(ctx, &server_name).await?;
    let auth = device_auth(&client, &identity.username, &identity.cert_chain).await?;

    let filename = file_basename(&absolute_path)?;
    let mut file = tokio::fs::File::open(&absolute_path).await?;
    let total_size = file.metadata().await?.len();
    let content_key = AeadKey::random();
    let mut uploaded_size = 0u64;
    let mut leaf_index = 0u64;
    let mut current_level: Vec<ChildRef> = Vec::new();
    let mut buf = vec![0u8; CHUNK_SIZE_BYTES];

    loop {
        let read = file.read(&mut buf).await?;
        if read == 0 {
            break;
        }
        let nonce = nonce_for_leaf(leaf_index);
        let ciphertext = content_key
            .encrypt(nonce, &buf[..read], &[])
            .map_err(|_| anyhow::anyhow!("chunk encryption failed"))?;
        let leaf = FragmentLeaf {
            data: Bytes::from(ciphertext),
        };
        let hash = Fragment::Leaf(leaf.clone()).bcs_hash();
        current_level.push(ChildRef {
            hash,
            size: read as u64,
        });
        let response = client.v1_upload_frag(auth, Fragment::Leaf(leaf), 0).await?;
        if let Err(err) = response {
            return Err(anyhow::anyhow!(err.to_string()));
        }
        uploaded_size = uploaded_size.saturating_add(read as u64);
        emit_event(
            ctx,
            Event::UploadProgress {
                id: upload_id,
                uploaded_size,
                total_size,
            },
        );
        leaf_index = leaf_index.saturating_add(1);
    }

    let mut nodes: Vec<FragmentNode> = Vec::new();
    while current_level.len() > MAX_FANOUT {
        let mut next_level = Vec::new();
        for group in current_level.chunks(MAX_FANOUT) {
            let pointers: Vec<nullspace_crypt::hash::Hash> =
                group.iter().map(|child| child.hash).collect();
            let size = group.iter().map(|child| child.size).sum();
            let node = FragmentNode { size, pointers };
            let hash = Fragment::Node(node.clone()).bcs_hash();
            next_level.push(ChildRef { hash, size });
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

    let root = FragmentRoot {
        filename: SmolStr::new(filename),
        mime,
        total_size,
        pointers: current_level.into_iter().map(|child| child.hash).collect(),
        content_key: Some(content_key),
    };

    emit_event(
        ctx,
        Event::UploadDone {
            id: upload_id,
            root,
        },
    );
    Ok(())
}

pub async fn attachment_download(
    ctx: &AnyCtx<Config>,
    attachment_id: Hash,
    save_dir: PathBuf,
) -> anyhow::Result<i64> {
    if !save_dir.is_absolute() {
        return Err(anyhow::anyhow!("save dir must be absolute"));
    }
    let download_id = rand::random();
    let ctx = ctx.clone();
    tokio::spawn(async move {
        if let Err(err) = download_inner(&ctx, attachment_id, save_dir, download_id).await {
            emit_event(
                &ctx,
                Event::DownloadFailed {
                    id: download_id,
                    error: err.to_string(),
                },
            );
        }
    });
    Ok(download_id)
}

async fn download_inner(
    ctx: &AnyCtx<Config>,
    attachment_id: Hash,
    save_dir: PathBuf,
    download_id: i64,
) -> anyhow::Result<()> {
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

    tokio::fs::create_dir_all(&save_dir).await?;
    let filename = sanitize_filename(root.filename.as_str());
    let final_path = unique_path(&save_dir, &filename).await?;
    let part_path = final_path.with_extension("part");
    let mut file = tokio::fs::File::create(&part_path).await?;

    if root.pointers.is_empty() {
        file.flush().await?;
        tokio::fs::rename(&part_path, &final_path).await?;
        emit_event(
            ctx,
            Event::DownloadDone {
                id: download_id,
                absolute_path: final_path,
            },
        );
        return Ok(());
    }

    let mut stack: Vec<Hash> = root.pointers.iter().rev().cloned().collect();
    let mut leaf_index = 0u64;
    let mut downloaded_size = 0u64;

    while let Some(hash) = stack.pop() {
        let response = client.v1_download_frag(hash).await?;
        let frag = response
            .map_err(|err| anyhow::anyhow!(err.to_string()))?
            .ok_or_else(|| anyhow::anyhow!("missing fragment"))?;
        if frag.bcs_hash() != hash {
            return Err(anyhow::anyhow!("fragment hash mismatch"));
        }
        match frag {
            Fragment::Node(node) => {
                for child in node.pointers.iter().rev() {
                    stack.push(*child);
                }
            }
            Fragment::Leaf(leaf) => {
                let plaintext = if let Some(key) = &root.content_key {
                    let nonce = nonce_for_leaf(leaf_index);
                    key.decrypt(nonce, &leaf.data, &[])
                        .map_err(|_| anyhow::anyhow!("chunk decryption failed"))?
                } else {
                    leaf.data.to_vec()
                };
                file.write_all(&plaintext).await?;
                downloaded_size = downloaded_size.saturating_add(plaintext.len() as u64);
                emit_event(
                    ctx,
                    Event::DownloadProgress {
                        id: download_id,
                        downloaded_size,
                        total_size: root.total_size,
                    },
                );
                leaf_index = leaf_index.saturating_add(1);
            }
        }
    }

    if downloaded_size != root.total_size {
        return Err(anyhow::anyhow!("download size mismatch"));
    }

    file.flush().await?;
    tokio::fs::rename(&part_path, &final_path).await?;
    std::fs::File::open(&final_path)?.sync_all()?;
    sqlx::query("insert or replace into attachment_paths (hash, download_path) values ($1, $2)")
        .bind(attachment_id.to_bytes().as_slice())
        .bind(final_path.to_string_lossy())
        .execute(ctx.get(DATABASE))
        .await?;
    emit_event(
        ctx,
        Event::DownloadDone {
            id: download_id,
            absolute_path: final_path,
        },
    );
    Ok(())
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
    let frag_root: FragmentRoot = bcs::from_bytes(&root_bytes)?;
    Ok(AttachmentStatus {
        frag_root,
        saved_to: dl_path.map(|s| s.into()),
    })
}

pub async fn store_attachment_root(
    conn: &mut sqlx::SqliteConnection,
    sender: &UserName,
    root: &FragmentRoot,
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
) -> anyhow::Result<(String, FragmentRoot)> {
    let row = sqlx::query_as::<_, (String, Vec<u8>)>(
        "SELECT sender_username, root FROM attachment_roots WHERE hash = ?",
    )
    .bind(attachment_id.to_bytes().to_vec())
    .fetch_optional(db)
    .await?;
    let Some((sender_username, root_bytes)) = row else {
        return Err(anyhow::anyhow!("attachment not found"));
    };
    let root: FragmentRoot = bcs::from_bytes(&root_bytes)?;
    Ok((sender_username, root))
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

fn sanitize_filename(name: &str) -> String {
    let mut out = String::with_capacity(name.len().max(12));
    for ch in name.chars() {
        if ch == '/' || ch == '\\' || ch.is_control() {
            continue;
        }
        out.push(ch);
    }
    let trimmed = out.trim();
    if trimmed.is_empty() {
        "attachment.bin".to_string()
    } else {
        trimmed.to_string()
    }
}

async fn unique_path(dir: &Path, filename: &str) -> anyhow::Result<PathBuf> {
    let base = dir.join(filename);
    if tokio::fs::try_exists(&base).await? == false {
        return Ok(base);
    }
    let (stem, ext) = split_extension(filename);
    for i in 1..=9999 {
        let candidate = if ext.is_empty() {
            dir.join(format!("{stem} ({i})"))
        } else {
            dir.join(format!("{stem} ({i}).{ext}"))
        };
        if tokio::fs::try_exists(&candidate).await? == false {
            return Ok(candidate);
        }
    }
    Err(anyhow::anyhow!("could not pick unique filename"))
}

fn split_extension(filename: &str) -> (&str, &str) {
    let Some(pos) = filename.rfind('.') else {
        return (filename, "");
    };
    let (stem, ext) = filename.split_at(pos);
    let ext = ext.trim_start_matches('.');
    if stem.is_empty() || ext.is_empty() {
        (filename, "")
    } else {
        (stem, ext)
    }
}

struct ChildRef {
    hash: nullspace_crypt::hash::Hash,
    size: u64,
}
