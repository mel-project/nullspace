use nullspace_crypt::hash::{BcsHashExt, Hash};
use nullspace_structs::fragment::Attachment;

pub async fn store_attachment_root(
    conn: &mut sqlx::SqliteConnection,
    root: &Attachment,
) -> anyhow::Result<Hash> {
    let hash = root.bcs_hash();
    let root_bcs = bcs::to_bytes(root)?;
    sqlx::query(
        "INSERT INTO attachment_roots (hash, root) \
         VALUES (?, ?) \
         ON CONFLICT(hash) DO UPDATE SET \
           root = excluded.root",
    )
    .bind(hash.to_bytes().to_vec())
    .bind(root_bcs)
    .execute(conn)
    .await?;
    Ok(hash)
}

pub async fn load_attachment_root(
    db: &mut sqlx::SqliteConnection,
    attachment_id: Hash,
) -> anyhow::Result<Attachment> {
    let row = sqlx::query_scalar::<_, Vec<u8>>("SELECT root FROM attachment_roots WHERE hash = ?")
        .bind(attachment_id.to_bytes().to_vec())
        .fetch_optional(&mut *db)
        .await?;
    let Some(root_bytes) = row else {
        return Err(anyhow::anyhow!("attachment not found"));
    };
    Ok(bcs::from_bytes(&root_bytes)?)
}
