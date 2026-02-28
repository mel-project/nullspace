use nullspace_structs::mailbox::MailboxId;
use nullspace_structs::timestamp::NanoTimestamp;

pub async fn ensure_mailbox_state(
    conn: &mut sqlx::SqliteConnection,
    server_name: &nullspace_structs::server::ServerName,
    mailbox: MailboxId,
    initial_after: NanoTimestamp,
) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT OR IGNORE INTO mailbox_state (server_name, mailbox_id, after_timestamp) \
         VALUES (?, ?, ?)",
    )
    .bind(server_name.as_str())
    .bind(mailbox.to_bytes().to_vec())
    .bind(initial_after.0 as i64)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

pub async fn load_mailbox_after(
    conn: &mut sqlx::SqliteConnection,
    server_name: &nullspace_structs::server::ServerName,
    mailbox: MailboxId,
) -> anyhow::Result<NanoTimestamp> {
    let row = sqlx::query_as::<_, (i64,)>(
        "SELECT after_timestamp FROM mailbox_state \
         WHERE server_name = ? AND mailbox_id = ?",
    )
    .bind(server_name.as_str())
    .bind(mailbox.to_bytes().to_vec())
    .fetch_optional(&mut *conn)
    .await?;
    Ok(row
        .map(|(after,)| NanoTimestamp(after as u64))
        .unwrap_or(NanoTimestamp(0)))
}

pub async fn update_mailbox_after(
    conn: &mut sqlx::SqliteConnection,
    server_name: &nullspace_structs::server::ServerName,
    mailbox: MailboxId,
    after: NanoTimestamp,
) -> anyhow::Result<()> {
    sqlx::query(
        "UPDATE mailbox_state SET after_timestamp = ? \
         WHERE server_name = ? AND mailbox_id = ?",
    )
    .bind(after.0 as i64)
    .bind(server_name.as_str())
    .bind(mailbox.to_bytes().to_vec())
    .execute(&mut *conn)
    .await?;
    Ok(())
}
