mod pubsub;

use std::collections::BTreeMap;
use std::sync::LazyLock;

use bytes::Bytes;
use futures_concurrency::future::Race;
use nullspace_crypt::hash::Hash;
use nullspace_structs::mailbox::{MailboxEntry, MailboxId, MailboxKey, MailboxRecvArgs};
use nullspace_structs::server::{AuthToken, ServerRpcError};
use nullspace_structs::{Blob, timestamp::NanoTimestamp};
use sqlx::{Sqlite, Transaction};
use tokio::time::{Duration, timeout};

use crate::database::DATABASE;
use crate::fatal_retry_later;
use crate::mailbox::pubsub::PubSub;

static MAILBOX_NOTIFY: LazyLock<PubSub> = LazyLock::new(PubSub::new);

pub async fn mailbox_create(
    auth: AuthToken,
    mailbox_key: MailboxKey,
) -> Result<MailboxId, ServerRpcError> {
    let mut tx = DATABASE.begin().await.map_err(fatal_retry_later)?;
    let Some(username) = username_for_auth_token(&mut tx, auth).await? else {
        tracing::debug!(auth = ?auth, "mailbox create denied: unknown auth token");
        return Err(ServerRpcError::AccessDenied);
    };

    let mailbox_id = mailbox_key.mailbox_id();
    let mailbox_key_hash = Hash::digest(&mailbox_key.to_bytes());
    let created_at = NanoTimestamp::now().0 as i64;

    sqlx::query(
        "INSERT OR IGNORE INTO mailboxes (mailbox_id, mailbox_key_hash, owner_username, created_at) \
         VALUES (?, ?, ?, ?)",
    )
    .bind(mailbox_id.to_bytes().to_vec())
    .bind(mailbox_key_hash.to_bytes().to_vec())
    .bind(username.as_str())
    .bind(created_at)
    .execute(tx.as_mut())
    .await
    .map_err(fatal_retry_later)?;

    let row = sqlx::query_as::<_, (Vec<u8>, String)>(
        "SELECT mailbox_key_hash, owner_username FROM mailboxes WHERE mailbox_id = ?",
    )
    .bind(mailbox_id.to_bytes().to_vec())
    .fetch_optional(tx.as_mut())
    .await
    .map_err(fatal_retry_later)?
    .ok_or_else(|| fatal_retry_later("mailbox missing after create"))?;

    let stored_hash = bytes_to_hash(&row.0)?;
    if stored_hash != mailbox_key_hash || row.1 != username.as_str() {
        tracing::debug!(auth = ?auth, mailbox = ?mailbox_id, "mailbox create denied: mailbox owned by another identity");
        return Err(ServerRpcError::AccessDenied);
    }

    tx.commit().await.map_err(fatal_retry_later)?;
    tracing::debug!(auth = ?auth, mailbox = ?mailbox_id, owner = %username, "mailbox create accepted");
    Ok(mailbox_id)
}

pub async fn mailbox_send(
    mailbox: MailboxId,
    message: Blob,
    ttl: u32,
) -> Result<NanoTimestamp, ServerRpcError> {
    let mut tx = DATABASE.begin().await.map_err(fatal_retry_later)?;
    let now = NanoTimestamp::now();
    purge_expired_entries(&mut tx, now).await?;

    if !mailbox_exists(&mut tx, &mailbox).await? {
        tracing::debug!(mailbox = ?mailbox, "mailbox send denied: mailbox does not exist");
        return Err(ServerRpcError::AccessDenied);
    }

    let received_at = now;
    let expires_at = expires_at_from_ttl(received_at, ttl);
    sqlx::query(
        "INSERT INTO mailbox_entries \
         (mailbox_id, received_at, message_body, expires_at) \
         VALUES (?, ?, ?, ?)",
    )
    .bind(mailbox.to_bytes().to_vec())
    .bind(received_at.0 as i64)
    .bind(message.0.to_vec())
    .bind(expires_at)
    .execute(tx.as_mut())
    .await
    .map_err(fatal_retry_later)?;

    tx.commit().await.map_err(fatal_retry_later)?;
    tracing::debug!(mailbox = ?mailbox, "mailbox send accepted");
    MAILBOX_NOTIFY.incr(mailbox);
    Ok(received_at)
}

pub async fn mailbox_multirecv(
    args: Vec<MailboxRecvArgs>,
    timeout_ms: u64,
) -> Result<BTreeMap<MailboxId, Vec<MailboxEntry>>, ServerRpcError> {
    tracing::debug!(args = args.len(), timeout_ms, "mailbox multirecv");
    let mut futs = vec![];
    for arg in args.iter() {
        futs.push(async {
            loop {
                let notify_ctr = MAILBOX_NOTIFY.counter(arg.mailbox);
                let mut tx = DATABASE.begin().await.map_err(fatal_retry_later)?;
                let now = NanoTimestamp::now();
                purge_expired_entries(&mut tx, now).await?;

                if !mailbox_key_allows_recv(&mut tx, &arg.mailbox, arg.mailbox_key).await? {
                    tracing::debug!(mailbox = ?arg.mailbox, "mailbox recv denied: invalid mailbox key");
                    return Err(ServerRpcError::AccessDenied);
                }

                let rows = sqlx::query_as::<_, (i64, Vec<u8>)>(
                    "SELECT received_at, message_body \
                     FROM mailbox_entries \
                     WHERE mailbox_id = ? AND received_at > ? AND (expires_at IS NULL OR expires_at > ?) \
                     ORDER BY received_at, entry_id \
                     LIMIT 100",
                )
                .bind(arg.mailbox.to_bytes().to_vec())
                .bind(arg.after.0 as i64)
                .bind(now.0 as i64)
                .fetch_all(tx.as_mut())
                .await
                .map_err(fatal_retry_later)?;

                let mut entries = Vec::with_capacity(rows.len());
                for (received_at, body) in rows {
                    entries.push(MailboxEntry {
                        body: Blob(Bytes::from(body)),
                        received_at: NanoTimestamp(received_at as u64),
                    });
                }

                tx.commit().await.map_err(fatal_retry_later)?;
                if !entries.is_empty() {
                    return Ok((arg.mailbox, entries));
                }
                MAILBOX_NOTIFY.wait_gt(arg.mailbox, notify_ctr).await;
            }
        })
    }

    let race = futs.race();
    let first = timeout(Duration::from_millis(timeout_ms), race).await;
    let Ok(first) = first else {
        return Ok(BTreeMap::new());
    };
    let (first_box, first_entries) = first?;
    let mut out = BTreeMap::new();
    out.insert(first_box, first_entries);
    Ok(out)
}

async fn mailbox_exists(
    tx: &mut Transaction<'_, Sqlite>,
    mailbox_id: &MailboxId,
) -> Result<bool, ServerRpcError> {
    let row = sqlx::query_scalar::<_, i64>("SELECT 1 FROM mailboxes WHERE mailbox_id = ?")
        .bind(mailbox_id.to_bytes().to_vec())
        .fetch_optional(tx.as_mut())
        .await
        .map_err(fatal_retry_later)?;
    Ok(row.is_some())
}

async fn mailbox_key_allows_recv(
    tx: &mut Transaction<'_, Sqlite>,
    mailbox_id: &MailboxId,
    mailbox_key: MailboxKey,
) -> Result<bool, ServerRpcError> {
    let expected_hash = Hash::digest(&mailbox_key.to_bytes());
    let stored = sqlx::query_scalar::<_, Vec<u8>>(
        "SELECT mailbox_key_hash FROM mailboxes WHERE mailbox_id = ?",
    )
    .bind(mailbox_id.to_bytes().to_vec())
    .fetch_optional(tx.as_mut())
    .await
    .map_err(fatal_retry_later)?;

    let Some(stored) = stored else {
        return Ok(false);
    };
    let stored_hash = bytes_to_hash(&stored)?;
    Ok(stored_hash == expected_hash)
}

async fn username_for_auth_token(
    tx: &mut Transaction<'_, Sqlite>,
    auth: AuthToken,
) -> Result<Option<String>, ServerRpcError> {
    let auth_bytes = bcs::to_bytes(&auth).map_err(fatal_retry_later)?;
    sqlx::query_scalar::<_, String>("SELECT username FROM device_auth_tokens WHERE auth_token = ?")
        .bind(auth_bytes)
        .fetch_optional(tx.as_mut())
        .await
        .map_err(fatal_retry_later)
}

async fn purge_expired_entries(
    tx: &mut Transaction<'_, Sqlite>,
    now: NanoTimestamp,
) -> Result<(), ServerRpcError> {
    sqlx::query("DELETE FROM mailbox_entries WHERE expires_at IS NOT NULL AND expires_at <= ?")
        .bind(now.0 as i64)
        .execute(tx.as_mut())
        .await
        .map_err(fatal_retry_later)?;
    Ok(())
}

fn expires_at_from_ttl(received_at: NanoTimestamp, ttl: u32) -> Option<i64> {
    if ttl == 0 {
        return None;
    }
    let ttl_ns = (ttl as u64).saturating_mul(1_000_000_000);
    let expires = received_at.0.saturating_add(ttl_ns);
    Some(expires as i64)
}

fn bytes_to_hash(value: &[u8]) -> Result<Hash, ServerRpcError> {
    let bytes: [u8; 32] = value
        .try_into()
        .map_err(|_| fatal_retry_later("invalid hash bytes"))?;
    Ok(Hash::from_bytes(bytes))
}
