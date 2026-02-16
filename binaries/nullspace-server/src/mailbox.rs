mod pubsub;

use std::collections::BTreeMap;
use std::sync::LazyLock;

use bytes::Bytes;
use futures_concurrency::future::Race;
use nullspace_crypt::hash::{BcsHashExt, Hash};
use nullspace_structs::server::{
    AuthToken, MailboxAcl, MailboxId, MailboxRecvArgs, ServerRpcError,
};
use nullspace_structs::{
    Blob, group::GroupId, server::MailboxEntry, timestamp::NanoTimestamp, username::UserName,
};
use sqlx::{Sqlite, Transaction};
use tokio::time::{Duration, timeout};

use crate::database::DATABASE;
use crate::fatal_retry_later;
use crate::mailbox::pubsub::PubSub;

static MAILBOX_NOTIFY: LazyLock<PubSub> = LazyLock::new(PubSub::new);

pub async fn mailbox_send(
    auth: AuthToken,
    mailbox: MailboxId,
    message: Blob,
    ttl: u32,
) -> Result<NanoTimestamp, ServerRpcError> {
    let mut tx = DATABASE.begin().await.map_err(fatal_retry_later)?;
    let now = NanoTimestamp::now();
    purge_expired_entries(&mut tx, now).await?;
    let acl = acl_for_token(&mut tx, &mailbox, auth).await?;
    if !acl.can_send {
        tracing::debug!(auth = ?auth, mailbox = ?mailbox, "mailbox send denied");
        return Err(ServerRpcError::AccessDenied);
    }
    let received_at = now;
    let expires_at = expires_at_from_ttl(received_at, ttl);
    let sender_hash = auth.bcs_hash();
    sqlx::query(
        "INSERT INTO mailbox_entries \
         (mailbox_id, received_at, message_kind, message_body, sender_auth_token_hash, expires_at) \
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(mailbox.to_bytes().to_vec())
    .bind(received_at.0 as i64)
    .bind(message.kind.to_string())
    .bind(message.inner.to_vec())
    .bind(sender_hash.to_bytes().to_vec())
    .bind(expires_at)
    .execute(tx.as_mut())
    .await
    .map_err(fatal_retry_later)?;
    tx.commit().await.map_err(fatal_retry_later)?;
    tracing::debug!(auth = ?auth, mailbox = ?mailbox, "mailbox send accepted");
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
                let acl = acl_for_token(&mut tx, &arg.mailbox, arg.auth).await?;
                if !acl.can_recv {
                    tracing::debug!(auth = ?arg.auth, mailbox = ?arg.mailbox, "mailbox recv denied");
                    return Err(ServerRpcError::AccessDenied);
                }
                let rows = sqlx::query_as::<_, (i64, String, Vec<u8>, Option<Vec<u8>>)>(
                    "SELECT received_at, message_kind, message_body, sender_auth_token_hash \
                FROM mailbox_entries \
                WHERE mailbox_id = ? AND received_at > ? AND (expires_at IS NULL OR expires_at > ?) \
                ORDER BY received_at, entry_id
                LIMIT 100",
                )
                .bind(arg.mailbox.to_bytes().to_vec())
                .bind(arg.after.0 as i64)
                .bind(now.0 as i64)
                .fetch_all(tx.as_mut())
                .await
                .map_err(fatal_retry_later)?;
                let mut entries = Vec::with_capacity(rows.len());
                for (received_at, kind, body, sender_hash) in rows {
                    let message = Blob {
                        kind: kind.into(),
                        inner: Bytes::from(body),
                    };
                    let sender_auth_token_hash = match sender_hash {
                        Some(bytes) => {
                            let buf: [u8; 32] = bytes
                                .try_into()
                                .map_err(|_| fatal_retry_later("invalid sender auth token hash"))?;
                            Some(nullspace_crypt::hash::Hash::from_bytes(buf))
                        }
                        None => None,
                    };
                    entries.push(MailboxEntry {
                        message,
                        received_at: NanoTimestamp(received_at as u64),
                        sender_auth_token_hash,
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

pub async fn mailbox_acl_edit(
    auth: AuthToken,
    mailbox: MailboxId,
    arg: MailboxAcl,
) -> Result<(), ServerRpcError> {
    let mut tx = DATABASE.begin().await.map_err(fatal_retry_later)?;
    let caller_hash = auth.bcs_hash();
    if arg.token_hash == caller_hash && acl_is_empty(&arg) {
        delete_acl(&mut tx, &mailbox, &arg.token_hash).await?;
        tx.commit().await.map_err(fatal_retry_later)?;
        tracing::debug!(
            auth = ?auth,
            mailbox = ?mailbox,
            token_hash = %arg.token_hash,
            "mailbox acl self-removal accepted"
        );
        return Ok(());
    }
    let existing = load_acl_hash(&mut tx, &mailbox, arg.token_hash).await?;
    if let Some(existing) = &existing
        && existing.can_edit_acl == arg.can_edit_acl
        && existing.can_send == arg.can_send
        && existing.can_recv == arg.can_recv
    {
        tx.commit().await.map_err(fatal_retry_later)?;
        tracing::debug!(
            auth = ?auth,
            mailbox = ?mailbox,
            token_hash = %arg.token_hash,
            "mailbox acl edit no-op"
        );
        return Ok(());
    }
    let acl = acl_for_token(&mut tx, &mailbox, auth).await?;
    let can_add_subset = existing.is_none() && acl_is_subset(&arg, &acl);
    if !acl.can_edit_acl && !can_add_subset {
        tracing::debug!(auth = ?auth, mailbox = ?mailbox, "mailbox acl edit denied");
        return Err(ServerRpcError::AccessDenied);
    }
    insert_acl(&mut tx, &mailbox, &arg).await?;
    tx.commit().await.map_err(fatal_retry_later)?;
    tracing::debug!(auth = ?auth, mailbox = ?mailbox, token_hash = %arg.token_hash, "mailbox acl edit accepted");
    Ok(())
}

pub async fn update_dm_mailbox(
    tx: &mut Transaction<'_, Sqlite>,
    username: &UserName,
    new_token: Option<AuthToken>,
) -> Result<(), ServerRpcError> {
    let mailbox_id = MailboxId::direct(username);
    let created_at = NanoTimestamp::now().0 as i64;
    sqlx::query("INSERT OR IGNORE INTO mailboxes (mailbox_id, created_at) VALUES (?, ?)")
        .bind(mailbox_id.to_bytes().to_vec())
        .bind(created_at)
        .execute(tx.as_mut())
        .await
        .map_err(fatal_retry_later)?;

    let anonymous = AuthToken::anonymous();
    let anonymous_acl = MailboxAcl {
        token_hash: anonymous.bcs_hash(),
        can_edit_acl: false,
        can_send: true,
        can_recv: false,
    };
    insert_acl(tx, &mailbox_id, &anonymous_acl).await?;

    if let Some(token) = new_token {
        let device_acl = MailboxAcl {
            token_hash: token.bcs_hash(),
            can_edit_acl: false,
            can_send: true,
            can_recv: true,
        };
        insert_acl(tx, &mailbox_id, &device_acl).await?;
    }
    Ok(())
}

pub async fn register_group(auth: AuthToken, group: GroupId) -> Result<(), ServerRpcError> {
    let mut tx = DATABASE.begin().await.map_err(fatal_retry_later)?;
    if !auth_token_exists(&mut tx, auth).await? {
        tracing::debug!(auth = ?auth, "group mailbox create denied: unknown auth token");
        return Err(ServerRpcError::AccessDenied);
    }
    let created_at = NanoTimestamp::now().0 as i64;
    let mailboxes = [
        MailboxId::group_messages(&group),
        MailboxId::group_management(&group),
    ];
    for mailbox_id in mailboxes {
        sqlx::query("INSERT OR IGNORE INTO mailboxes (mailbox_id, created_at) VALUES (?, ?)")
            .bind(mailbox_id.to_bytes().to_vec())
            .bind(created_at)
            .execute(tx.as_mut())
            .await
            .map_err(fatal_retry_later)?;
        let acl = MailboxAcl {
            token_hash: auth.bcs_hash(),
            can_edit_acl: true,
            can_send: true,
            can_recv: true,
        };
        insert_acl(&mut tx, &mailbox_id, &acl).await?;
    }
    tx.commit().await.map_err(fatal_retry_later)?;
    tracing::debug!(auth = ?auth, group = ?group, "group mailboxes created");
    Ok(())
}

async fn acl_for_token(
    tx: &mut Transaction<'_, Sqlite>,
    mailbox_id: &MailboxId,
    token: AuthToken,
) -> Result<MailboxAcl, ServerRpcError> {
    if let Some(acl) = load_acl(tx, mailbox_id, token).await? {
        return Ok(acl);
    }
    let anonymous = AuthToken::anonymous();

    if let Some(acl) = load_acl(tx, mailbox_id, anonymous).await? {
        return Ok(acl);
    }
    Ok(empty_acl(token))
}

async fn insert_acl(
    tx: &mut Transaction<'_, Sqlite>,
    mailbox_id: &MailboxId,
    acl: &MailboxAcl,
) -> Result<(), ServerRpcError> {
    sqlx::query(
        "INSERT OR REPLACE INTO mailbox_acl \
         (mailbox_id, token_hash, can_edit_acl, can_send, can_recv) \
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(mailbox_id.to_bytes().to_vec())
    .bind(acl.token_hash.to_bytes().to_vec())
    .bind(i64::from(acl.can_edit_acl))
    .bind(i64::from(acl.can_send))
    .bind(i64::from(acl.can_recv))
    .execute(tx.as_mut())
    .await
    .map_err(fatal_retry_later)?;
    Ok(())
}

async fn load_acl(
    tx: &mut Transaction<'_, Sqlite>,
    mailbox_id: &MailboxId,
    token: AuthToken,
) -> Result<Option<MailboxAcl>, ServerRpcError> {
    load_acl_hash(tx, mailbox_id, token.bcs_hash()).await
}

fn empty_acl(token: AuthToken) -> MailboxAcl {
    MailboxAcl {
        token_hash: token.bcs_hash(),
        can_edit_acl: false,
        can_send: false,
        can_recv: false,
    }
}

fn acl_is_subset(candidate: &MailboxAcl, holder: &MailboxAcl) -> bool {
    (!candidate.can_edit_acl || holder.can_edit_acl)
        && (!candidate.can_send || holder.can_send)
        && (!candidate.can_recv || holder.can_recv)
}

fn acl_is_empty(candidate: &MailboxAcl) -> bool {
    !candidate.can_edit_acl && !candidate.can_send && !candidate.can_recv
}

async fn load_acl_hash(
    tx: &mut Transaction<'_, Sqlite>,
    mailbox_id: &MailboxId,
    token_hash: Hash,
) -> Result<Option<MailboxAcl>, ServerRpcError> {
    let row = sqlx::query_as::<_, (i64, i64, i64)>(
        "SELECT can_edit_acl, can_send, can_recv \
         FROM mailbox_acl WHERE mailbox_id = ? AND token_hash = ?",
    )
    .bind(mailbox_id.to_bytes().to_vec())
    .bind(token_hash.to_bytes().to_vec())
    .fetch_optional(tx.as_mut())
    .await
    .map_err(fatal_retry_later)?;
    Ok(row.map(|(can_edit_acl, can_send, can_recv)| MailboxAcl {
        token_hash,
        can_edit_acl: can_edit_acl != 0,
        can_send: can_send != 0,
        can_recv: can_recv != 0,
    }))
}

async fn delete_acl(
    tx: &mut Transaction<'_, Sqlite>,
    mailbox_id: &MailboxId,
    token_hash: &Hash,
) -> Result<(), ServerRpcError> {
    sqlx::query("DELETE FROM mailbox_acl WHERE mailbox_id = ? AND token_hash = ?")
        .bind(mailbox_id.to_bytes().to_vec())
        .bind(token_hash.to_bytes().to_vec())
        .execute(tx.as_mut())
        .await
        .map_err(fatal_retry_later)?;
    Ok(())
}

async fn auth_token_exists(
    tx: &mut Transaction<'_, Sqlite>,
    auth: AuthToken,
) -> Result<bool, ServerRpcError> {
    let auth_bytes = bcs::to_bytes(&auth).map_err(fatal_retry_later)?;
    let row = sqlx::query_scalar::<_, i64>(
        "SELECT 1 FROM device_auth_tokens WHERE auth_token = ? LIMIT 1",
    )
    .bind(auth_bytes)
    .fetch_optional(tx.as_mut())
    .await
    .map_err(fatal_retry_later)?;
    Ok(row.is_some())
}

fn expires_at_from_ttl(received_at: NanoTimestamp, ttl: u32) -> Option<i64> {
    if ttl == 0 {
        return None;
    }
    let ttl_ns = u64::from(ttl).saturating_mul(1_000_000_000);
    Some(received_at.0.saturating_add(ttl_ns) as i64)
}

async fn purge_expired_entries(
    tx: &mut Transaction<'_, Sqlite>,
    now: NanoTimestamp,
) -> Result<(), ServerRpcError> {
    sqlx::query(
        "DELETE FROM mailbox_entries \
         WHERE expires_at IS NOT NULL AND expires_at <= ?",
    )
    .bind(now.0 as i64)
    .execute(tx.as_mut())
    .await
    .map_err(fatal_retry_later)?;
    Ok(())
}
