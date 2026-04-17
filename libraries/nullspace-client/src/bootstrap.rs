use std::collections::{BTreeMap, BTreeSet};

use anyctx::AnyCtx;
use bytes::Bytes;
use nullspace_crypt::hash::Hash;
use nullspace_crypt::signing::SigningPublic;
use nullspace_structs::certificate::DeviceSecret;
use nullspace_structs::directory::DirectoryUpdate;
use nullspace_structs::event::{MessagePayload, TAG_MESSAGE};
use nullspace_structs::group::{
    GroupBearerKey, GroupId, GroupMetadata, GroupRoster, GroupRosterSettings, MemberState,
};
use nullspace_structs::mailbox::{MailboxId, MailboxKey};
use nullspace_structs::server::ServerName;
use nullspace_structs::timestamp::NanoTimestamp;
use nullspace_structs::username::UserName;
use serde::{Deserialize, Serialize};

use crate::api::{InternalRpcError, internal_err};
use crate::config::Config;
use crate::database::DATABASE;
use crate::storage::{
    ensure_thread_id, load_roster, replace_current_roster, store_attachment_root, store_gbk,
};

const MAX_TRANSFER_MESSAGES_PER_THREAD: usize = 1000;

#[derive(Clone, Serialize, Deserialize)]
pub struct ProvisioningBootstrap {
    pub device_secret: DeviceSecret,
    pub add_device_update: DirectoryUpdate,
    pub dm_mailbox_key: MailboxKey,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ProvisioningBundle {
    pub bootstrap: ProvisioningBootstrap,
    pub threads: Vec<ProvisioningThread>,
    pub events: Vec<ProvisioningEvent>,
    pub groups: Vec<ProvisioningGroupState>,
    pub mailbox_state: Vec<ProvisioningMailboxState>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ProvisioningThread {
    pub id: i64,
    pub thread_kind: String,
    pub thread_counterparty: String,
    pub created_at: i64,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ProvisioningEvent {
    pub id: i64,
    pub thread_id: i64,
    pub sender_username: String,
    pub event_tag: u16,
    pub event_body: Bytes,
    pub event_after: Option<Hash>,
    pub event_hash: Hash,
    pub sent_at: NanoTimestamp,
    pub received_at: NanoTimestamp,
    pub read_at: Option<NanoTimestamp>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ProvisioningGroupState {
    pub group_id: GroupId,
    pub rotation_index: u64,
    pub gbk: GroupBearerKey,
    pub server_name: ServerName,
    pub admin_set: BTreeSet<SigningPublic>,
    pub rotation_hash: Hash,
    pub title: Option<String>,
    pub description: Option<String>,
    pub new_members_muted: bool,
    pub allow_new_members_to_see_history: bool,
    pub members: Vec<ProvisioningGroupMember>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ProvisioningGroupMember {
    pub username: UserName,
    pub is_admin: bool,
    pub is_muted: bool,
    pub is_banned: bool,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ProvisioningMailboxState {
    pub server_name: ServerName,
    pub mailbox_id: MailboxId,
    pub after_timestamp: NanoTimestamp,
}

#[derive(sqlx::FromRow)]
struct ThreadRow {
    id: i64,
    thread_kind: String,
    thread_counterparty: String,
    created_at: i64,
}

#[derive(sqlx::FromRow)]
struct EventRow {
    id: i64,
    thread_id: i64,
    sender_username: String,
    event_tag: i64,
    event_body: Vec<u8>,
    event_after: Option<Vec<u8>>,
    event_hash: Vec<u8>,
    sent_at: i64,
    received_at: i64,
    read_at: Option<i64>,
}

#[derive(sqlx::FromRow)]
struct GroupKeyRow {
    group_id: Vec<u8>,
    gbk: Vec<u8>,
    server_name: String,
    admin_set: Vec<u8>,
    rotation_hash: Vec<u8>,
}

pub async fn build_provisioning_bundle(
    ctx: &AnyCtx<Config>,
    bootstrap: ProvisioningBootstrap,
    dm_server_name: ServerName,
) -> Result<ProvisioningBundle, InternalRpcError> {
    let db = ctx.get(DATABASE);
    let mut conn = db.acquire().await.map_err(internal_err)?;
    let groups = export_group_states(&mut conn).await.map_err(internal_err)?;
    let (threads, events) = export_threads(&mut conn, &groups).await.map_err(internal_err)?;
    let mailbox_state = export_mailbox_state(&mut conn, &groups, dm_server_name, bootstrap.dm_mailbox_key)
        .await
        .map_err(internal_err)?;
    Ok(ProvisioningBundle {
        bootstrap,
        threads,
        events,
        groups,
        mailbox_state,
    })
}

pub async fn import_provisioning_bundle(
    conn: &mut sqlx::SqliteConnection,
    bundle: &ProvisioningBundle,
) -> anyhow::Result<()> {
    for thread in &bundle.threads {
        sqlx::query(
            "INSERT INTO event_threads (id, thread_kind, thread_counterparty, created_at) \
             VALUES (?, ?, ?, ?)",
        )
        .bind(thread.id)
        .bind(&thread.thread_kind)
        .bind(&thread.thread_counterparty)
        .bind(thread.created_at)
        .execute(&mut *conn)
        .await?;
    }

    for group in &bundle.groups {
        let mut members = BTreeMap::new();
        let mut banned = BTreeSet::new();
        for member in &group.members {
            if member.is_banned {
                banned.insert(member.username.clone());
            } else {
                members.insert(
                    member.username.clone(),
                    MemberState {
                        is_admin: member.is_admin,
                        is_muted: member.is_muted,
                    },
                );
            }
        }
        let roster = GroupRoster {
            members,
            banned,
            metadata: GroupMetadata {
                title: group.title.clone(),
                description: group.description.clone(),
            },
            settings: GroupRosterSettings {
                new_members_muted: group.new_members_muted,
                allow_new_members_to_see_history: group.allow_new_members_to_see_history,
            },
        };
        store_gbk(
            conn,
            group.group_id,
            &group.gbk,
            &group.server_name,
            group.rotation_index,
            &group.admin_set,
            &group.rotation_hash,
        )
        .await?;
        replace_current_roster(conn, group.group_id, group.rotation_index, &roster).await?;
        if sqlx::query_scalar::<_, i64>(
            "SELECT 1 FROM event_threads WHERE thread_kind = 'group' AND thread_counterparty = ? LIMIT 1",
        )
        .bind(group.group_id.to_string())
        .fetch_optional(&mut *conn)
        .await?
        .is_none()
        {
            let _ = ensure_thread_id(conn, "group", &group.group_id.to_string()).await?;
        }
    }

    for event in &bundle.events {
        sqlx::query(
            "INSERT INTO thread_events \
             (id, thread_id, sender_username, event_tag, event_body, event_after, event_hash, sent_at, received_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(event.id)
        .bind(event.thread_id)
        .bind(&event.sender_username)
        .bind(i64::from(event.event_tag))
        .bind(event.event_body.as_ref())
        .bind(event.event_after.map(|hash| hash.to_bytes().to_vec()))
        .bind(event.event_hash.to_bytes().to_vec())
        .bind(event.sent_at.0 as i64)
        .bind(event.received_at.0 as i64)
        .execute(&mut *conn)
        .await?;

        if let Some(read_at) = event.read_at {
            sqlx::query("INSERT INTO message_reads (message_id, read_at) VALUES (?, ?)")
                .bind(event.id)
                .bind(read_at.0 as i64)
                .execute(&mut *conn)
                .await?;
        }

        if event.event_tag == TAG_MESSAGE {
            let payload: MessagePayload = serde_json::from_slice(&event.event_body)?;
            for attachment in payload.attachments {
                let _ = store_attachment_root(conn, &attachment).await?;
            }
            for image in payload.images {
                let _ = store_attachment_root(conn, &image.inner).await?;
            }
        }
    }

    for mailbox in &bundle.mailbox_state {
        sqlx::query(
            "INSERT INTO mailbox_state (server_name, mailbox_id, after_timestamp) \
             VALUES (?, ?, ?) \
             ON CONFLICT(server_name, mailbox_id) DO UPDATE SET after_timestamp = excluded.after_timestamp",
        )
        .bind(mailbox.server_name.as_str())
        .bind(mailbox.mailbox_id.to_bytes().to_vec())
        .bind(mailbox.after_timestamp.0 as i64)
        .execute(&mut *conn)
        .await?;
    }

    Ok(())
}

async fn export_group_states(
    conn: &mut sqlx::SqliteConnection,
) -> anyhow::Result<Vec<ProvisioningGroupState>> {
    let rows = sqlx::query_as::<_, GroupKeyRow>(
        "SELECT group_id, gbk, server_name, admin_set, rotation_hash FROM group_keys",
    )
    .fetch_all(&mut *conn)
    .await?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let group_id = GroupId::from_bytes(
            row.group_id
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid group_id length"))?,
        );
        let (rotation_index, roster) = load_roster(conn, group_id).await?;
        let members = roster
            .members
            .into_iter()
            .map(|(username, state)| ProvisioningGroupMember {
                username,
                is_admin: state.is_admin,
                is_muted: state.is_muted,
                is_banned: false,
            })
            .chain(roster.banned.into_iter().map(|username| ProvisioningGroupMember {
                username,
                is_admin: false,
                is_muted: false,
                is_banned: true,
            }))
            .collect();
        out.push(ProvisioningGroupState {
            group_id,
            rotation_index,
            gbk: bcs::from_bytes(&row.gbk)?,
            server_name: ServerName::parse(row.server_name)?,
            admin_set: bcs::from_bytes(&row.admin_set)?,
            rotation_hash: Hash::from_bytes(
                row.rotation_hash
                    .as_slice()
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("invalid rotation hash length"))?,
            ),
            title: roster.metadata.title,
            description: roster.metadata.description,
            new_members_muted: roster.settings.new_members_muted,
            allow_new_members_to_see_history: roster.settings.allow_new_members_to_see_history,
            members,
        });
    }
    Ok(out)
}

async fn export_threads(
    conn: &mut sqlx::SqliteConnection,
    groups: &[ProvisioningGroupState],
) -> anyhow::Result<(Vec<ProvisioningThread>, Vec<ProvisioningEvent>)> {
    let required_group_threads = groups
        .iter()
        .map(|group| group.group_id.to_string())
        .collect::<BTreeSet<_>>();
    let thread_rows = sqlx::query_as::<_, ThreadRow>(
        "SELECT id, thread_kind, thread_counterparty, created_at FROM event_threads",
    )
    .fetch_all(&mut *conn)
    .await?;

    let mut threads = Vec::new();
    let mut events = Vec::new();
    for thread in thread_rows {
        let mut selected = Vec::new();
        let event_rows = sqlx::query_as::<_, EventRow>(
            "SELECT e.id, e.thread_id, e.sender_username, e.event_tag, e.event_body, e.event_after, \
                    e.event_hash, e.sent_at, e.received_at, mr.read_at \
             FROM thread_events e \
             LEFT JOIN message_reads mr ON mr.message_id = e.id \
             WHERE e.thread_id = ? AND e.received_at IS NOT NULL AND e.send_error IS NULL \
             ORDER BY e.id DESC",
        )
        .bind(thread.id)
        .fetch_all(&mut *conn)
        .await?;

        let mut message_count = 0usize;
        for row in event_rows {
            let is_message = row.event_tag == i64::from(TAG_MESSAGE);
            if is_message && message_count == MAX_TRANSFER_MESSAGES_PER_THREAD {
                break;
            }
            selected.push(row);
            if is_message {
                message_count += 1;
                if message_count == MAX_TRANSFER_MESSAGES_PER_THREAD {
                    break;
                }
            }
        }
        if selected.is_empty()
            && !(thread.thread_kind == "group"
                && required_group_threads.contains(&thread.thread_counterparty))
        {
            continue;
        }

        threads.push(ProvisioningThread {
            id: thread.id,
            thread_kind: thread.thread_kind.clone(),
            thread_counterparty: thread.thread_counterparty,
            created_at: thread.created_at,
        });

        selected.reverse();
        for row in selected {
            events.push(ProvisioningEvent {
                id: row.id,
                thread_id: row.thread_id,
                sender_username: row.sender_username,
                event_tag: u16::try_from(row.event_tag)
                    .map_err(|_| anyhow::anyhow!("invalid event_tag"))?,
                event_body: Bytes::from(row.event_body),
                event_after: row.event_after.map(decode_hash).transpose()?,
                event_hash: decode_hash(row.event_hash)?,
                sent_at: NanoTimestamp(row.sent_at as u64),
                received_at: NanoTimestamp(row.received_at as u64),
                read_at: row.read_at.map(|ts| NanoTimestamp(ts as u64)),
            });
        }
    }
    Ok((threads, events))
}

async fn export_mailbox_state(
    conn: &mut sqlx::SqliteConnection,
    groups: &[ProvisioningGroupState],
    dm_server_name: ServerName,
    dm_mailbox_key: MailboxKey,
) -> anyhow::Result<Vec<ProvisioningMailboxState>> {
    let mut keys = vec![(dm_server_name, dm_mailbox_key.mailbox_id())];
    keys.extend(
        groups
            .iter()
            .map(|group| (group.server_name.clone(), group.gbk.mailbox_key().mailbox_id())),
    );

    let mut out = Vec::new();
    for (server_name, mailbox_id) in keys {
        let after_timestamp = sqlx::query_scalar::<_, i64>(
            "SELECT after_timestamp FROM mailbox_state WHERE server_name = ? AND mailbox_id = ?",
        )
        .bind(server_name.as_str())
        .bind(mailbox_id.to_bytes().to_vec())
        .fetch_optional(&mut *conn)
        .await?;
        if let Some(after_timestamp) = after_timestamp {
            out.push(ProvisioningMailboxState {
                server_name,
                mailbox_id,
                after_timestamp: NanoTimestamp(after_timestamp as u64),
            });
        }
    }
    Ok(out)
}

fn decode_hash(bytes: Vec<u8>) -> anyhow::Result<Hash> {
    Ok(Hash::from_bytes(
        bytes.as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid hash length"))?,
    ))
}
