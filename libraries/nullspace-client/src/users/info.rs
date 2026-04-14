use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use moka::future::Cache;
use nullspace_crypt::hash::{BcsHashExt, Hash};
use nullspace_crypt::signing::{Signable, SigningPublic};
use nullspace_structs::fragment::ImageAttachment;
use nullspace_structs::mailbox::MailboxId;
use nullspace_structs::server::{ServerClient, ServerName, SignedMediumPk};
use nullspace_structs::timestamp::NanoTimestamp;
use nullspace_structs::username::{UserDescriptor, UserName};
use tracing::warn;

use super::profile::get_profile;
use crate::DIR_CLIENT;
use crate::attachments::store_attachment_root;
use crate::config::{Config, Ctx};
use crate::convo::last_dm_received_at;
use crate::database::DATABASE;
use crate::identity::{Identity, identity_exists};
use crate::internal::{
    InternalRpcError, MessageDirection, UserDetails, UserLastMessageSummary, internal_err,
    map_anyhow_err,
};
use crate::net::get_server_client;

pub struct UserInfo {
    pub username: UserName,
    pub server: Arc<ServerClient>,
    pub server_name: ServerName,
    pub devices: BTreeSet<SigningPublic>,
    pub medium_pks: BTreeMap<Hash, SignedMediumPk>,
}

pub struct UserDetailsData {
    pub display_name: Option<String>,
    pub avatar: Option<ImageAttachment>,
    pub server_name: ServerName,
    pub last_dm_received_at: Option<NanoTimestamp>,
}

const CACHE_TTL: Duration = Duration::from_secs(60);

static DESCRIPTOR_CACHE: Ctx<Cache<UserName, UserDescriptor>> =
    |_| Cache::builder().time_to_live(CACHE_TTL).build();

static USER_INFO_CACHE: Ctx<Cache<UserName, Arc<UserInfo>>> =
    |_| Cache::builder().time_to_live(CACHE_TTL).build();

static USER_DM_MAILBOX_CACHE: Ctx<Cache<UserMailboxKey, MailboxId>> = |_| Cache::builder().build();

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct UserMailboxKey {
    username: UserName,
    server_name: ServerName,
}

pub async fn get_user_descriptor(
    ctx: &anyctx::AnyCtx<Config>,
    username: &UserName,
) -> anyhow::Result<UserDescriptor> {
    ctx.get(DESCRIPTOR_CACHE)
        .try_get_with(username.clone(), async {
            ctx.get(DIR_CLIENT)
                .get_user_descriptor(username)
                .await?
                .context("username not in directory")
        })
        .await
        .map_err(|err: Arc<anyhow::Error>| anyhow::anyhow!(err.to_string()))
}

pub async fn get_user_info(
    ctx: &anyctx::AnyCtx<Config>,
    username: &UserName,
) -> anyhow::Result<Arc<UserInfo>> {
    ctx.get(USER_INFO_CACHE)
        .try_get_with(username.clone(), async {
            let descriptor = get_user_descriptor(ctx, username).await?;
            let server_name = descriptor.server_name.clone();
            let server = get_server_client(ctx, &server_name).await?;
            let devices = descriptor.devices.clone();

            if devices.is_empty() {
                anyhow::bail!("no active devices for {username}");
            }

            let medium_pks = fetch_medium_pks(&server, username).await?;
            let medium_pks = validate_medium_pks(username, &devices, medium_pks);

            Ok(Arc::new(UserInfo {
                username: username.clone(),
                server,
                server_name,
                devices,
                medium_pks,
            }))
        })
        .await
        .map_err(|err: Arc<anyhow::Error>| anyhow::anyhow!(err.to_string()))
}

pub async fn get_user_dm_mailbox(
    ctx: &anyctx::AnyCtx<Config>,
    user: &UserInfo,
) -> anyhow::Result<MailboxId> {
    let cache_key = UserMailboxKey {
        username: user.username.clone(),
        server_name: user.server_name.clone(),
    };
    ctx.get(USER_DM_MAILBOX_CACHE)
        .try_get_with(cache_key, async {
            let profile = user
                .server
                .profile(user.username.clone())
                .await?
                .map_err(|err| anyhow::anyhow!(err.to_string()))?
                .context("target profile not found")?;

            if !user
                .devices
                .iter()
                .any(|device_pk| profile.verify(*device_pk).is_ok())
            {
                anyhow::bail!("target profile signature is invalid");
            }

            Ok(profile.dm_mailbox)
        })
        .await
        .map_err(|err: Arc<anyhow::Error>| anyhow::anyhow!(err.to_string()))
}

fn validate_medium_pks(
    username: &UserName,
    devices: &BTreeSet<SigningPublic>,
    medium_pks: BTreeMap<Hash, SignedMediumPk>,
) -> BTreeMap<Hash, SignedMediumPk> {
    let device_by_hash: BTreeMap<Hash, SigningPublic> = devices
        .iter()
        .copied()
        .map(|pk| (pk.bcs_hash(), pk))
        .collect();

    medium_pks
        .into_iter()
        .filter(|(device_hash, medium_pk)| {
            let Some(device_pk) = device_by_hash.get(device_hash) else {
                return false;
            };
            if medium_pk.verify(*device_pk).is_err() {
                warn!(username=%username, device_hash=%device_hash, "invalid medium-term key signature");
                return false;
            }
            true
        })
        .collect()
}

async fn fetch_medium_pks(
    server: &ServerClient,
    username: &UserName,
) -> anyhow::Result<BTreeMap<Hash, SignedMediumPk>> {
    server
        .device_medium_pks(username.clone())
        .await?
        .map_err(|err| anyhow::anyhow!(err.to_string()))
}

pub async fn user_details_data(
    ctx: &anyctx::AnyCtx<Config>,
    local_username: &UserName,
    username: &UserName,
) -> anyhow::Result<UserDetailsData> {
    let profile = get_profile(ctx, username).await?;
    let db = ctx.get(DATABASE);
    if let Some(profile) = profile.as_ref()
        && let Some(avatar) = profile.avatar.as_ref()
    {
        let mut conn = db.acquire().await?;
        store_attachment_root(&mut conn, &avatar.inner).await?;
    }
    let user_info = get_user_info(ctx, username).await?;
    let (display_name, avatar) = match profile {
        Some(profile) => (profile.display_name, profile.avatar),
        None => (None, None),
    };
    let mut conn = db.acquire().await?;
    let last_dm_received_at = last_dm_received_at(&mut conn, local_username, username).await?;
    Ok(UserDetailsData {
        display_name,
        avatar,
        server_name: user_info.server_name.clone(),
        last_dm_received_at,
    })
}

// --- RPC impl delegate ---

pub async fn user_details_impl(
    ctx: &anyctx::AnyCtx<Config>,
    username: UserName,
) -> Result<UserDetails, InternalRpcError> {
    let db = ctx.get(DATABASE);
    if !identity_exists(&mut *db.acquire().await.map_err(internal_err)?)
        .await
        .map_err(internal_err)?
    {
        return Err(InternalRpcError::NotReady);
    }
    let identity = Identity::load(&mut *db.acquire().await.map_err(internal_err)?)
        .await
        .map_err(internal_err)?;
    let details = user_details_data(ctx, &identity.username, &username)
        .await
        .map_err(map_anyhow_err)?;

    Ok(UserDetails {
        username: username.clone(),
        display_name: details.display_name,
        avatar: details.avatar,
        server_name: Some(details.server_name),
        common_groups: sqlx::query_scalar::<_, Vec<u8>>(
            "SELECT DISTINCT self.group_id \
             FROM group_members_current self \
             JOIN group_members_current other ON other.group_id = self.group_id \
             WHERE self.username = ? AND other.username = ? \
               AND self.is_banned = 0 AND other.is_banned = 0",
        )
        .bind(identity.username.as_str())
        .bind(username.as_str())
        .fetch_all(&mut *db.acquire().await.map_err(internal_err)?)
        .await
        .map_err(internal_err)?
        .into_iter()
        .map(|bytes| {
            let arr: [u8; 16] = bytes
                .try_into()
                .map_err(|_| internal_err("invalid group_id"))?;
            Ok(nullspace_structs::group::GroupId::from_bytes(arr))
        })
        .collect::<Result<Vec<_>, _>>()?,
        last_dm_message: details
            .last_dm_received_at
            .map(|received_at| UserLastMessageSummary {
                received_at: Some(received_at),
                direction: MessageDirection::Incoming,
                preview: String::new(),
            }),
    })
}
