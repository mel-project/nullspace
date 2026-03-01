mod guest;
mod host;
mod pairing_code;
mod wire;

use std::sync::Arc;
use std::time::Duration;

use anyctx::AnyCtx;
use nullspace_crypt::dh::DhSecret;
use nullspace_crypt::signing::Signable;
use nullspace_structs::certificate::DeviceSecret;
use nullspace_structs::mailbox::MailboxKey;
use nullspace_structs::server::{
    AuthToken, DeviceAuthRequest, ServerClient, ServerName, SignedDeviceAuthRequest,
    SignedMediumPk,
};
use nullspace_structs::timestamp::{NanoTimestamp, Timestamp};
use nullspace_structs::username::{UserDescriptor, UserName};

use crate::config::Config;
use crate::identity::Identity;
use crate::internal::{InternalRpcError, internal_err};
use crate::server::get_server_client;
use crate::DIR_CLIENT;

pub(crate) use guest::{register_finish, register_start};
pub(crate) use host::HostProvisioning;

const PROVISION_HOST_POLL_INTERVAL: Duration = Duration::from_millis(1500);
const PROVISION_HOST_REPOST_INTERVAL: Duration = Duration::from_secs(5);
const PROVISION_GUEST_WAIT_TIMEOUT: Duration = Duration::from_secs(60);

pub(crate) async fn server_from_name(
    ctx: &AnyCtx<Config>,
    server_name: &ServerName,
) -> Result<Arc<ServerClient>, InternalRpcError> {
    let dir = ctx.get(DIR_CLIENT);
    let descriptor = dir
        .get_server_descriptor(server_name)
        .await
        .map_err(internal_err)?
        .ok_or_else(|| InternalRpcError::Other("server not found".into()))?;
    let _ = descriptor;
    get_server_client(ctx, server_name)
        .await
        .map_err(internal_err)
}

pub(crate) async fn register_medium_key(
    server: &ServerClient,
    auth: AuthToken,
    device_secret: &DeviceSecret,
) -> Result<DhSecret, InternalRpcError> {
    let medium_sk = DhSecret::random();
    let mut signed = SignedMediumPk {
        medium_pk: medium_sk.public_key(),
        created: Timestamp::now(),
        signature: nullspace_crypt::signing::Signature::from_bytes([0u8; 64]),
    };
    signed.sign(device_secret);
    server
        .device_add_medium_pk(auth, signed)
        .await
        .map_err(internal_err)?
        .map_err(internal_err)?;
    Ok(medium_sk)
}

pub(crate) async fn persist_identity(
    db: &mut sqlx::SqliteConnection,
    username: UserName,
    server_name: ServerName,
    device_secret: DeviceSecret,
    medium_sk: DhSecret,
    dm_mailbox_key: MailboxKey,
) -> Result<(), InternalRpcError> {
    sqlx::query(
        "INSERT INTO client_identity \
         (id, username, server_name, device_secret, medium_sk_current, medium_sk_prev, dm_mailbox_key) \
         VALUES (1, ?, ?, ?, ?, ?, ?)",
    )
    .bind(username.as_str())
    .bind(server_name.as_str())
    .bind(bcs::to_bytes(&device_secret).map_err(internal_err)?)
    .bind(bcs::to_bytes(&medium_sk).map_err(internal_err)?)
    .bind(bcs::to_bytes(&medium_sk).map_err(internal_err)?)
    .bind(bcs::to_bytes(&dm_mailbox_key).map_err(internal_err)?)
    .execute(&mut *db)
    .await
    .map_err(internal_err)?;
    Ok(())
}

pub(crate) async fn authenticate_device(
    server: &ServerClient,
    username: &UserName,
    device_secret: &DeviceSecret,
) -> Result<AuthToken, InternalRpcError> {
    let device_pk = device_secret.public().signing_public();
    let challenge = server
        .device_auth_start(username.clone(), device_pk)
        .await
        .map_err(internal_err)?
        .map_err(internal_err)?;
    let mut request = SignedDeviceAuthRequest {
        request: DeviceAuthRequest {
            username: username.clone(),
            device_pk,
            challenge: challenge.challenge,
        },
        signature: nullspace_crypt::signing::Signature::from_bytes([0u8; 64]),
    };
    request.sign(device_secret);
    server
        .device_auth_finish(request)
        .await
        .map_err(internal_err)?
        .map_err(internal_err)
}

pub(crate) fn next_nonce(previous: u64) -> u64 {
    let now = NanoTimestamp::now().0;
    now.max(previous.saturating_add(1))
}

pub(crate) async fn resolve_user_server_name(
    ctx: &AnyCtx<Config>,
    username: &UserName,
) -> Result<ServerName, InternalRpcError> {
    let dir = ctx.get(DIR_CLIENT);
    let descriptor = dir
        .get_user_descriptor(username)
        .await
        .map_err(internal_err)?
        .ok_or_else(|| InternalRpcError::Other("username not found in directory".into()))?;
    Ok(descriptor.server_name)
}

pub(crate) fn ensure_issuer_device(
    identity: &Identity,
    state: &UserDescriptor,
) -> Result<(), InternalRpcError> {
    let self_pk = identity.device_secret.public().signing_public();
    if !state.devices.contains(&self_pk) {
        return Err(InternalRpcError::AccessDenied);
    }
    Ok(())
}
