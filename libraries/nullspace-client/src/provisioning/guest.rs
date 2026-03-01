use anyctx::AnyCtx;
use nullspace_crypt::signing::Signable;
use nullspace_crypt::spake::SpakeSession;
use nullspace_structs::certificate::DeviceSecret;
use nullspace_structs::mailbox::MailboxKey;
use nullspace_structs::profile::UserProfile;
use nullspace_structs::server::{ChanDirection, ServerName};
use nullspace_structs::timestamp::Timestamp;
use nullspace_structs::username::{UserDescriptor, UserName};

use crate::config::Config;
use crate::database::{DATABASE, DbNotify};
use crate::events::emit_event;
use crate::internal::{Event, InternalRpcError, RegisterFinish, RegisterStartInfo, internal_err};
use crate::DIR_CLIENT;

use super::pairing_code::{decode_pairing_code, parse_pairing_code_input};
use super::wire::{
    ProvisionSpakePhase, decrypt_finish_payload, post_spake_message, wait_for_finish_envelope,
    wait_for_spake_message,
};
use super::{
    PROVISION_GUEST_WAIT_TIMEOUT, authenticate_device, next_nonce, persist_identity,
    register_medium_key, resolve_user_server_name, server_from_name,
};

pub(crate) async fn register_start(
    ctx: &AnyCtx<Config>,
    username: UserName,
) -> Result<Option<RegisterStartInfo>, InternalRpcError> {
    tracing::debug!(username = %username, "register_start begin");
    let dir = ctx.get(DIR_CLIENT);
    let descriptor = dir
        .get_user_descriptor(&username)
        .await
        .map_err(internal_err)?;
    let Some(descriptor) = descriptor else {
        tracing::debug!(username = %username, "register_start not found");
        return Ok(None);
    };
    let server_name = descriptor.server_name.clone();
    tracing::debug!(username = %username, server = %server_name, "register_start found");
    Ok(Some(RegisterStartInfo {
        username,
        server_name,
    }))
}

pub(crate) async fn register_finish(
    ctx: AnyCtx<Config>,
    request: RegisterFinish,
) -> Result<(), InternalRpcError> {
    let db = ctx.get(DATABASE);
    let mut conn = db.acquire().await.map_err(internal_err)?;
    if crate::identity::identity_exists(&mut conn)
        .await
        .map_err(internal_err)?
    {
        return Err(InternalRpcError::NotReady);
    }
    match request {
        RegisterFinish::BootstrapNewUser {
            username,
            server_name,
        } => register_bootstrap(ctx, username, server_name).await,
        RegisterFinish::AddDeviceByCode { username, code } => {
            register_add_device_by_code(ctx, username, code).await
        }
    }
}

async fn register_bootstrap(
    ctx: AnyCtx<Config>,
    username: UserName,
    server_name: ServerName,
) -> Result<(), InternalRpcError> {
    let dir = ctx.get(DIR_CLIENT);
    if dir
        .get_user_descriptor(&username)
        .await
        .map_err(internal_err)?
        .is_some()
    {
        return Err(InternalRpcError::Other("username already exists".into()));
    }
    let server = server_from_name(&ctx, &server_name).await?;
    let device_secret = DeviceSecret::random();
    let nonce_bind = next_nonce(0);
    dir.bind_server(&username, &server_name, nonce_bind, &device_secret)
        .await
        .map_err(internal_err)?;
    let auth = authenticate_device(&server, &username, &device_secret).await?;
    let medium_sk = register_medium_key(&server, auth, &device_secret).await?;
    let dm_mailbox_key = MailboxKey::random();
    let dm_mailbox = server
        .mailbox_create(auth, dm_mailbox_key)
        .await
        .map_err(internal_err)?
        .map_err(internal_err)?;

    let created = Timestamp::now();
    let mut profile = UserProfile {
        display_name: None,
        avatar: None,
        dm_mailbox,
        created,
        signature: nullspace_crypt::signing::Signature::from_bytes([0u8; 64]),
    };
    profile.sign(&device_secret);
    server
        .profile_set(username.clone(), profile)
        .await
        .map_err(internal_err)?
        .map_err(internal_err)?;

    let db = ctx.get(DATABASE);
    persist_identity(
        &mut *db.acquire().await.map_err(internal_err)?,
        username,
        server_name,
        device_secret,
        medium_sk,
        dm_mailbox_key,
    )
    .await?;
    DbNotify::touch();
    emit_event(&ctx, Event::State { logged_in: true });
    Ok(())
}

async fn register_add_device_by_code(
    ctx: AnyCtx<Config>,
    username: UserName,
    code: String,
) -> Result<(), InternalRpcError> {
    let normalized_code = parse_pairing_code_input(&code)?;
    let (channel, _token) = decode_pairing_code(normalized_code)?;
    let server_name = resolve_user_server_name(&ctx, &username).await?;
    let server = server_from_name(&ctx, &server_name).await?;
    let (spake_session, ehlo_msg) = SpakeSession::start(
        normalized_code.to_string().as_bytes(),
        username.as_str().as_bytes(),
    );

    let helo_msg = wait_for_spake_message(
        &server,
        channel,
        ChanDirection::Forward,
        ProvisionSpakePhase::Helo,
        PROVISION_GUEST_WAIT_TIMEOUT,
    )
    .await?;
    post_spake_message(
        &server,
        channel,
        ChanDirection::Backward,
        ProvisionSpakePhase::Ehlo,
        &ehlo_msg,
    )
    .await?;

    let spake_key = spake_session
        .finish(&helo_msg)
        .map_err(|err| InternalRpcError::Other(format!("spake exchange failed: {err}")))?;
    let finish = wait_for_finish_envelope(
        &server,
        channel,
        ChanDirection::Forward,
        PROVISION_GUEST_WAIT_TIMEOUT,
    )
    .await?;
    let payload = decrypt_finish_payload(&spake_key, &finish)?;
    register_add_device_payload(ctx, username, payload).await
}

async fn register_add_device_payload(
    ctx: AnyCtx<Config>,
    expected_username: UserName,
    payload: super::wire::ProvisioningPayload,
) -> Result<(), InternalRpcError> {
    if payload.add_device_update.key != expected_username.as_str() {
        return Err(InternalRpcError::Other(
            "provision payload username mismatch".into(),
        ));
    }
    let dir = ctx.get(DIR_CLIENT);
    let new_device_pk = payload.device_secret.public().signing_public();
    if payload.add_device_update.signer_pk == new_device_pk {
        return Err(InternalRpcError::Other(
            "provision signer must be an existing different device".into(),
        ));
    }
    payload
        .add_device_update
        .verify(payload.add_device_update.signer_pk)
        .map_err(|err| InternalRpcError::Other(format!("invalid signed update: {err}")))?;
    let next_descriptor: UserDescriptor =
        bcs::from_bytes(&payload.add_device_update.value).map_err(internal_err)?;
    if !next_descriptor.devices.contains(&new_device_pk) {
        return Err(InternalRpcError::Other(
            "provision payload does not add the expected device".into(),
        ));
    }
    if payload.add_device_update.owners != next_descriptor.devices {
        return Err(InternalRpcError::Other(
            "provision update owners do not match descriptor devices".into(),
        ));
    }
    dir.insert_raw(payload.add_device_update.clone())
        .await
        .map_err(internal_err)?;
    dir.wait_for_user_nonce(&expected_username, payload.add_device_update.nonce)
        .await
        .map_err(internal_err)?;

    let descriptor = dir
        .get_user_descriptor(&expected_username)
        .await
        .map_err(internal_err)?
        .ok_or_else(|| InternalRpcError::Other("username not found in directory".into()))?;
    if !descriptor.devices.contains(&new_device_pk) {
        return Err(InternalRpcError::Other(
            "add-device action committed but device is absent".into(),
        ));
    }
    let server_name = descriptor.server_name.clone();
    let server = server_from_name(&ctx, &server_name).await?;
    let auth = authenticate_device(&server, &expected_username, &payload.device_secret).await?;
    let medium_sk = register_medium_key(&server, auth, &payload.device_secret).await?;
    server
        .mailbox_create(auth, payload.dm_mailbox_key)
        .await
        .map_err(internal_err)?
        .map_err(internal_err)?;
    let db = ctx.get(DATABASE);
    persist_identity(
        &mut *db.acquire().await.map_err(internal_err)?,
        expected_username,
        server_name,
        payload.device_secret,
        medium_sk,
        payload.dm_mailbox_key,
    )
    .await?;
    DbNotify::touch();
    emit_event(&ctx, Event::State { logged_in: true });
    Ok(())
}
