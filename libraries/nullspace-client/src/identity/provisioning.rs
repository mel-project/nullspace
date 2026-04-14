use std::sync::Arc;
use std::time::{Duration, Instant};

use anyctx::AnyCtx;
use bytes::Bytes;
use nullspace_crypt::aead::AeadKey;
use nullspace_crypt::dh::DhSecret;
use nullspace_crypt::signing::Signable;
use nullspace_crypt::spake::{SpakeKey, SpakeMessage, SpakeSession};
use nullspace_structs::Blob;
use nullspace_structs::certificate::DeviceSecret;
use nullspace_structs::directory::DirectoryUpdate;
use nullspace_structs::fragment::Attachment;
use nullspace_structs::mailbox::MailboxKey;
use nullspace_structs::profile::UserProfile;
use nullspace_structs::server::{
    AuthToken, ChanDirection, DeviceAuthRequest, ServerClient, ServerName, SignedDeviceAuthRequest,
    SignedMediumPk,
};
use nullspace_structs::timestamp::{NanoTimestamp, Timestamp};
use nullspace_structs::username::{UserDescriptor, UserName};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_with::base64::{Base64, UrlSafe};
use serde_with::formats::Unpadded;
use serde_with::{FromInto, IfIsHumanReadable, serde_as};
use tokio::sync::Mutex as AsyncMutex;

use super::Identity;
use super::provisioning_bundle::{
    ProvisioningBootstrap, ProvisioningBundle, build_provisioning_bundle,
    import_provisioning_bundle,
};
use crate::DIR_CLIENT;
use crate::attachments::{attachment_download_oneshot_with_progress, attachment_upload_path};
use crate::config::Config;
use crate::database::{DATABASE, DbNotify};
use crate::events::emit_event;
use crate::internal::{
    Event, InternalRpcError, ProvisionHostState, RegisterFinish, RegisterStartInfo, internal_err,
};
use crate::net::get_auth_token;
use crate::net::get_server_client;

const PROVISION_HOST_REPOST_INTERVAL: Duration = Duration::from_secs(5);
const PROVISION_GUEST_WAIT_TIMEOUT: Duration = Duration::from_secs(60);
const PROVISION_POLL_INTERVAL: Duration = Duration::from_millis(1500);

pub async fn register_start(
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
    tracing::debug!(username = %username, server = %descriptor.server_name, "register_start found");
    Ok(Some(RegisterStartInfo {
        username,
        server_name: descriptor.server_name,
    }))
}

pub async fn register_finish(
    ctx: AnyCtx<Config>,
    request: RegisterFinish,
) -> Result<(), InternalRpcError> {
    let db = ctx.get(DATABASE);
    let mut conn = db.acquire().await.map_err(internal_err)?;
    if super::identity_exists(&mut conn)
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

pub struct HostProvisioning {
    active: AsyncMutex<Option<ActiveProvisioning>>,
}

impl HostProvisioning {
    pub fn new() -> Self {
        Self {
            active: AsyncMutex::new(None),
        }
    }

    pub async fn start(&self, ctx: AnyCtx<Config>) -> Result<String, InternalRpcError> {
        let identity = load_identity(&ctx).await?;
        let server_name = resolve_user_server_name(&ctx, &identity.username).await?;
        let server = server_from_name(&ctx, &server_name).await?;
        let descriptor = load_user_descriptor(&ctx, &identity.username).await?;
        ensure_issuer_device(&identity, &descriptor)?;

        let auth = get_auth_token(&ctx).await.map_err(internal_err)?;
        let channel = server_channel_allocate(server.as_ref(), auth).await?;
        let token = rand::thread_rng().next_u32();
        let code = encode_pairing_code(channel, token)?;
        let display_code = format_pairing_code(code);
        let (spake_session, helo_msg) = SpakeSession::start(
            code.to_string().as_bytes(),
            identity.username.as_str().as_bytes(),
        );
        post_spake_message(
            server.as_ref(),
            channel,
            ChanDirection::Forward,
            ProvisionWireMessage::Helo {
                spake_msg: helo_msg,
            },
        )
        .await?;

        let mut active = self.active.lock().await;
        *active = Some(ActiveProvisioning {
            state: ProvisionHostState::Pending {
                display_code: display_code.clone(),
            },
            username: identity.username,
            server,
            channel,
            spake_session: Some(spake_session),
            helo_msg,
            started_at: Instant::now(),
            last_helo_posted_at: Instant::now(),
        });
        Ok(display_code)
    }

    pub async fn status(
        &self,
        ctx: &AnyCtx<Config>,
    ) -> Result<ProvisionHostState, InternalRpcError> {
        let mut active = self.active.lock().await;
        let Some(active) = active.as_mut() else {
            return Ok(ProvisionHostState::Idle);
        };

        if !matches!(active.state, ProvisionHostState::Pending { .. }) {
            return Ok(active.state.clone());
        }
        if active.started_at.elapsed() >= PROVISION_GUEST_WAIT_TIMEOUT {
            active.fail("pairing code expired");
            return Ok(active.state.clone());
        }
        if active.last_helo_posted_at.elapsed() >= PROVISION_HOST_REPOST_INTERVAL {
            if let Err(err) = post_spake_message(
                active.server.as_ref(),
                active.channel,
                ChanDirection::Forward,
                ProvisionWireMessage::Helo {
                    spake_msg: active.helo_msg,
                },
            )
            .await
            {
                active.fail(err.to_string());
                return Ok(active.state.clone());
            }
            active.last_helo_posted_at = Instant::now();
        }

        let Some(blob) = (match server_channel_recv(
            active.server.as_ref(),
            active.channel,
            ChanDirection::Backward,
        )
        .await
        {
            Ok(blob) => blob,
            Err(err) => {
                active.fail(err.to_string());
                return Ok(active.state.clone());
            }
        }) else {
            return Ok(active.state.clone());
        };
        let Ok(ProvisionWireMessage::Ehlo { spake_msg }) =
            serde_json::from_slice::<ProvisionWireMessage>(&blob.0)
        else {
            return Ok(active.state.clone());
        };

        let Some(spake_session) = active.spake_session.take() else {
            return Ok(active.state.clone());
        };
        let spake_key = match spake_session.finish(&spake_msg) {
            Ok(key) => key,
            Err(err) => {
                active.fail(format!("spake exchange failed: {err}"));
                return Ok(active.state.clone());
            }
        };
        let transfer = match build_provisioning_transfer(ctx, &active.username).await {
            Ok(transfer) => transfer,
            Err(err) => {
                active.fail(err.to_string());
                return Ok(active.state.clone());
            }
        };
        let envelope = match encrypt_finish_payload(&spake_key, &transfer) {
            Ok(envelope) => envelope,
            Err(err) => {
                active.fail(err.to_string());
                return Ok(active.state.clone());
            }
        };
        if let Err(err) = post_finish_envelope(
            active.server.as_ref(),
            active.channel,
            ChanDirection::Forward,
            &envelope,
        )
        .await
        {
            active.fail(err.to_string());
            return Ok(active.state.clone());
        }
        active.state = ProvisionHostState::Completed;
        Ok(active.state.clone())
    }

    pub async fn stop(&self) -> Result<(), InternalRpcError> {
        let mut active = self.active.lock().await;
        *active = None;
        Ok(())
    }
}

struct ActiveProvisioning {
    state: ProvisionHostState,
    username: UserName,
    server: Arc<ServerClient>,
    channel: u32,
    spake_session: Option<SpakeSession>,
    helo_msg: SpakeMessage,
    started_at: Instant,
    last_helo_posted_at: Instant,
}

impl ActiveProvisioning {
    fn fail(&mut self, message: impl Into<String>) {
        self.state = ProvisionHostState::Failed {
            error: message.into(),
        };
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
    let dm_mailbox_key = MailboxKey::random();
    let nonce_bind = next_nonce(0);
    dir.bind_server(&username, &server_name, nonce_bind, &device_secret)
        .await
        .map_err(internal_err)?;

    let auth = authenticate_device(&server, &username, &device_secret).await?;
    let medium_sk = register_medium_key(&server, auth, &device_secret).await?;
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

    persist_identity_and_emit(
        &ctx,
        username,
        server_name,
        device_secret,
        medium_sk,
        dm_mailbox_key,
    )
    .await
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

    let helo_msg = wait_for_spake_message(&server, channel, ChanDirection::Forward).await?;
    post_spake_message(
        &server,
        channel,
        ChanDirection::Backward,
        ProvisionWireMessage::Ehlo {
            spake_msg: ehlo_msg,
        },
    )
    .await?;

    let spake_key = spake_session
        .finish(&helo_msg)
        .map_err(|err| InternalRpcError::Other(format!("spake exchange failed: {err}")))?;
    let finish = wait_for_finish_envelope(&server, channel, ChanDirection::Forward).await?;
    let transfer = decrypt_finish_payload(&spake_key, &finish)?;
    let bundle = download_provisioning_bundle(&ctx, &transfer.bundle_attachment).await?;
    register_add_device_payload(ctx, username, bundle).await
}

async fn register_add_device_payload(
    ctx: AnyCtx<Config>,
    expected_username: UserName,
    bundle: ProvisioningBundle,
) -> Result<(), InternalRpcError> {
    let payload = &bundle.bootstrap;
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

    let descriptor = load_user_descriptor(&ctx, &expected_username).await?;
    if !descriptor.devices.contains(&new_device_pk) {
        return Err(InternalRpcError::Other(
            "add-device action committed but device is absent".into(),
        ));
    }
    let server_name = descriptor.server_name;
    let server = server_from_name(&ctx, &server_name).await?;
    let auth = authenticate_device(&server, &expected_username, &payload.device_secret).await?;
    let medium_sk = register_medium_key(&server, auth, &payload.device_secret).await?;
    server
        .mailbox_create(auth, payload.dm_mailbox_key)
        .await
        .map_err(internal_err)?
        .map_err(internal_err)?;
    persist_imported_identity_and_emit(
        &ctx,
        &bundle,
        expected_username,
        server_name,
        medium_sk,
    )
    .await
}

async fn load_identity(ctx: &AnyCtx<Config>) -> Result<Identity, InternalRpcError> {
    let db = ctx.get(DATABASE);
    Identity::load(&mut *db.acquire().await.map_err(internal_err)?)
        .await
        .map_err(internal_err)
}

async fn load_user_descriptor(
    ctx: &AnyCtx<Config>,
    username: &UserName,
) -> Result<UserDescriptor, InternalRpcError> {
    let dir = ctx.get(DIR_CLIENT);
    dir.get_user_descriptor(username)
        .await
        .map_err(internal_err)?
        .ok_or_else(|| InternalRpcError::Other("username not found in directory".into()))
}

async fn build_provisioning_bootstrap(
    ctx: &AnyCtx<Config>,
    username: &UserName,
) -> Result<ProvisioningBootstrap, InternalRpcError> {
    let identity = load_identity(ctx).await?;
    if identity.username != *username {
        return Err(InternalRpcError::Other(
            "identity username changed during provisioning".into(),
        ));
    }
    let descriptor = load_user_descriptor(ctx, &identity.username).await?;
    ensure_issuer_device(&identity, &descriptor)?;

    let device_secret = DeviceSecret::random();
    let dir = ctx.get(DIR_CLIENT);
    let state = dir
        .query_key_state(identity.username.as_str())
        .await
        .map_err(internal_err)?
        .ok_or_else(|| InternalRpcError::Other("username key state not found".into()))?;
    let nonce = next_nonce(state.nonce_max);
    let new_device_pk = device_secret.public().signing_public();
    let mut next_descriptor = descriptor;
    next_descriptor.devices.insert(new_device_pk);
    let mut add_device_update = DirectoryUpdate {
        key: identity.username.as_str().to_owned(),
        nonce,
        signer_pk: identity.device_secret.public().signing_public(),
        owners: next_descriptor.devices.clone(),
        value: bcs::to_bytes(&next_descriptor)
            .map(Bytes::from)
            .map_err(internal_err)?,
        signature: nullspace_crypt::signing::Signature::from_bytes([0u8; 64]),
    };
    add_device_update.sign(&identity.device_secret);
    Ok(ProvisioningBootstrap {
        device_secret,
        add_device_update,
        dm_mailbox_key: identity.dm_mailbox_key,
    })
}

async fn build_provisioning_transfer(
    ctx: &AnyCtx<Config>,
    username: &UserName,
) -> Result<ProvisioningTransfer, InternalRpcError> {
    let identity = load_identity(ctx).await?;
    let dm_server_name = identity
        .server_name
        .clone()
        .ok_or_else(|| InternalRpcError::Other("server name not available".into()))?;
    let bootstrap = build_provisioning_bootstrap(ctx, username).await?;
    let bundle = build_provisioning_bundle(ctx, bootstrap, dm_server_name).await?;
    let bundle_attachment = upload_provisioning_bundle(ctx, &bundle).await?;
    Ok(ProvisioningTransfer { bundle_attachment })
}

async fn upload_provisioning_bundle(
    ctx: &AnyCtx<Config>,
    bundle: &ProvisioningBundle,
) -> Result<Attachment, InternalRpcError> {
    let bundle_bytes = bcs::to_bytes(bundle).map_err(internal_err)?;
    let temp_dir = tempfile::tempdir().map_err(internal_err)?;
    let bundle_path = temp_dir.path().join("provisioning-bundle.bcs");
    tokio::fs::write(&bundle_path, &bundle_bytes)
        .await
        .map_err(internal_err)?;
    let progress_ctx = ctx.clone();
    let progress = std::sync::Arc::new(move |uploaded_size, total_size| {
        emit_event(
            &progress_ctx,
            Event::ProvisionBundleUploadProgress {
                uploaded_size,
                total_size,
            },
        );
    });
    let result = attachment_upload_path(
        ctx,
        bundle_path,
        "provisioning-bundle.bcs".into(),
        "application/x-nullspace-provisioning-bundle".into(),
        Some(progress),
    )
    .await;
    drop(temp_dir);
    match result {
        Ok(attachment) => {
            emit_event(ctx, Event::ProvisionBundleUploadDone);
            Ok(attachment)
        }
        Err(err) => {
            emit_event(
                ctx,
                Event::ProvisionBundleUploadFailed {
                    error: err.to_string(),
                },
            );
            Err(internal_err(err))
        }
    }
}

async fn download_provisioning_bundle(
    ctx: &AnyCtx<Config>,
    attachment: &Attachment,
) -> Result<ProvisioningBundle, InternalRpcError> {
    let temp_dir = tempfile::tempdir().map_err(internal_err)?;
    let bundle_path = temp_dir.path().join("provisioning-bundle.bcs");
    let progress_ctx = ctx.clone();
    let progress = std::sync::Arc::new(move |downloaded_size, total_size| {
        emit_event(
            &progress_ctx,
            Event::ProvisionBundleDownloadProgress {
                downloaded_size,
                total_size,
            },
        );
    });
    let result = attachment_download_oneshot_with_progress(
        ctx,
        attachment.clone(),
        bundle_path.clone(),
        Some(progress),
    )
    .await;
    if let Err(err) = result {
        emit_event(
            ctx,
            Event::ProvisionBundleDownloadFailed {
                error: err.to_string(),
            },
        );
        return Err(internal_err(err));
    }
    let bundle_bytes = tokio::fs::read(&bundle_path).await.map_err(internal_err)?;
    drop(temp_dir);
    emit_event(ctx, Event::ProvisionBundleDownloadDone);
    bcs::from_bytes(&bundle_bytes).map_err(internal_err)
}

async fn persist_identity_and_emit(
    ctx: &AnyCtx<Config>,
    username: UserName,
    server_name: ServerName,
    device_secret: DeviceSecret,
    medium_sk: DhSecret,
    dm_mailbox_key: MailboxKey,
) -> Result<(), InternalRpcError> {
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
    emit_event(ctx, Event::State { logged_in: true });
    Ok(())
}

async fn persist_imported_identity_and_emit(
    ctx: &AnyCtx<Config>,
    bundle: &ProvisioningBundle,
    username: UserName,
    server_name: ServerName,
    medium_sk: DhSecret,
) -> Result<(), InternalRpcError> {
    let db = ctx.get(DATABASE);
    let mut tx = db.begin().await.map_err(internal_err)?;
    persist_identity(
        &mut tx,
        username,
        server_name,
        bundle.bootstrap.device_secret.clone(),
        medium_sk,
        bundle.bootstrap.dm_mailbox_key,
    )
    .await?;
    import_provisioning_bundle(&mut tx, bundle)
        .await
        .map_err(internal_err)?;
    tx.commit().await.map_err(internal_err)?;
    DbNotify::touch();
    emit_event(ctx, Event::State { logged_in: true });
    Ok(())
}

async fn server_from_name(
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

async fn register_medium_key(
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

async fn persist_identity(
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

async fn authenticate_device(
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

fn next_nonce(previous: u64) -> u64 {
    let now = NanoTimestamp::now().0;
    now.max(previous.saturating_add(1))
}

async fn resolve_user_server_name(
    ctx: &AnyCtx<Config>,
    username: &UserName,
) -> Result<ServerName, InternalRpcError> {
    Ok(load_user_descriptor(ctx, username).await?.server_name)
}

fn ensure_issuer_device(
    identity: &Identity,
    descriptor: &UserDescriptor,
) -> Result<(), InternalRpcError> {
    let self_pk = identity.device_secret.public().signing_public();
    if !descriptor.devices.contains(&self_pk) {
        return Err(InternalRpcError::AccessDenied);
    }
    Ok(())
}

fn format_pairing_code(code: u64) -> String {
    let digits = code.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 4);
    for (index, ch) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(4) {
            out.push(' ');
        }
        out.push(ch);
    }
    out
}

fn parse_pairing_code_input(code: &str) -> Result<u64, InternalRpcError> {
    let normalized: String = code
        .chars()
        .filter(|ch| !ch.is_ascii_whitespace() && *ch != '-')
        .collect();
    if normalized.is_empty() || !normalized.chars().all(|ch| ch.is_ascii_digit()) {
        return Err(InternalRpcError::Other(
            "invalid pairing code format".into(),
        ));
    }
    normalized
        .parse::<u64>()
        .map_err(|_| InternalRpcError::Other("pairing code is out of range".into()))
}

fn encode_pairing_code(channel: u32, token: u32) -> Result<u64, InternalRpcError> {
    let mut bits = Vec::new();
    bits.push(true);
    encode_elias_delta_bits(u64::from(channel) + 1, &mut bits);
    for index in (0..32).rev() {
        bits.push(((token >> index) & 1) == 1);
    }
    if bits.len() > 64 {
        return Err(InternalRpcError::Other(
            "pairing channel is too large to encode".into(),
        ));
    }
    let mut value = 0u64;
    for bit in bits {
        value = (value << 1) | u64::from(bit);
    }
    Ok(value)
}

fn decode_pairing_code(code: u64) -> Result<(u32, u32), InternalRpcError> {
    if code == 0 {
        return Err(InternalRpcError::Other("invalid pairing code".into()));
    }
    let bit_len = 64 - code.leading_zeros() as usize;
    let mut bits = Vec::with_capacity(bit_len);
    for shift in (0..bit_len).rev() {
        bits.push(((code >> shift) & 1) == 1);
    }
    if bits.first().copied() != Some(true) {
        return Err(InternalRpcError::Other(
            "invalid pairing code prefix".into(),
        ));
    }
    let mut cursor = 1;
    let delta = decode_elias_delta_bits(&bits, &mut cursor)?;
    if delta == 0 {
        return Err(InternalRpcError::Other(
            "invalid pairing code channel".into(),
        ));
    }
    let channel_u64 = delta - 1;
    let channel = u32::try_from(channel_u64)
        .map_err(|_| InternalRpcError::Other("pairing code channel out of range".into()))?;
    if bits.len() != cursor + 32 {
        return Err(InternalRpcError::Other(
            "invalid pairing code length".into(),
        ));
    }
    let mut token = 0u32;
    for bit in bits.iter().skip(cursor) {
        token = (token << 1) | u32::from(*bit);
    }
    Ok((channel, token))
}

fn encode_elias_delta_bits(value: u64, out: &mut Vec<bool>) {
    let value_bits = usize::BITS as usize - value.leading_zeros() as usize;
    let len_bits = usize::BITS as usize - value_bits.leading_zeros() as usize;
    out.extend(std::iter::repeat_n(false, len_bits.saturating_sub(1)));
    for shift in (0..len_bits).rev() {
        out.push(((value_bits >> shift) & 1) == 1);
    }
    for shift in (0..value_bits.saturating_sub(1)).rev() {
        out.push(((value >> shift) & 1) == 1);
    }
}

fn decode_elias_delta_bits(bits: &[bool], cursor: &mut usize) -> Result<u64, InternalRpcError> {
    let mut zeros = 0usize;
    while *cursor + zeros < bits.len() && !bits[*cursor + zeros] {
        zeros += 1;
    }
    if *cursor + zeros >= bits.len() {
        return Err(InternalRpcError::Other("invalid pairing code delta".into()));
    }
    *cursor += zeros;
    let len_bits = zeros + 1;
    if *cursor + len_bits > bits.len() {
        return Err(InternalRpcError::Other("invalid pairing code delta".into()));
    }
    let mut value_bits = 0usize;
    for bit in &bits[*cursor..*cursor + len_bits] {
        value_bits = (value_bits << 1) | usize::from(*bit);
    }
    *cursor += len_bits;
    if value_bits == 0 {
        return Err(InternalRpcError::Other("invalid pairing code delta".into()));
    }
    if *cursor + value_bits.saturating_sub(1) > bits.len() {
        return Err(InternalRpcError::Other("invalid pairing code delta".into()));
    }
    let mut value = 1u64;
    for bit in &bits[*cursor..*cursor + value_bits.saturating_sub(1)] {
        value = (value << 1) | u64::from(*bit);
    }
    *cursor += value_bits.saturating_sub(1);
    Ok(value)
}

#[derive(Serialize, Deserialize)]
struct ProvisioningTransfer {
    bundle_attachment: Attachment,
}

#[serde_as]
#[derive(Serialize, Deserialize, Clone)]
struct ProvisionFinishEnvelope {
    #[serde_as(as = "IfIsHumanReadable<Base64<UrlSafe, Unpadded>, FromInto<Vec<u8>>>")]
    nonce: Bytes,
    #[serde_as(as = "IfIsHumanReadable<Base64<UrlSafe, Unpadded>, FromInto<Vec<u8>>>")]
    ciphertext: Bytes,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum ProvisionWireMessage {
    Helo { spake_msg: SpakeMessage },
    Ehlo { spake_msg: SpakeMessage },
    Finish { envelope: ProvisionFinishEnvelope },
}

fn encrypt_finish_payload(
    spake_key: &SpakeKey,
    payload: &ProvisioningTransfer,
) -> Result<ProvisionFinishEnvelope, InternalRpcError> {
    let mut nonce = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut nonce);
    let key = AeadKey::from_bytes(spake_key.to_bytes());
    let plaintext = serde_json::to_vec(payload).map_err(internal_err)?;
    let ciphertext = key
        .encrypt(nonce, &plaintext, &[])
        .map_err(|err| InternalRpcError::Other(format!("provision encryption failed: {err}")))?;
    Ok(ProvisionFinishEnvelope {
        nonce: Bytes::from(nonce.to_vec()),
        ciphertext: Bytes::from(ciphertext),
    })
}

fn decrypt_finish_payload(
    spake_key: &SpakeKey,
    envelope: &ProvisionFinishEnvelope,
) -> Result<ProvisioningTransfer, InternalRpcError> {
    let nonce: [u8; 24] = envelope
        .nonce
        .as_ref()
        .try_into()
        .map_err(|_| InternalRpcError::Other("invalid provision nonce length".into()))?;
    let key = AeadKey::from_bytes(spake_key.to_bytes());
    let plaintext = key
        .decrypt(nonce, &envelope.ciphertext, &[])
        .map_err(|err| InternalRpcError::Other(format!("provision decryption failed: {err}")))?;
    serde_json::from_slice::<ProvisioningTransfer>(&plaintext).map_err(internal_err)
}

async fn post_spake_message(
    server: &ServerClient,
    channel: u32,
    direction: ChanDirection,
    message: ProvisionWireMessage,
) -> Result<(), InternalRpcError> {
    let body = serde_json::to_vec(&message).map_err(internal_err)?;
    server_channel_send(server, channel, direction, Blob(Bytes::from(body))).await
}

async fn post_finish_envelope(
    server: &ServerClient,
    channel: u32,
    direction: ChanDirection,
    envelope: &ProvisionFinishEnvelope,
) -> Result<(), InternalRpcError> {
    let body = serde_json::to_vec(&ProvisionWireMessage::Finish {
        envelope: envelope.clone(),
    })
    .map_err(internal_err)?;
    server_channel_send(server, channel, direction, Blob(Bytes::from(body))).await
}

async fn wait_for_spake_message(
    server: &ServerClient,
    channel: u32,
    direction: ChanDirection,
) -> Result<SpakeMessage, InternalRpcError> {
    let start = Instant::now();
    while start.elapsed() < PROVISION_GUEST_WAIT_TIMEOUT {
        if let Some(blob) = server_channel_recv(server, channel, direction).await?
            && let Ok(ProvisionWireMessage::Helo { spake_msg }) =
                serde_json::from_slice::<ProvisionWireMessage>(&blob.0)
        {
            return Ok(spake_msg);
        }
        tokio::time::sleep(PROVISION_POLL_INTERVAL).await;
    }
    Err(InternalRpcError::Other(
        "timed out waiting for provisioning handshake".into(),
    ))
}

async fn wait_for_finish_envelope(
    server: &ServerClient,
    channel: u32,
    direction: ChanDirection,
) -> Result<ProvisionFinishEnvelope, InternalRpcError> {
    let start = Instant::now();
    while start.elapsed() < PROVISION_GUEST_WAIT_TIMEOUT {
        if let Some(blob) = server_channel_recv(server, channel, direction).await?
            && let Ok(ProvisionWireMessage::Finish { envelope }) =
                serde_json::from_slice::<ProvisionWireMessage>(&blob.0)
        {
            return Ok(envelope);
        }
        tokio::time::sleep(PROVISION_POLL_INTERVAL).await;
    }
    Err(InternalRpcError::Other(
        "timed out waiting for provisioning finish".into(),
    ))
}

async fn server_channel_allocate(
    server: &ServerClient,
    auth: AuthToken,
) -> Result<u32, InternalRpcError> {
    server
        .chan_allocate(auth)
        .await
        .map_err(internal_err)?
        .map_err(internal_err)
}

async fn server_channel_send(
    server: &ServerClient,
    channel: u32,
    direction: ChanDirection,
    value: Blob,
) -> Result<(), InternalRpcError> {
    server
        .chan_send(channel, direction, value)
        .await
        .map_err(internal_err)?
        .map_err(internal_err)
}

async fn server_channel_recv(
    server: &ServerClient,
    channel: u32,
    direction: ChanDirection,
) -> Result<Option<Blob>, InternalRpcError> {
    server
        .chan_recv(channel, direction)
        .await
        .map_err(internal_err)?
        .map_err(internal_err)
}

#[cfg(test)]
mod tests {
    use super::{
        decode_pairing_code, encode_pairing_code, format_pairing_code, parse_pairing_code_input,
    };

    #[test]
    fn pairing_code_roundtrip() {
        let channels = [0u32, 1, 2, 9, 63, 255, 1_024, 65_535, 1_000_000];
        let tokens = [0u32, 1, 0x1234_5678, u32::MAX];
        for channel in channels {
            for token in tokens {
                let code = encode_pairing_code(channel, token).expect("encode code");
                let (decoded_channel, decoded_token) =
                    decode_pairing_code(code).expect("decode code");
                assert_eq!(decoded_channel, channel);
                assert_eq!(decoded_token, token);
            }
        }
    }

    #[test]
    fn pairing_code_parse_normalizes_spaces_and_dashes() {
        let code = 1234_5678_9012u64;
        let display = format_pairing_code(code);
        assert_eq!(
            parse_pairing_code_input(&display).expect("parse display"),
            code
        );
        assert_eq!(
            parse_pairing_code_input("1234-5678-9012").expect("parse dashed"),
            code
        );
    }

    #[test]
    fn pairing_code_rejects_bad_input() {
        assert!(parse_pairing_code_input("").is_err());
        assert!(parse_pairing_code_input("abc").is_err());
        assert!(parse_pairing_code_input("12 34 x").is_err());
    }
}
