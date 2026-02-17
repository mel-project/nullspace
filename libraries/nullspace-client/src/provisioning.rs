use anyctx::AnyCtx;
use bytes::Bytes;
use nullspace_crypt::aead::AeadKey;
use nullspace_crypt::hash::BcsHashExt;
use nullspace_crypt::spake::{SpakeKey, SpakeMessage, SpakeSession};
use nullspace_structs::Blob;
use nullspace_structs::certificate::DeviceSecret;
use nullspace_structs::server::{AuthToken, ServerClient, ServerName};
use nullspace_structs::timestamp::{NanoTimestamp, Timestamp};
use nullspace_structs::username::{PreparedUserAction, UserAction, UserDescriptor, UserName};
use parking_lot::Mutex as ParkingMutex;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_with::base64::{Base64, UrlSafe};
use serde_with::formats::Unpadded;
use serde_with::{FromInto, IfIsHumanReadable, serde_as};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex as AsyncMutex;

use crate::auth_tokens::get_auth_token;
use crate::config::Config;
use crate::database::{DATABASE, DbNotify};
use crate::directory::DIR_CLIENT;
use crate::identity::Identity;
use crate::internal::{
    InternalRpcError, ProvisionHostPhase, ProvisionHostStart, ProvisionHostStatus,
    authenticate_device, internal_err, persist_identity, register_medium_key, server_from_name,
};

const PROVISION_HOST_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(15);
const PROVISION_HOST_POLL_INTERVAL: Duration = Duration::from_millis(250);
const PROVISION_HOST_REPOST_INTERVAL: Duration = Duration::from_secs(5);
const PROVISION_GUEST_WAIT_TIMEOUT: Duration = Duration::from_secs(60);

pub(crate) struct HostProvisioning {
    sessions: AsyncMutex<BTreeMap<u64, Arc<ProvisionHostSession>>>,
    next_session_id: AtomicU64,
}

impl HostProvisioning {
    pub(crate) fn new() -> Self {
        Self {
            sessions: AsyncMutex::new(BTreeMap::new()),
            next_session_id: AtomicU64::new(1),
        }
    }

    pub(crate) async fn start(
        &self,
        ctx: AnyCtx<Config>,
        can_issue: bool,
        expiry: Timestamp,
    ) -> Result<ProvisionHostStart, InternalRpcError> {
        let db = ctx.get(DATABASE);
        let identity = Identity::load(db).await.map_err(internal_err)?;
        let server_name = resolve_user_server_name(&ctx, &identity.username).await?;
        let server = server_from_name(&ctx, &server_name).await?;
        let dir = ctx.get(DIR_CLIENT);
        let descriptor = dir
            .get_user_descriptor(&identity.username)
            .await
            .map_err(internal_err)?
            .ok_or_else(|| InternalRpcError::Other("username not found in directory".into()))?;
        ensure_issuer_device(&identity, &descriptor)?;

        let session_id = self.next_session_id.fetch_add(1, Ordering::Relaxed);
        let session = Arc::new(ProvisionHostSession::new());
        let (attempt, display_code) = begin_host_attempt(&ctx, server.as_ref(), &session).await?;
        {
            let mut sessions = self.sessions.lock().await;
            sessions.insert(session_id, session.clone());
        }

        let username = identity.username.clone();
        tokio::spawn(async move {
            run_host_session(
                ctx,
                session,
                username,
                server,
                can_issue,
                expiry,
                attempt,
            )
            .await;
        });

        Ok(ProvisionHostStart {
            session_id,
            display_code,
        })
    }

    pub(crate) async fn status(
        &self,
        session_id: u64,
    ) -> Result<ProvisionHostStatus, InternalRpcError> {
        let session = {
            let sessions = self.sessions.lock().await;
            sessions.get(&session_id).cloned()
        };
        let Some(session) = session else {
            return Err(InternalRpcError::Other(
                "provisioning session not found".into(),
            ));
        };
        Ok(session.snapshot())
    }

    pub(crate) async fn stop(&self, session_id: u64) -> Result<(), InternalRpcError> {
        let session = {
            let mut sessions = self.sessions.lock().await;
            sessions.remove(&session_id)
        };
        if let Some(session) = session {
            session.cancel();
        }
        Ok(())
    }
}

pub(crate) async fn register_add_device_by_code(
    ctx: AnyCtx<Config>,
    username: UserName,
    code: String,
) -> Result<(), InternalRpcError> {
    let normalized_code = parse_pairing_code_input(&code)?;
    let (channel, _token) = decode_pairing_code(normalized_code)?;
    let server_name = resolve_user_server_name(&ctx, &username).await?;
    let server = server_from_name(&ctx, &server_name).await?;
    let (spake_session, ehlo_msg) =
        SpakeSession::start(normalized_code.to_string().as_bytes(), username.as_str().as_bytes());

    let helo_msg = wait_for_spake_message(
        &server,
        channel,
        Blob::V1_PROVISION_HELO,
        PROVISION_GUEST_WAIT_TIMEOUT,
    )
    .await?;
    post_spake_message(&server, channel, Blob::V1_PROVISION_EHLO, &ehlo_msg).await?;

    let spake_key = spake_session
        .finish(&helo_msg)
        .map_err(|err| InternalRpcError::Other(format!("spake exchange failed: {err}")))?;
    let finish = wait_for_finish_envelope(&server, channel, PROVISION_GUEST_WAIT_TIMEOUT).await?;
    let payload = decrypt_finish_payload(&spake_key, &finish)?;
    register_add_device_payload(ctx, username, payload).await
}

pub(crate) fn next_nonce(previous: u64) -> u64 {
    let now = NanoTimestamp::now().0;
    now.max(previous.saturating_add(1))
}

struct ProvisionHostSession {
    status: ParkingMutex<ProvisionHostStatus>,
    cancelled: AtomicBool,
}

impl ProvisionHostSession {
    fn new() -> Self {
        Self {
            status: ParkingMutex::new(ProvisionHostStatus {
                phase: ProvisionHostPhase::Pending,
                display_code: String::new(),
                error: None,
            }),
            cancelled: AtomicBool::new(false),
        }
    }

    fn snapshot(&self) -> ProvisionHostStatus {
        self.status.lock().clone()
    }

    fn set_pending_code(&self, display_code: String) {
        let mut status = self.status.lock();
        status.phase = ProvisionHostPhase::Pending;
        status.display_code = display_code;
        status.error = None;
    }

    fn set_completed(&self) {
        let mut status = self.status.lock();
        status.phase = ProvisionHostPhase::Completed;
        status.error = None;
    }

    fn set_failed(&self, message: impl Into<String>) {
        let mut status = self.status.lock();
        status.phase = ProvisionHostPhase::Failed;
        status.error = Some(message.into());
    }

    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Relaxed)
    }

    fn cancel(&self) {
        self.cancelled.store(true, Ordering::Relaxed);
    }
}

#[derive(Clone, Copy)]
struct HostAttempt {
    channel: u32,
    code: u64,
}

async fn run_host_session(
    ctx: AnyCtx<Config>,
    session: Arc<ProvisionHostSession>,
    username: UserName,
    server: Arc<ServerClient>,
    can_issue: bool,
    expiry: Timestamp,
    mut attempt: HostAttempt,
) {
    loop {
        if session.is_cancelled() {
            return;
        }
        match run_host_attempt(
            &ctx,
            &session,
            &username,
            server.as_ref(),
            can_issue,
            expiry,
            attempt,
        )
        .await
        {
            Ok(true) => {
                session.set_completed();
                return;
            }
            Ok(false) => {}
            Err(err) => {
                session.set_failed(err.to_string());
                return;
            }
        }
        if session.is_cancelled() {
            return;
        }
        match begin_host_attempt(&ctx, server.as_ref(), &session).await {
            Ok((next, _display_code)) => {
                attempt = next;
            }
            Err(err) => {
                session.set_failed(err.to_string());
                return;
            }
        }
    }
}

async fn run_host_attempt(
    ctx: &AnyCtx<Config>,
    session: &Arc<ProvisionHostSession>,
    username: &UserName,
    server: &ServerClient,
    can_issue: bool,
    expiry: Timestamp,
    attempt: HostAttempt,
) -> Result<bool, InternalRpcError> {
    let (spake_session, helo_msg) =
        SpakeSession::start(attempt.code.to_string().as_bytes(), username.as_str().as_bytes());
    if post_spake_message(server, attempt.channel, Blob::V1_PROVISION_HELO, &helo_msg)
        .await
        .is_err()
    {
        return Ok(false);
    }
    let started = Instant::now();
    let mut last_helo = started;

    while started.elapsed() < PROVISION_HOST_ATTEMPT_TIMEOUT {
        if session.is_cancelled() {
            return Ok(false);
        }
        if last_helo.elapsed() >= PROVISION_HOST_REPOST_INTERVAL {
            if post_spake_message(server, attempt.channel, Blob::V1_PROVISION_HELO, &helo_msg)
                .await
                .is_err()
            {
                return Ok(false);
            }
            last_helo = Instant::now();
        }
        let Some(blob) = server_multicast_poll(server, attempt.channel).await.ok().flatten() else {
            tokio::time::sleep(PROVISION_HOST_POLL_INTERVAL).await;
            continue;
        };
        if blob.kind != Blob::V1_PROVISION_EHLO {
            tokio::time::sleep(PROVISION_HOST_POLL_INTERVAL).await;
            continue;
        }
        let Ok(peer_msg) = serde_json::from_slice::<ProvisionSpakeMessage>(&blob.inner) else {
            tokio::time::sleep(PROVISION_HOST_POLL_INTERVAL).await;
            continue;
        };
        let Ok(spake_key) = spake_session.finish(&peer_msg.spake_msg) else {
            return Ok(false);
        };
        let payload = build_provisioning_payload(ctx, username, can_issue, expiry).await?;
        let envelope = encrypt_finish_payload(&spake_key, &payload)?;
        if post_finish_envelope(server, attempt.channel, &envelope)
            .await
            .is_err()
        {
            return Ok(false);
        }
        return Ok(true);
    }
    Ok(false)
}

async fn begin_host_attempt(
    ctx: &AnyCtx<Config>,
    server: &ServerClient,
    session: &ProvisionHostSession,
) -> Result<(HostAttempt, String), InternalRpcError> {
    let auth = get_auth_token(ctx).await.map_err(internal_err)?;
    let channel = server_multicast_allocate(server, auth).await?;
    let token = rand::thread_rng().next_u32();
    let code = encode_pairing_code(channel, token)?;
    let display_code = format_pairing_code(code);
    session.set_pending_code(display_code.clone());
    Ok((HostAttempt { channel, code }, display_code))
}

async fn build_provisioning_payload(
    ctx: &AnyCtx<Config>,
    username: &UserName,
    can_issue: bool,
    expiry: Timestamp,
) -> Result<ProvisioningPayload, InternalRpcError> {
    let db = ctx.get(DATABASE);
    let identity = Identity::load(db).await.map_err(internal_err)?;
    if identity.username != *username {
        return Err(InternalRpcError::Other(
            "identity username changed during provisioning".into(),
        ));
    }
    let dir = ctx.get(DIR_CLIENT);
    let descriptor = dir
        .get_user_descriptor(&identity.username)
        .await
        .map_err(internal_err)?
        .ok_or_else(|| InternalRpcError::Other("username not found in directory".into()))?;
    ensure_issuer_device(&identity, &descriptor)?;
    let device_secret = DeviceSecret::random();
    let nonce = next_nonce(descriptor.nonce_max);
    let add_device_action = dir
        .prepare_user_action(
            &identity.username,
            UserAction::AddDevice {
                device_pk: device_secret.public().signing_public(),
                can_issue,
                expiry,
            },
            nonce,
            &identity.device_secret,
        )
        .await
        .map_err(internal_err)?;
    Ok(ProvisioningPayload {
        device_secret,
        add_device_action,
    })
}

async fn register_add_device_payload(
    ctx: AnyCtx<Config>,
    expected_username: UserName,
    payload: ProvisioningPayload,
) -> Result<(), InternalRpcError> {
    let username = payload.add_device_action.username.clone();
    if username != expected_username {
        return Err(InternalRpcError::Other(
            "provision payload username mismatch".into(),
        ));
    }
    let dir = ctx.get(DIR_CLIENT);
    if payload.add_device_action.signer_pk == payload.device_secret.public().signing_public() {
        return Err(InternalRpcError::Other(
            "provision signer must be an existing different device".into(),
        ));
    }
    let UserAction::AddDevice { device_pk, .. } = &payload.add_device_action.action else {
        return Err(InternalRpcError::Other(
            "provision payload does not contain add_device action".into(),
        ));
    };
    if *device_pk != payload.device_secret.public().signing_public() {
        return Err(InternalRpcError::Other(
            "provision device secret does not match add_device action".into(),
        ));
    }
    dir.submit_prepared_user_action(payload.add_device_action.clone())
        .await
        .map_err(internal_err)?;

    let descriptor = dir
        .get_user_descriptor(&username)
        .await
        .map_err(internal_err)?
        .ok_or_else(|| InternalRpcError::Other("username not found".into()))?;
    let now = Timestamp::now().0;
    let self_hash = payload.device_secret.public().signing_public().bcs_hash();
    let Some(device_state) = descriptor.devices.get(&self_hash) else {
        return Err(InternalRpcError::Other(
            "add-device action committed but device is absent".into(),
        ));
    };
    if !device_state.active || device_state.is_expired(now) {
        return Err(InternalRpcError::Other(
            "device is inactive or expired after add-device".into(),
        ));
    }
    let server_name = descriptor
        .server_name
        .clone()
        .ok_or_else(|| InternalRpcError::Other("username has no bound server".into()))?;
    let server = server_from_name(&ctx, &server_name).await?;
    let auth = authenticate_device(&server, &username, &payload.device_secret).await?;
    let medium_sk = register_medium_key(&server, auth, &payload.device_secret).await?;
    persist_identity(
        ctx.get(DATABASE),
        username,
        server_name,
        payload.device_secret,
        medium_sk,
    )
    .await?;
    DbNotify::touch();
    Ok(())
}

fn encrypt_finish_payload(
    spake_key: &SpakeKey,
    payload: &ProvisioningPayload,
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
) -> Result<ProvisioningPayload, InternalRpcError> {
    let nonce: [u8; 24] = envelope
        .nonce
        .as_ref()
        .try_into()
        .map_err(|_| InternalRpcError::Other("invalid provision nonce length".into()))?;
    let key = AeadKey::from_bytes(spake_key.to_bytes());
    let plaintext = key
        .decrypt(nonce, &envelope.ciphertext, &[])
        .map_err(|err| InternalRpcError::Other(format!("provision decryption failed: {err}")))?;
    serde_json::from_slice::<ProvisioningPayload>(&plaintext).map_err(internal_err)
}

async fn post_spake_message(
    server: &ServerClient,
    channel: u32,
    kind: &str,
    message: &SpakeMessage,
) -> Result<(), InternalRpcError> {
    let body = serde_json::to_vec(&ProvisionSpakeMessage {
        spake_msg: *message,
    })
    .map_err(internal_err)?;
    server_multicast_post(
        server,
        channel,
        Blob {
            kind: kind.into(),
            inner: Bytes::from(body),
        },
    )
    .await
}

async fn post_finish_envelope(
    server: &ServerClient,
    channel: u32,
    envelope: &ProvisionFinishEnvelope,
) -> Result<(), InternalRpcError> {
    let body = serde_json::to_vec(envelope).map_err(internal_err)?;
    server_multicast_post(
        server,
        channel,
        Blob {
            kind: Blob::V1_PROVISION_FINISH.into(),
            inner: Bytes::from(body),
        },
    )
    .await
}

async fn wait_for_spake_message(
    server: &ServerClient,
    channel: u32,
    expected_kind: &str,
    timeout: Duration,
) -> Result<SpakeMessage, InternalRpcError> {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if let Some(blob) = server_multicast_poll(server, channel).await? {
            if blob.kind == expected_kind
                && let Ok(msg) = serde_json::from_slice::<ProvisionSpakeMessage>(&blob.inner)
            {
                return Ok(msg.spake_msg);
            }
        }
        tokio::time::sleep(PROVISION_HOST_POLL_INTERVAL).await;
    }
    Err(InternalRpcError::Other(
        "timed out waiting for provisioning handshake".into(),
    ))
}

async fn wait_for_finish_envelope(
    server: &ServerClient,
    channel: u32,
    timeout: Duration,
) -> Result<ProvisionFinishEnvelope, InternalRpcError> {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if let Some(blob) = server_multicast_poll(server, channel).await? {
            if blob.kind == Blob::V1_PROVISION_FINISH
                && let Ok(msg) = serde_json::from_slice::<ProvisionFinishEnvelope>(&blob.inner)
            {
                return Ok(msg);
            }
        }
        tokio::time::sleep(PROVISION_HOST_POLL_INTERVAL).await;
    }
    Err(InternalRpcError::Other(
        "timed out waiting for provisioning finish".into(),
    ))
}

async fn server_multicast_allocate(
    server: &ServerClient,
    auth: AuthToken,
) -> Result<u32, InternalRpcError> {
    server
        .v1_multicast_allocate(auth)
        .await
        .map_err(internal_err)?
        .map_err(|err| InternalRpcError::Other(err.to_string()))
}

async fn server_multicast_post(
    server: &ServerClient,
    channel: u32,
    value: Blob,
) -> Result<(), InternalRpcError> {
    server
        .v1_multicast_post(channel, value)
        .await
        .map_err(internal_err)?
        .map_err(|err| InternalRpcError::Other(err.to_string()))
}

async fn server_multicast_poll(
    server: &ServerClient,
    channel: u32,
) -> Result<Option<Blob>, InternalRpcError> {
    server
        .v1_multicast_poll(channel)
        .await
        .map_err(internal_err)?
        .map_err(|err| InternalRpcError::Other(err.to_string()))
}

async fn resolve_user_server_name(
    ctx: &AnyCtx<Config>,
    username: &UserName,
) -> Result<ServerName, InternalRpcError> {
    let dir = ctx.get(DIR_CLIENT);
    let descriptor = dir
        .get_user_descriptor(username)
        .await
        .map_err(internal_err)?
        .ok_or_else(|| InternalRpcError::Other("username not found in directory".into()))?;
    descriptor
        .server_name
        .ok_or_else(|| InternalRpcError::Other("username has no bound server".into()))
}

fn ensure_issuer_device(
    identity: &Identity,
    state: &UserDescriptor,
) -> Result<(), InternalRpcError> {
    let now = Timestamp::now().0;
    let self_hash = identity.device_secret.public().signing_public().bcs_hash();
    let Some(device_state) = state.devices.get(&self_hash) else {
        return Err(InternalRpcError::AccessDenied);
    };
    if !device_state.active || device_state.is_expired(now) || !device_state.can_issue {
        return Err(InternalRpcError::AccessDenied);
    }
    Ok(())
}

#[derive(Serialize, Deserialize)]
struct ProvisioningPayload {
    device_secret: DeviceSecret,
    add_device_action: PreparedUserAction,
}

#[derive(Serialize, Deserialize)]
struct ProvisionSpakeMessage {
    spake_msg: SpakeMessage,
}

#[serde_as]
#[derive(Serialize, Deserialize)]
struct ProvisionFinishEnvelope {
    #[serde_as(as = "IfIsHumanReadable<Base64<UrlSafe, Unpadded>, FromInto<Vec<u8>>>")]
    nonce: Bytes,
    #[serde_as(as = "IfIsHumanReadable<Base64<UrlSafe, Unpadded>, FromInto<Vec<u8>>>")]
    ciphertext: Bytes,
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
        return Err(InternalRpcError::Other("invalid pairing code format".into()));
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
        return Err(InternalRpcError::Other("invalid pairing code prefix".into()));
    }
    let mut cursor = 1;
    let delta = decode_elias_delta_bits(&bits, &mut cursor)?;
    if delta == 0 {
        return Err(InternalRpcError::Other("invalid pairing code channel".into()));
    }
    let channel_u64 = delta - 1;
    let channel = u32::try_from(channel_u64)
        .map_err(|_| InternalRpcError::Other("pairing code channel out of range".into()))?;
    if bits.len() != cursor + 32 {
        return Err(InternalRpcError::Other("invalid pairing code length".into()));
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

#[cfg(test)]
mod tests {
    use super::{decode_pairing_code, encode_pairing_code, format_pairing_code, parse_pairing_code_input};

    #[test]
    fn pairing_code_roundtrip() {
        let channels = [0u32, 1, 2, 9, 63, 255, 1_024, 65_535, 1_000_000];
        let tokens = [0u32, 1, 0x1234_5678, u32::MAX];
        for channel in channels {
            for token in tokens {
                let code = encode_pairing_code(channel, token).expect("encode code");
                let (decoded_channel, decoded_token) = decode_pairing_code(code).expect("decode code");
                assert_eq!(decoded_channel, channel);
                assert_eq!(decoded_token, token);
            }
        }
    }

    #[test]
    fn pairing_code_parse_normalizes_spaces_and_dashes() {
        let code = 1234_5678_9012u64;
        let display = format_pairing_code(code);
        assert_eq!(parse_pairing_code_input(&display).expect("parse display"), code);
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
