use anyctx::AnyCtx;
use bytes::Bytes;
use nullspace_crypt::aead::AeadKey;
use nullspace_crypt::signing::Signable;
use nullspace_crypt::spake::{SpakeKey, SpakeMessage, SpakeSession};
use nullspace_structs::Blob;
use nullspace_structs::certificate::DeviceSecret;
use nullspace_structs::directory::DirectoryUpdate;
use nullspace_structs::server::{AuthToken, ChanDirection, ServerClient, ServerName};
use nullspace_structs::timestamp::NanoTimestamp;
use nullspace_structs::username::{UserDescriptor, UserName};
use parking_lot::Mutex as ParkingMutex;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_with::base64::{Base64, UrlSafe};
use serde_with::formats::Unpadded;
use serde_with::{FromInto, IfIsHumanReadable, serde_as};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::auth_tokens::get_auth_token;
use crate::config::Config;
use crate::database::{DATABASE, DbNotify};
use crate::directory::DIR_CLIENT;
use crate::identity::Identity;
use crate::internal::{
    InternalRpcError, ProvisionHostPhase, ProvisionHostStart, ProvisionHostStatus,
    authenticate_device, internal_err, persist_identity, register_medium_key, server_from_name,
};

const PROVISION_HOST_POLL_INTERVAL: Duration = Duration::from_millis(250);
const PROVISION_HOST_REPOST_INTERVAL: Duration = Duration::from_secs(5);
const PROVISION_GUEST_WAIT_TIMEOUT: Duration = Duration::from_secs(60);

pub(crate) struct HostProvisioning {
    sessions: ParkingMutex<BTreeMap<u64, Arc<ProvisionHostSession>>>,
    next_session_id: AtomicU64,
}

impl HostProvisioning {
    pub(crate) fn new() -> Self {
        Self {
            sessions: ParkingMutex::new(BTreeMap::new()),
            next_session_id: AtomicU64::new(1),
        }
    }

    pub(crate) async fn start(
        &self,
        ctx: AnyCtx<Config>,
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
            let mut sessions = self.sessions.lock();
            sessions.insert(session_id, session.clone());
        }

        let username = identity.username.clone();
        tokio::spawn(async move {
            run_host_session(ctx, session, username, server, attempt).await;
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
            let sessions = self.sessions.lock();
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
            let mut sessions = self.sessions.lock();
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
    let (spake_session, ehlo_msg) = SpakeSession::start(
        normalized_code.to_string().as_bytes(),
        username.as_str().as_bytes(),
    );

    let helo_msg = wait_for_spake_message(
        &server,
        channel,
        ChanDirection::Forward,
        Blob::V1_PROVISION_HELO,
        PROVISION_GUEST_WAIT_TIMEOUT,
    )
    .await?;
    post_spake_message(
        &server,
        channel,
        ChanDirection::Backward,
        Blob::V1_PROVISION_EHLO,
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
    mut attempt: HostAttempt,
) {
    loop {
        if session.is_cancelled() {
            return;
        }
        match run_host_attempt(&ctx, &session, &username, server.as_ref(), attempt).await {
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
    attempt: HostAttempt,
) -> Result<bool, InternalRpcError> {
    let (spake_session, helo_msg) = SpakeSession::start(
        attempt.code.to_string().as_bytes(),
        username.as_str().as_bytes(),
    );
    if post_spake_message(
        server,
        attempt.channel,
        ChanDirection::Forward,
        Blob::V1_PROVISION_HELO,
        &helo_msg,
    )
    .await
    .is_err()
    {
        return Ok(false);
    }
    let started = Instant::now();
    let mut last_helo = started;

    loop {
        if session.is_cancelled() {
            return Ok(false);
        }
        if last_helo.elapsed() >= PROVISION_HOST_REPOST_INTERVAL {
            if post_spake_message(
                server,
                attempt.channel,
                ChanDirection::Forward,
                Blob::V1_PROVISION_HELO,
                &helo_msg,
            )
            .await
            .is_err()
            {
                return Ok(false);
            }
            last_helo = Instant::now();
        }
        let Some(blob) = server_channel_recv(server, attempt.channel, ChanDirection::Backward)
            .await
            .ok()
            .flatten()
        else {
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
        let payload = build_provisioning_payload(ctx, username).await?;
        let envelope = encrypt_finish_payload(&spake_key, &payload)?;
        if post_finish_envelope(server, attempt.channel, ChanDirection::Forward, &envelope)
            .await
            .is_err()
        {
            return Ok(false);
        }
        return Ok(true);
    }
}

async fn begin_host_attempt(
    ctx: &AnyCtx<Config>,
    server: &ServerClient,
    session: &ProvisionHostSession,
) -> Result<(HostAttempt, String), InternalRpcError> {
    let auth = get_auth_token(ctx).await.map_err(internal_err)?;
    let channel = server_channel_allocate(server, auth).await?;
    let token = rand::thread_rng().next_u32();
    let code = encode_pairing_code(channel, token)?;
    let display_code = format_pairing_code(code);
    session.set_pending_code(display_code.clone());
    Ok((HostAttempt { channel, code }, display_code))
}

async fn build_provisioning_payload(
    ctx: &AnyCtx<Config>,
    username: &UserName,
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
    let state = dir
        .query_key_state(identity.username.as_str())
        .await
        .map_err(internal_err)?;
    let state =
        state.ok_or_else(|| InternalRpcError::Other("username key state not found".into()))?;
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
    Ok(ProvisioningPayload {
        device_secret,
        add_device_update,
    })
}

async fn register_add_device_payload(
    ctx: AnyCtx<Config>,
    expected_username: UserName,
    payload: ProvisioningPayload,
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
    persist_identity(
        ctx.get(DATABASE),
        expected_username,
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
    direction: ChanDirection,
    kind: &str,
    message: &SpakeMessage,
) -> Result<(), InternalRpcError> {
    let body = serde_json::to_vec(&ProvisionSpakeMessage {
        spake_msg: *message,
    })
    .map_err(internal_err)?;
    server_channel_send(
        server,
        channel,
        direction,
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
    direction: ChanDirection,
    envelope: &ProvisionFinishEnvelope,
) -> Result<(), InternalRpcError> {
    let body = serde_json::to_vec(envelope).map_err(internal_err)?;
    server_channel_send(
        server,
        channel,
        direction,
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
    direction: ChanDirection,
    expected_kind: &str,
    timeout: Duration,
) -> Result<SpakeMessage, InternalRpcError> {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if let Some(blob) = server_channel_recv(server, channel, direction).await?
            && blob.kind == expected_kind
            && let Ok(msg) = serde_json::from_slice::<ProvisionSpakeMessage>(&blob.inner)
        {
            return Ok(msg.spake_msg);
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
    direction: ChanDirection,
    timeout: Duration,
) -> Result<ProvisionFinishEnvelope, InternalRpcError> {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if let Some(blob) = server_channel_recv(server, channel, direction).await?
            && blob.kind == Blob::V1_PROVISION_FINISH
            && let Ok(msg) = serde_json::from_slice::<ProvisionFinishEnvelope>(&blob.inner)
        {
            return Ok(msg);
        }
        tokio::time::sleep(PROVISION_HOST_POLL_INTERVAL).await;
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
        .v1_chan_allocate(auth)
        .await
        .map_err(internal_err)?
        .map_err(|err| InternalRpcError::Other(err.to_string()))
}

async fn server_channel_send(
    server: &ServerClient,
    channel: u32,
    direction: ChanDirection,
    value: Blob,
) -> Result<(), InternalRpcError> {
    server
        .v1_chan_send(channel, direction, value)
        .await
        .map_err(internal_err)?
        .map_err(|err| InternalRpcError::Other(err.to_string()))
}

async fn server_channel_recv(
    server: &ServerClient,
    channel: u32,
    direction: ChanDirection,
) -> Result<Option<Blob>, InternalRpcError> {
    server
        .v1_chan_recv(channel, direction)
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
    Ok(descriptor.server_name)
}

fn ensure_issuer_device(
    identity: &Identity,
    state: &UserDescriptor,
) -> Result<(), InternalRpcError> {
    let self_pk = identity.device_secret.public().signing_public();
    if !state.devices.contains(&self_pk) {
        return Err(InternalRpcError::AccessDenied);
    }
    Ok(())
}

#[derive(Serialize, Deserialize)]
struct ProvisioningPayload {
    device_secret: DeviceSecret,
    add_device_update: DirectoryUpdate,
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
