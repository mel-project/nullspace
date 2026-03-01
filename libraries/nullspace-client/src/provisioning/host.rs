use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

use anyctx::AnyCtx;
use bytes::Bytes;
use nullspace_crypt::signing::Signable;
use nullspace_crypt::spake::SpakeSession;
use nullspace_structs::directory::DirectoryUpdate;
use nullspace_structs::server::{ChanDirection, ServerClient};
use nullspace_structs::username::UserName;
use parking_lot::Mutex as ParkingMutex;
use rand::RngCore;

use crate::auth_tokens::get_auth_token;
use crate::config::Config;
use crate::database::DATABASE;
use crate::identity::Identity;
use crate::internal::{
    InternalRpcError, ProvisionHostPhase, ProvisionHostStart, ProvisionHostStatus, internal_err,
};
use crate::DIR_CLIENT;

use super::pairing_code::{encode_pairing_code, format_pairing_code};
use super::wire::{
    ProvisionSpakePhase, ProvisionWireMessage, ProvisioningPayload, encrypt_finish_payload,
    post_finish_envelope, post_spake_message, server_channel_allocate, server_channel_recv,
};
use super::{
    PROVISION_HOST_POLL_INTERVAL, PROVISION_HOST_REPOST_INTERVAL, ensure_issuer_device, next_nonce,
    resolve_user_server_name, server_from_name,
};

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
        let identity = Identity::load(&mut *db.acquire().await.map_err(internal_err)?)
            .await
            .map_err(internal_err)?;
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
        ProvisionSpakePhase::Helo,
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
                ProvisionSpakePhase::Helo,
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
        let Ok(wire) = serde_json::from_slice::<ProvisionWireMessage>(&blob.0) else {
            tokio::time::sleep(PROVISION_HOST_POLL_INTERVAL).await;
            continue;
        };
        let ProvisionWireMessage::Ehlo { spake_msg } = wire else {
            tokio::time::sleep(PROVISION_HOST_POLL_INTERVAL).await;
            continue;
        };
        let Ok(spake_key) = spake_session.finish(&spake_msg) else {
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
    let identity = Identity::load(&mut *db.acquire().await.map_err(internal_err)?)
        .await
        .map_err(internal_err)?;
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
    let device_secret = nullspace_structs::certificate::DeviceSecret::random();
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
        dm_mailbox_key: identity.dm_mailbox_key,
    })
}
