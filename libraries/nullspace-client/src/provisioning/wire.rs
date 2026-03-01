use std::time::{Duration, Instant};

use bytes::Bytes;
use nullspace_crypt::aead::AeadKey;
use nullspace_crypt::spake::{SpakeKey, SpakeMessage};
use nullspace_structs::Blob;
use nullspace_structs::certificate::DeviceSecret;
use nullspace_structs::directory::DirectoryUpdate;
use nullspace_structs::mailbox::MailboxKey;
use nullspace_structs::server::{AuthToken, ChanDirection, ServerClient};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_with::base64::{Base64, UrlSafe};
use serde_with::formats::Unpadded;
use serde_with::{FromInto, IfIsHumanReadable, serde_as};

use crate::internal::{InternalRpcError, internal_err};

use super::PROVISION_HOST_POLL_INTERVAL;

#[derive(Serialize, Deserialize)]
pub(crate) struct ProvisioningPayload {
    pub(crate) device_secret: DeviceSecret,
    pub(crate) add_device_update: DirectoryUpdate,
    pub(crate) dm_mailbox_key: MailboxKey,
}

#[serde_as]
#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct ProvisionFinishEnvelope {
    #[serde_as(as = "IfIsHumanReadable<Base64<UrlSafe, Unpadded>, FromInto<Vec<u8>>>")]
    nonce: Bytes,
    #[serde_as(as = "IfIsHumanReadable<Base64<UrlSafe, Unpadded>, FromInto<Vec<u8>>>")]
    ciphertext: Bytes,
}

#[derive(Clone, Copy)]
pub(crate) enum ProvisionSpakePhase {
    Helo,
    Ehlo,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum ProvisionWireMessage {
    Helo { spake_msg: SpakeMessage },
    Ehlo { spake_msg: SpakeMessage },
    Finish { envelope: ProvisionFinishEnvelope },
}

pub(crate) fn encrypt_finish_payload(
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

pub(crate) fn decrypt_finish_payload(
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

pub(crate) async fn post_spake_message(
    server: &ServerClient,
    channel: u32,
    direction: ChanDirection,
    phase: ProvisionSpakePhase,
    message: &SpakeMessage,
) -> Result<(), InternalRpcError> {
    let payload = match phase {
        ProvisionSpakePhase::Helo => ProvisionWireMessage::Helo {
            spake_msg: *message,
        },
        ProvisionSpakePhase::Ehlo => ProvisionWireMessage::Ehlo {
            spake_msg: *message,
        },
    };
    let body = serde_json::to_vec(&payload).map_err(internal_err)?;
    server_channel_send(server, channel, direction, Blob(Bytes::from(body))).await
}

pub(crate) async fn post_finish_envelope(
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

pub(crate) async fn wait_for_spake_message(
    server: &ServerClient,
    channel: u32,
    direction: ChanDirection,
    expected_phase: ProvisionSpakePhase,
    timeout: Duration,
) -> Result<SpakeMessage, InternalRpcError> {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if let Some(blob) = server_channel_recv(server, channel, direction).await?
            && let Ok(msg) = serde_json::from_slice::<ProvisionWireMessage>(&blob.0)
        {
            match (expected_phase, msg) {
                (ProvisionSpakePhase::Helo, ProvisionWireMessage::Helo { spake_msg }) => {
                    return Ok(spake_msg);
                }
                (ProvisionSpakePhase::Ehlo, ProvisionWireMessage::Ehlo { spake_msg }) => {
                    return Ok(spake_msg);
                }
                _ => {}
            }
        }
        tokio::time::sleep(PROVISION_HOST_POLL_INTERVAL).await;
    }
    Err(InternalRpcError::Other(
        "timed out waiting for provisioning handshake".into(),
    ))
}

pub(crate) async fn wait_for_finish_envelope(
    server: &ServerClient,
    channel: u32,
    direction: ChanDirection,
    timeout: Duration,
) -> Result<ProvisionFinishEnvelope, InternalRpcError> {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if let Some(blob) = server_channel_recv(server, channel, direction).await?
            && let Ok(ProvisionWireMessage::Finish { envelope }) =
                serde_json::from_slice::<ProvisionWireMessage>(&blob.0)
        {
            return Ok(envelope);
        }
        tokio::time::sleep(PROVISION_HOST_POLL_INTERVAL).await;
    }
    Err(InternalRpcError::Other(
        "timed out waiting for provisioning finish".into(),
    ))
}

pub(crate) async fn server_channel_allocate(
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

pub(crate) async fn server_channel_recv(
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
