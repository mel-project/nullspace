use anyctx::AnyCtx;
use bytes::Bytes;
use nullspace_crypt::dh::DhPublic;
use nullspace_structs::e2ee::{DeviceSigned, HeaderEncrypted};
use nullspace_structs::username::UserName;

use crate::config::Config;
use crate::identity::Identity;

/// Result of decrypting and verifying a device-signed, header-encrypted message.
pub(crate) struct VerifiedPayload {
    pub sender: UserName,
    pub payload: Bytes,
}

/// Decrypt a header-encrypted blob, then verify the device signature.
///
/// Tries the current medium key first, falling back to the previous one.
/// The sender's device is verified against the directory.
pub(crate) async fn decrypt_and_verify(
    ctx: &AnyCtx<Config>,
    identity: &Identity,
    ciphertext: &[u8],
) -> anyhow::Result<VerifiedPayload> {
    let encrypted: HeaderEncrypted = bcs::from_bytes(ciphertext)?;
    let decrypted = match encrypted.decrypt_bytes(&identity.medium_sk_current) {
        Ok(d) => d,
        Err(err) => {
            tracing::debug!(error = %err, "decrypt with current medium key failed, trying previous");
            encrypted.decrypt_bytes(&identity.medium_sk_prev)?
        }
    };

    let signed: DeviceSigned = bcs::from_bytes(&decrypted)?;
    let sender = signed.sender().clone();
    let descriptor = crate::user_info::get_user_descriptor(ctx, &sender).await?;
    if !descriptor.devices.contains(&signed.sender_device_pk()) {
        anyhow::bail!("sender device not found in directory state");
    }
    let payload = signed
        .verify_bytes()
        .map_err(|_| anyhow::anyhow!("device signature verification failed"))?;

    Ok(VerifiedPayload { sender, payload })
}

/// Sign a payload with the device key, then header-encrypt for all recipients.
pub(crate) fn sign_and_encrypt(
    identity: &Identity,
    payload: &[u8],
    recipients: impl IntoIterator<Item = DhPublic>,
) -> anyhow::Result<Bytes> {
    let signed = DeviceSigned::sign_bytes(
        Bytes::from(payload.to_vec()),
        identity.username.clone(),
        identity.device_secret.public().signing_public(),
        &identity.device_secret,
    );
    let signed_bytes = bcs::to_bytes(&signed)?;
    let encrypted = HeaderEncrypted::encrypt_bytes(&signed_bytes, recipients)
        .map_err(|_| anyhow::anyhow!("header encryption failed"))?;
    Ok(Bytes::from(bcs::to_bytes(&encrypted)?))
}
