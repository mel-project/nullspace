use std::collections::BTreeMap;

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use smol_str::SmolStr;
use thiserror::Error;
use xirtam_crypt::aead::AeadKey;
use xirtam_crypt::dh::{DhPublic, DhSecret};
use xirtam_crypt::hash::{BcsHashExt, Hash};
use xirtam_crypt::signing::Signature;

use crate::Message;
use crate::certificate::{CertificateChain, DevicePublic, DeviceSecret};
use crate::envelope::{envelope_decrypt, envelope_encrypt};
use crate::handle::Handle;

/// A decoded DM payload.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageContent {
    pub mime: SmolStr,
    pub body: Bytes,
}

#[derive(Debug, Error)]
#[error("decryption error")]
pub struct DecryptionError;

/// An encrypted DM payload with per-device key headers.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedDm {
    pub headers: BTreeMap<Hash, Bytes>,
    pub body: Bytes,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct EncryptedDmHeader {
    sender_handle: Handle,
    sender_chain: CertificateChain,
    key: [u8; 32],
    key_sig: Signature,
}

#[derive(Clone, Debug)]
pub struct DecryptedDm {
    sender_handle: Handle,
    sender_chain: CertificateChain,
    key: AeadKey,
    key_sig: Signature,
    body: Bytes,
}

impl MessageContent {
    pub fn encrypt<I>(
        &self,
        sender_handle: Handle,
        sender_chain: CertificateChain,
        sender_device: &DeviceSecret,
        recipients: I,
    ) -> Result<EncryptedDm, DecryptionError>
    where
        I: IntoIterator<Item = (DevicePublic, DhPublic)>,
    {
        let key = AeadKey::random();
        let key_bytes = key.to_bytes();
        let key_sig = sender_device.sign_sk.sign(&key_bytes);
        let header = EncryptedDmHeader {
            sender_handle,
            sender_chain,
            key: key_bytes,
            key_sig,
        };
        let header_bytes = bcs::to_bytes(&header).map_err(|_| DecryptionError)?;
        let message = Message {
            kind: Message::V1_MESSAGE_CONTENT.into(),
            inner: Bytes::from(bcs::to_bytes(self).map_err(|_| DecryptionError)?),
        };
        let plaintext = bcs::to_bytes(&message).map_err(|_| DecryptionError)?;
        let ciphertext = key
            .encrypt([0u8; 12], &plaintext, &[])
            .map_err(|_| DecryptionError)?;

        let mut headers = BTreeMap::new();
        for (device_public, temp_pk) in recipients {
            let device_hash = device_public.bcs_hash();
            let sealed = envelope_encrypt(&temp_pk, &header_bytes);
            headers.insert(device_hash, sealed);
        }

        Ok(EncryptedDm {
            headers,
            body: Bytes::from(ciphertext),
        })
    }
}

impl EncryptedDm {
    pub fn decrypt(
        &self,
        recipient_secret: &DeviceSecret,
        recipient_temp: &DhSecret,
    ) -> Result<DecryptedDm, DecryptionError> {
        let recipient_device_hash = recipient_secret.public().bcs_hash();
        let sealed = self
            .headers
            .get(&recipient_device_hash)
            .ok_or(DecryptionError)?;
        let header_bytes = envelope_decrypt(recipient_temp, sealed).map_err(|_| DecryptionError)?;
        let header: EncryptedDmHeader =
            bcs::from_bytes(&header_bytes).map_err(|_| DecryptionError)?;
        Ok(DecryptedDm {
            sender_handle: header.sender_handle,
            sender_chain: header.sender_chain,
            key: AeadKey::from_bytes(header.key),
            key_sig: header.key_sig,
            body: self.body.clone(),
        })
    }
}

impl DecryptedDm {
    pub fn sender(&self) -> Handle {
        self.sender_handle.clone()
    }

    pub fn validate(self, sender_root_hash: Hash) -> Result<MessageContent, DecryptionError> {
        let verified = self
            .sender_chain
            .verify(sender_root_hash)
            .map_err(|_| DecryptionError)?;
        let device = verified.last().ok_or(DecryptionError)?;
        device
            .pk
            .sign_pk
            .verify(&self.key_sig, &self.key.to_bytes())
            .map_err(|_| DecryptionError)?;
        let plaintext = self
            .key
            .decrypt([0u8; 12], &self.body, &[])
            .map_err(|_| DecryptionError)?;
        let message: Message = bcs::from_bytes(&plaintext).map_err(|_| DecryptionError)?;
        if message.kind != Message::V1_MESSAGE_CONTENT {
            return Err(DecryptionError);
        }
        let content: MessageContent =
            bcs::from_bytes(&message.inner).map_err(|_| DecryptionError)?;
        Ok(content)
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::timestamp::Timestamp;

    #[test]
    fn encrypt_decrypt_multiple_recipients() {
        let sender_secret = DeviceSecret {
            sign_sk: xirtam_crypt::signing::SigningSecret::random(),
            long_sk: DhSecret::random(),
        };
        let sender_handle = Handle::parse("@sender01").expect("sender handle");
        let sender_cert = sender_secret.self_signed(Timestamp(u64::MAX), true);
        let sender_chain = CertificateChain(vec![sender_cert.clone()]);
        let sender_root_hash = sender_cert.pk.sign_pk.bcs_hash();

        let recipient_a = DeviceSecret {
            sign_sk: xirtam_crypt::signing::SigningSecret::random(),
            long_sk: DhSecret::random(),
        };
        let recipient_b = DeviceSecret {
            sign_sk: xirtam_crypt::signing::SigningSecret::random(),
            long_sk: DhSecret::random(),
        };
        let temp_a = DhSecret::random();
        let temp_b = DhSecret::random();
        let temp_sender = DhSecret::random();

        let content = MessageContent {
            mime: SmolStr::new("text/plain"),
            body: Bytes::from_static(b"hello recipients"),
        };

        let encrypted = content
            .encrypt(
                sender_handle.clone(),
                sender_chain,
                &sender_secret,
                [
                    (sender_secret.public(), temp_sender.public_key()),
                    (recipient_a.public(), temp_a.public_key()),
                    (recipient_b.public(), temp_b.public_key()),
                ],
            )
            .expect("encrypt");

        let decrypted_a = encrypted.decrypt(&recipient_a, &temp_a).expect("decrypt a");
        let decrypted_b = encrypted.decrypt(&recipient_b, &temp_b).expect("decrypt b");

        assert_eq!(decrypted_a.sender(), sender_handle);
        assert_eq!(decrypted_b.sender(), sender_handle);

        let content_a = decrypted_a.validate(sender_root_hash).expect("validate a");
        let content_b = decrypted_b.validate(sender_root_hash).expect("validate b");

        assert_eq!(content_a.mime, content.mime);
        assert_eq!(content_a.body, content.body);
        assert_eq!(content_b.mime, content.mime);
        assert_eq!(content_b.body, content.body);
    }
}
