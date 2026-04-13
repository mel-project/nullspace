use bytes::Bytes;
use nullspace_crypt::aead::AeadKey;
use nullspace_crypt::dh::{DhPublic, DhSecret};
use nullspace_crypt::hash::BcsHashExt;
use nullspace_crypt::signing::{Signable, Signature, SigningPublic};
use nullspace_crypt::stream::StreamKey;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::certificate::DeviceSecret;
use crate::username::UserName;

/// A device-signed payload that authenticates the sender and body.
///
/// The signature is computed over the BCS encoding of `(sender, sender_device_pk, body)`
/// to provide defense-in-depth against malleability.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeviceSigned {
    pub sender: UserName,
    pub sender_device_pk: SigningPublic,
    pub body: Bytes,
    pub signature: Signature,
}

/// Errors returned by device-signed payload helpers.
#[derive(Debug, Error)]
pub enum DeviceSignedError {
    #[error("encode error")]
    Encode,
    #[error("decode error")]
    Decode,
    #[error("verify error")]
    Verify,
}

impl Signable for DeviceSigned {
    fn signed_value(&self) -> Vec<u8> {
        // Sign the full tuple to avoid malleability of metadata or body bytes.
        bcs::to_bytes(&(&self.sender, &self.sender_device_pk, &self.body))
            .expect("bcs serialization failed")
    }

    fn signature_mut(&mut self) -> &mut Signature {
        &mut self.signature
    }

    fn signature(&self) -> &Signature {
        &self.signature
    }
}

impl DeviceSigned {
    /// Sign a payload body with the sender device.
    pub fn sign_bytes(
        body: Bytes,
        sender: UserName,
        sender_device_pk: SigningPublic,
        sender_device: &DeviceSecret,
    ) -> Self {
        let mut signed = Self {
            sender,
            sender_device_pk,
            body,
            signature: Signature::from_bytes([0u8; 64]),
        };
        signed.sign(sender_device);
        signed
    }

    /// Return the sender username.
    pub fn sender(&self) -> &UserName {
        &self.sender
    }

    pub fn sender_device_pk(&self) -> SigningPublic {
        self.sender_device_pk
    }

    /// Verify and return the raw body bytes.
    pub fn verify_bytes(self) -> Result<Bytes, DeviceSignedError> {
        self.verify(self.sender_device_pk)
            .map_err(|_| DeviceSignedError::Verify)?;
        Ok(self.body)
    }
}

/// A header-encrypted payload with per-recipient headers.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HeaderEncrypted {
    pub sender_epk: DhPublic,
    pub headers: Vec<EncryptionHeader>,
    pub body: Bytes,
}

/// A single recipient header for header encryption.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptionHeader {
    pub receiver_mpk_short: [u8; 2],
    pub receiver_key: Bytes,
}

/// Errors returned by header encryption helpers.
#[derive(Debug, Error)]
pub enum HeaderEncryptionError {
    #[error("encode error")]
    Encode,
    #[error("encrypt error")]
    Encrypt,
    #[error("decrypt error")]
    Decrypt,
    #[error("dh error")]
    Dh,
}

impl HeaderEncrypted {
    /// Encrypt raw bytes for a set of medium-term public keys.
    pub fn encrypt_bytes<I>(plaintext: &[u8], recipients: I) -> Result<Self, HeaderEncryptionError>
    where
        I: IntoIterator<Item = DhPublic>,
    {
        let sender_esk = DhSecret::random();
        let sender_epk = sender_esk.public_key();
        let key = AeadKey::random();
        let key_bytes = key.to_bytes();
        let mut headers = Vec::new();
        for recipient_mpk in recipients {
            let receiver_mpk_short = mpk_short(&recipient_mpk);
            let ss = sender_esk
                .diffie_hellman(&recipient_mpk)
                .map_err(|_| HeaderEncryptionError::Dh)?;
            let sealed = StreamKey::from_bytes(ss).encrypt([0u8; 24], &key_bytes);
            headers.push(EncryptionHeader {
                receiver_mpk_short,
                receiver_key: Bytes::from(sealed),
            });
        }
        let aad = header_aad(&sender_epk, &headers)?;
        let ciphertext = key
            .encrypt([0u8; 24], plaintext, &aad)
            .map_err(|_| HeaderEncryptionError::Encrypt)?;
        Ok(Self {
            sender_epk,
            headers,
            body: Bytes::from(ciphertext),
        })
    }

    /// Decrypt raw bytes using the recipient's medium-term secret.
    pub fn decrypt_bytes(
        &self,
        recipient_medium: &DhSecret,
    ) -> Result<Vec<u8>, HeaderEncryptionError> {
        let recipient_mpk = recipient_medium.public_key();
        let mpk_short = mpk_short(&recipient_mpk);
        let aad = header_aad(&self.sender_epk, &self.headers)?;
        let ss = recipient_medium
            .diffie_hellman(&self.sender_epk)
            .map_err(|_| HeaderEncryptionError::Dh)?;
        let stream_key = StreamKey::from_bytes(ss);
        for header in self
            .headers
            .iter()
            .filter(|header| header.receiver_mpk_short == mpk_short)
        {
            let key_bytes = stream_key.decrypt([0u8; 24], &header.receiver_key);
            if key_bytes.len() != 32 {
                continue;
            }
            let mut key_buf = [0u8; 32];
            key_buf.copy_from_slice(&key_bytes);
            let key = AeadKey::from_bytes(key_buf);
            if let Ok(plaintext) = key.decrypt([0u8; 24], &self.body, &aad) {
                return Ok(plaintext);
            }
        }
        Err(HeaderEncryptionError::Decrypt)
    }
}

fn mpk_short(mpk: &DhPublic) -> [u8; 2] {
    let hash = mpk.bcs_hash().to_bytes();
    [hash[0], hash[1]]
}

fn header_aad(
    sender_epk: &DhPublic,
    headers: &[EncryptionHeader],
) -> Result<Vec<u8>, HeaderEncryptionError> {
    bcs::to_bytes(&(sender_epk, headers)).map_err(|_| HeaderEncryptionError::Encode)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{Event, EventRecipient, MessagePayload, MessageText, TAG_MESSAGE};
    use crate::timestamp::NanoTimestamp;
    use std::collections::BTreeMap;

    #[test]
    fn encrypt_decrypt_multiple_recipients() {
        let medium_a = DhSecret::random();
        let medium_b = DhSecret::random();

        let payload = MessagePayload {
            payload: MessageText::Plain("hello recipients".to_string()),
            attachments: Vec::new(),
            images: Vec::new(),
            replies_to: None,
            metadata: BTreeMap::new(),
        };
        let event = Event::default()
            .sender(UserName::parse("@sender_test").expect("sender username"))
            .recipient(EventRecipient::Dm(
                UserName::parse("@recipient01").expect("recipient username"),
            ))
            .sent_at(NanoTimestamp(0))
            .encoded_body(payload)
            .expect("payload");

        let encrypted = HeaderEncrypted::encrypt_bytes(
            &bcs::to_bytes(&event).expect("encode event"),
            [medium_a.public_key(), medium_b.public_key()],
        )
        .expect("encrypt");

        let decrypted_a = encrypted.decrypt_bytes(&medium_a).expect("decrypt a");
        let decrypted_b = encrypted.decrypt_bytes(&medium_b).expect("decrypt b");

        let event_a: Event = bcs::from_bytes(&decrypted_a).expect("decode a");
        let event_b: Event = bcs::from_bytes(&decrypted_b).expect("decode b");

        assert_eq!(event_a.tag, TAG_MESSAGE);
        assert_eq!(event_a.body, event.body);
        assert_eq!(event_b.tag, TAG_MESSAGE);
        assert_eq!(event_b.body, event.body);
    }

    #[test]
    fn encrypt_to_empty_recipient_set_is_unreadable() {
        let outsider = DhSecret::random();
        let plaintext = b"dead group payload";

        let encrypted = HeaderEncrypted::encrypt_bytes(plaintext, []).expect("encrypt");

        assert!(encrypted.headers.is_empty());
        assert!(encrypted.decrypt_bytes(&outsider).is_err());
    }
}
