use std::collections::BTreeMap;

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use xirtam_crypt::aead::AeadKey;
use xirtam_crypt::dh::{DhPublic, DhSecret};
use xirtam_crypt::hash::{BcsHashExt, Hash};
use xirtam_crypt::signing::Signature;

use crate::Blob;
use crate::certificate::{CertificateChain, DevicePublic, DeviceSecret};
use crate::handle::Handle;

/// An encrypted payload with per-device key headers.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Envelope {
    pub headers: BTreeMap<Hash, Bytes>,
    pub body: Bytes,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct EnvelopeHeader {
    sender_handle: Handle,
    sender_chain: CertificateChain,
    key: [u8; 32],
    key_sig: Signature,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecryptedEnvelope {
    sender_handle: Handle,
    sender_chain: CertificateChain,
    key: [u8; 32],
    key_sig: Signature,
    body: Bytes,
}

#[derive(Debug, Error)]
#[error("envelope error")]
pub struct EnvelopeError;

impl Envelope {
    pub fn encrypt_message<I>(
        message: &Blob,
        sender_handle: Handle,
        sender_chain: CertificateChain,
        sender_device: &DeviceSecret,
        recipients: I,
    ) -> Result<Envelope, EnvelopeError>
    where
        I: IntoIterator<Item = (DevicePublic, DhPublic)>,
    {
        let key = AeadKey::random();
        let key_bytes = key.to_bytes();
        let key_sig = sender_device.sign(&key_bytes);
        let header = EnvelopeHeader {
            sender_handle,
            sender_chain,
            key: key_bytes,
            key_sig,
        };
        let header_bytes = bcs::to_bytes(&header).map_err(|_| EnvelopeError)?;
        let plaintext = bcs::to_bytes(message).map_err(|_| EnvelopeError)?;
        let ciphertext = key
            .encrypt([0u8; 24], &plaintext, &[])
            .map_err(|_| EnvelopeError)?;

        let mut headers = BTreeMap::new();
        for (device_public, medium_pk) in recipients {
            let device_hash = device_public.bcs_hash();
            let sealed = encrypt_header(&medium_pk, &header_bytes)?;
            headers.insert(device_hash, sealed);
        }

        Ok(Envelope {
            headers,
            body: Bytes::from(ciphertext),
        })
    }

    pub fn decrypt_message(
        &self,
        recipient_public: &DevicePublic,
        recipient_medium: &DhSecret,
    ) -> Result<DecryptedEnvelope, EnvelopeError> {
        let recipient_device_hash = recipient_public.bcs_hash();
        let sealed = self
            .headers
            .get(&recipient_device_hash)
            .ok_or(EnvelopeError)?;
        let header_bytes = decrypt_header(recipient_medium, sealed)?;
        let header: EnvelopeHeader = bcs::from_bytes(&header_bytes).map_err(|_| EnvelopeError)?;
        let key = AeadKey::from_bytes(header.key);
        let plaintext = key
            .decrypt([0u8; 24], &self.body, &[])
            .map_err(|_| EnvelopeError)?;
        Ok(DecryptedEnvelope {
            sender_handle: header.sender_handle,
            sender_chain: header.sender_chain,
            key: header.key,
            key_sig: header.key_sig,
            body: Bytes::from(plaintext),
        })
    }
}

impl DecryptedEnvelope {
    pub fn handle(&self) -> &Handle {
        &self.sender_handle
    }

    pub fn verify(self, sender_root_hash: Hash) -> Result<Blob, EnvelopeError> {
        let verified = self
            .sender_chain
            .verify(sender_root_hash)
            .map_err(|_| EnvelopeError)?;
        let device = verified.last().ok_or(EnvelopeError)?;
        device
            .pk
            .verify(&self.key_sig, &self.key)
            .map_err(|_| EnvelopeError)?;
        let message: Blob = bcs::from_bytes(&self.body).map_err(|_| EnvelopeError)?;
        Ok(message)
    }
}

fn encrypt_header(to: &DhPublic, msg: &[u8]) -> Result<Bytes, EnvelopeError> {
    let eph_sk = DhSecret::random();
    let ss = eph_sk.diffie_hellman(to);
    let ciphertext = AeadKey::from_bytes(ss)
        .encrypt(Default::default(), msg, &[])
        .map_err(|_| EnvelopeError)?;
    let encoded = bcs::to_bytes(&(eph_sk.public_key(), ciphertext)).map_err(|_| EnvelopeError)?;
    Ok(encoded.into())
}

fn decrypt_header(my_sk: &DhSecret, envelope: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
    let (eph_pk, ct): (DhPublic, Vec<u8>) = bcs::from_bytes(envelope).map_err(|_| EnvelopeError)?;
    let ss = my_sk.diffie_hellman(&eph_pk);
    let pt = AeadKey::from_bytes(ss)
        .decrypt(Default::default(), &ct, &[])
        .map_err(|_| EnvelopeError)?;
    Ok(pt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::msg_content::MessageContent;
    use crate::timestamp::{NanoTimestamp, Timestamp};

    #[test]
    fn encrypt_decrypt_multiple_recipients() {
        let sender_secret = DeviceSecret::random();
        let sender_handle = Handle::parse("@sender01").expect("sender handle");
        let sender_cert = sender_secret.self_signed(Timestamp(u64::MAX), true);
        let sender_chain = CertificateChain(vec![sender_cert.clone()]);
        let sender_root_hash = sender_cert.pk.bcs_hash();

        let recipient_a = DeviceSecret::random();
        let recipient_b = DeviceSecret::random();
        let medium_a = DhSecret::random();
        let medium_b = DhSecret::random();
        let medium_sender = DhSecret::random();

        let content = MessageContent {
            recipient: Handle::parse("@recipient01").expect("recipient handle"),
            sent_at: NanoTimestamp(0),
            mime: smol_str::SmolStr::new("text/plain"),
            body: Bytes::from_static(b"hello recipients"),
        };
        let message = Blob {
            kind: Blob::V1_MESSAGE_CONTENT.into(),
            inner: Bytes::from(bcs::to_bytes(&content).expect("content")),
        };

        let encrypted = Envelope::encrypt_message(
            &message,
            sender_handle.clone(),
            sender_chain,
            &sender_secret,
            [
                (sender_secret.public(), medium_sender.public_key()),
                (recipient_a.public(), medium_a.public_key()),
                (recipient_b.public(), medium_b.public_key()),
            ],
        )
        .expect("encrypt");

        let decrypted_a = encrypted
            .decrypt_message(&recipient_a.public(), &medium_a)
            .expect("decrypt a");
        let decrypted_b = encrypted
            .decrypt_message(&recipient_b.public(), &medium_b)
            .expect("decrypt b");

        assert_eq!(decrypted_a.handle(), &sender_handle);
        assert_eq!(decrypted_b.handle(), &sender_handle);

        let message_a = decrypted_a.verify(sender_root_hash).expect("verify a");
        let message_b = decrypted_b.verify(sender_root_hash).expect("verify b");

        assert_eq!(message_a.kind, message.kind);
        assert_eq!(message_a.inner, message.inner);
        assert_eq!(message_b.kind, message.kind);
        assert_eq!(message_b.inner, message.inner);
    }
}
