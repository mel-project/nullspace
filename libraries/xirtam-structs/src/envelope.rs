use std::fmt::Display;

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use xirtam_crypt::aead::AeadKey;
use xirtam_crypt::dh::{DhPublic, DhSecret, triple_dh};

#[derive(Clone)]
pub struct EnvelopePublic {
    pub long_term: DhPublic,
    pub short_term: DhPublic,
}

#[derive(Clone)]
pub struct EnvelopeSecret {
    pub long_term: DhSecret,
    pub short_term: DhSecret,
}

#[derive(Debug, Error)]
/// An intentionally opaque error in sealing or opening envelopes.
pub struct EnvelopeError;

impl Display for EnvelopeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        "envelope error".fmt(f)
    }
}

#[derive(Serialize, Deserialize)]
struct EnvelopePayload {
    sender_ephemeral: DhPublic,
    ciphertext: Vec<u8>,
}

impl EnvelopePublic {
    pub fn seal_to(
        &self,
        plaintext: Bytes,
        sender_long_term: &DhSecret,
    ) -> Result<Bytes, EnvelopeError> {
        let sender_ephemeral = DhSecret::random();
        let key_bytes = triple_dh(
            sender_long_term,
            &sender_ephemeral,
            &self.long_term,
            &self.short_term,
        );
        let key = AeadKey::from_bytes(key_bytes);
        let nonce = [0u8; 12];
        let ciphertext = key
            .encrypt(nonce, &plaintext, &[])
            .map_err(|_| EnvelopeError)?;
        let payload = EnvelopePayload {
            sender_ephemeral: sender_ephemeral.public_key(),
            ciphertext,
        };
        let encoded = bcs::to_bytes(&payload).map_err(|_| EnvelopeError)?;
        Ok(Bytes::from(encoded))
    }
}

impl EnvelopeSecret {
    pub fn open_from(
        &self,
        envelope: Bytes,
        sender_long_term: &DhPublic,
    ) -> Result<Bytes, EnvelopeError> {
        let payload: EnvelopePayload = bcs::from_bytes(&envelope).map_err(|_| EnvelopeError)?;
        let key_bytes = triple_dh(
            &self.long_term,
            &self.short_term,
            sender_long_term,
            &payload.sender_ephemeral,
        );
        let key = AeadKey::from_bytes(key_bytes);
        let plaintext = key
            .decrypt([0u8; 12], &payload.ciphertext, &[])
            .map_err(|_| EnvelopeError)?;
        Ok(Bytes::from(plaintext))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_roundtrip() {
        let sender_long_term = DhSecret::random();
        let receiver_long_term = DhSecret::random();
        let receiver_short_term = DhSecret::random();
        let envelope_public = EnvelopePublic {
            long_term: receiver_long_term.public_key(),
            short_term: receiver_short_term.public_key(),
        };
        let envelope_secret = EnvelopeSecret {
            long_term: receiver_long_term,
            short_term: receiver_short_term,
        };
        let plaintext = Bytes::from_static(b"roundtrip envelope test");

        let sealed = envelope_public
            .seal_to(plaintext.clone(), &sender_long_term)
            .expect("seal");
        let opened = envelope_secret
            .open_from(sealed, &sender_long_term.public_key())
            .expect("open");

        assert_eq!(opened, plaintext);
    }

}
