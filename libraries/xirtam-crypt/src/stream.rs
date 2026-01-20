use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::XChaCha20;
use derivative::Derivative;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_with::base64::{Base64, UrlSafe};
use serde_with::formats::Unpadded;
use serde_with::{Bytes, IfIsHumanReadable, serde_as};

use crate::redacted_debug;

/// XChaCha20 key used for stream encryption and decryption without authentication.
#[serde_as]
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Derivative)]
#[derivative(Debug)]
pub struct StreamKey(
    #[derivative(Debug(format_with = "redacted_debug"))]
    #[serde_as(as = "IfIsHumanReadable<Base64<UrlSafe, Unpadded>, Bytes>")] [u8; 32],
);

impl StreamKey {
    /// Generate a random stream key.
    pub fn random() -> Self {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Build a stream key from 32 raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Serialize the stream key as 32 bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// Encrypt `plaintext` with the given nonce.
    pub fn encrypt(&self, nonce: [u8; 24], plaintext: &[u8]) -> Vec<u8> {
        let mut buf = plaintext.to_vec();
        let mut cipher = XChaCha20::new((&self.0).into(), (&nonce).into());
        cipher.apply_keystream(&mut buf);
        buf
    }

    /// Decrypt `ciphertext` with the given nonce.
    pub fn decrypt(&self, nonce: [u8; 24], ciphertext: &[u8]) -> Vec<u8> {
        let mut buf = ciphertext.to_vec();
        let mut cipher = XChaCha20::new((&self.0).into(), (&nonce).into());
        cipher.apply_keystream(&mut buf);
        buf
    }
}
