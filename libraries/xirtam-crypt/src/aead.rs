use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_with::base64::{Base64, UrlSafe};
use serde_with::formats::Unpadded;
use serde_with::{Bytes, IfIsHumanReadable, serde_as};
use thiserror::Error;

/// Errors returned by symmetric encryption operations.
#[derive(Debug, Error)]
pub enum AeadError {
    #[error("encryption failed")]
    Encrypt,
    #[error("decryption failed")]
    Decrypt,
}

/// ChaCha20-Poly1305 key used for symmetric encryption and decryption.
#[serde_as]
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AeadKey(
    #[serde_as(as = "IfIsHumanReadable<Base64<UrlSafe, Unpadded>, Bytes>")] [u8; 32],
);

impl AeadKey {
    /// Generate a random symmetric key.
    pub fn random() -> Self {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Build a symmetric key from 32 raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Serialize the symmetric key as 32 bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// Encrypt `plaintext` with the given nonce and associated data.
    pub fn encrypt(
        &self,
        nonce: [u8; 12],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, AeadError> {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.0));
        let payload = Payload {
            msg: plaintext,
            aad,
        };
        cipher
            .encrypt(Nonce::from_slice(&nonce), payload)
            .map_err(|_| AeadError::Encrypt)
    }

    /// Decrypt `ciphertext` with the given nonce and associated data.
    pub fn decrypt(
        &self,
        nonce: [u8; 12],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, AeadError> {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.0));
        let payload = Payload {
            msg: ciphertext,
            aad,
        };
        cipher
            .decrypt(Nonce::from_slice(&nonce), payload)
            .map_err(|_| AeadError::Decrypt)
    }
}
