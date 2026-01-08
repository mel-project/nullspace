use core::convert::TryFrom;
use std::fmt;
use std::str::FromStr;

use derivative::Derivative;
use ed25519_consensus::{Signature as Ed25519Signature, SigningKey, VerificationKey};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_with::base64::{Base64, UrlSafe};
use serde_with::formats::Unpadded;
use serde_with::{Bytes, IfIsHumanReadable, serde_as};
use thiserror::Error;

use crate::encoding;
use crate::ParseKeyError;

/// Ed25519 public key used for signing verification.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SigningPublic(VerificationKey);

/// Ed25519 signing key used to produce signatures.
#[derive(Clone, Derivative)]
#[derivative(Debug)]
pub struct SigningSecret(#[derivative(Debug(format_with = "redacted_debug"))] SigningKey);

/// Ed25519 signature.
#[serde_as]
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct Signature(
    #[serde_as(as = "IfIsHumanReadable<Base64<UrlSafe, Unpadded>, Bytes>")] [u8; 64],
);

/// Types that carry a signature over a serialized payload.
pub trait Signable {
    /// Return the bytes that are signed. This should *not* depend on the signature field.
    fn signed_value(&self) -> Vec<u8>;

    /// Mutable access to the signature field.
    fn signature_mut(&mut self) -> &mut Signature;

    /// Shared access to the signature field.
    fn signature(&self) -> &Signature;

    /// Sign this value with the provided secret key.
    fn sign(&mut self, signer: &SigningSecret) {
        let sig = signer.sign(&self.signed_value());
        *self.signature_mut() = sig;
    }

    /// Verify this value against the provided public key.
    fn verify(&self, signer: SigningPublic) -> Result<(), SigningError> {
        signer.verify(self.signature(), &self.signed_value())
    }
}

/// Errors returned by signing operations.
#[derive(Debug, Error)]
pub enum SigningError {
    #[error("invalid public key bytes")]
    InvalidPublicKey,
    #[error("signature verification failed")]
    InvalidSignature,
}

#[serde_as]
#[derive(Serialize, Deserialize)]
struct SigningPublicSerde(
    #[serde_as(as = "IfIsHumanReadable<Base64<UrlSafe, Unpadded>, Bytes>")] [u8; 32],
);

#[serde_as]
#[derive(Serialize, Deserialize)]
struct SigningSecretSerde(
    #[serde_as(as = "IfIsHumanReadable<Base64<UrlSafe, Unpadded>, Bytes>")] [u8; 32],
);

impl SigningPublic {
    /// Build a public key from its 32-byte compressed form.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, SigningError> {
        VerificationKey::try_from(bytes)
            .map(Self)
            .map_err(|_| SigningError::InvalidPublicKey)
    }

    /// Serialize the public key as 32 bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Verify a signature over `msg` using this public key.
    pub fn verify(&self, signature: &Signature, msg: &[u8]) -> Result<(), SigningError> {
        let sig = Ed25519Signature::from(signature.0);
        self.0
            .verify(&sig, msg)
            .map_err(|_| SigningError::InvalidSignature)
    }
}

impl fmt::Display for SigningPublic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", encoding::encode_32_base64(self.to_bytes()))
    }
}

impl FromStr for SigningPublic {
    type Err = ParseKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = encoding::decode_32_base64(s)?;
        SigningPublic::from_bytes(bytes).map_err(|_| ParseKeyError::InvalidPublicKey)
    }
}

impl Serialize for SigningPublic {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        SigningPublicSerde(self.to_bytes()).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SigningPublic {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let SigningPublicSerde(bytes) = SigningPublicSerde::deserialize(deserializer)?;
        SigningPublic::from_bytes(bytes).map_err(serde::de::Error::custom)
    }
}

impl SigningSecret {
    /// Generate a random signing secret.
    pub fn random() -> Self {
        Self(SigningKey::new(rand::thread_rng()))
    }

    /// Build a signing secret from 32 raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(SigningKey::from(bytes))
    }

    /// Serialize the signing secret as 32 bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Derive the matching public key for this secret.
    pub fn public_key(&self) -> SigningPublic {
        SigningPublic(self.0.verification_key())
    }

    /// Sign a message and return the signature.
    pub fn sign(&self, msg: &[u8]) -> Signature {
        Signature(self.0.sign(msg).to_bytes())
    }
}

impl fmt::Display for SigningSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", encoding::encode_32_base64(self.to_bytes()))
    }
}

impl FromStr for SigningSecret {
    type Err = ParseKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = encoding::decode_32_base64(s)?;
        Ok(SigningSecret::from_bytes(bytes))
    }
}

impl Signature {
    /// Build a signature from its 64-byte form.
    pub fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    /// Serialize the signature as 64 bytes.
    pub fn to_bytes(&self) -> [u8; 64] {
        self.0
    }
}

fn redacted_debug<T>(_value: &T, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.write_str("REDACTED")
}

impl Serialize for SigningSecret {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        SigningSecretSerde(self.to_bytes()).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SigningSecret {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let SigningSecretSerde(bytes) = SigningSecretSerde::deserialize(deserializer)?;
        Ok(SigningSecret::from_bytes(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::{Signature, SigningPublic, SigningSecret};

    #[test]
    fn serde_json_round_trip_and_verify() {
        let secret = SigningSecret::from_bytes([7u8; 32]);
        let public = secret.public_key();
        let msg = b"signing-round-trip";
        let signature = secret.sign(msg);

        let secret_json = serde_json::to_string(&secret).expect("secret to json");
        let public_json = serde_json::to_string(&public).expect("public to json");

        let secret_val: serde_json::Value =
            serde_json::from_str(&secret_json).expect("secret json value");
        let public_val: serde_json::Value =
            serde_json::from_str(&public_json).expect("public json value");

        assert!(secret_val.is_string());
        assert!(public_val.is_string());

        let secret_back: SigningSecret =
            serde_json::from_str(&secret_json).expect("secret from json");
        let public_back: SigningPublic =
            serde_json::from_str(&public_json).expect("public from json");

        assert_eq!(secret.to_bytes(), secret_back.to_bytes());
        assert_eq!(public.to_bytes(), public_back.to_bytes());
        public_back
            .verify(&signature, msg)
            .expect("signature verify");

        let signature_json = serde_json::to_string(&signature).expect("signature to json");
        let signature_back: Signature =
            serde_json::from_str(&signature_json).expect("signature from json");
        assert_eq!(signature.to_bytes(), signature_back.to_bytes());
    }
}
