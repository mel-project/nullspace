use crate::hash::Hash;
use crate::redacted_debug;
use std::fmt;
use std::str::FromStr;

use derivative::Derivative;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_with::base64::{Base64, UrlSafe};
use serde_with::formats::Unpadded;
use serde_with::{Bytes, IfIsHumanReadable, serde_as};
use subtle::ConstantTimeEq;
use thiserror::Error;

use crate::ParseKeyError;
use crate::encoding;

/// Errors returned by Diffie-Hellman operations.
#[derive(Debug, Error)]
pub enum DhError {
    #[error("invalid shared secret")]
    InvalidSharedSecret,
}

/// X25519 public key used for Diffie-Hellman key exchange.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DhPublic(x25519_dalek::PublicKey);

/// X25519 static secret key used for Diffie-Hellman key exchange.
#[derive(Clone, Derivative)]
#[derivative(Debug)]
pub struct DhSecret(
    #[derivative(Debug(format_with = "redacted_debug"))] x25519_dalek::StaticSecret,
);

#[serde_as]
#[derive(Serialize, Deserialize)]
struct DhPublicSerde(
    #[serde_as(as = "IfIsHumanReadable<Base64<UrlSafe, Unpadded>, Bytes>")] [u8; 32],
);

#[serde_as]
#[derive(Serialize, Deserialize)]
struct DhSecretSerde(
    #[serde_as(as = "IfIsHumanReadable<Base64<UrlSafe, Unpadded>, Bytes>")] [u8; 32],
);

impl DhPublic {
    /// Build a public key from its 32-byte compressed form.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(x25519_dalek::PublicKey::from(bytes))
    }

    /// Serialize the public key as 32 bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub(crate) fn as_inner(&self) -> &x25519_dalek::PublicKey {
        &self.0
    }
}

impl fmt::Display for DhPublic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", encoding::encode_32_base64(self.to_bytes()))
    }
}

impl FromStr for DhPublic {
    type Err = ParseKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = encoding::decode_32_base64(s)?;
        Ok(DhPublic::from_bytes(bytes))
    }
}

impl Serialize for DhPublic {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        DhPublicSerde(self.to_bytes()).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for DhPublic {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let DhPublicSerde(bytes) = DhPublicSerde::deserialize(deserializer)?;
        Ok(DhPublic::from_bytes(bytes))
    }
}

impl DhSecret {
    /// Generate a random DH secret.
    pub fn random() -> Self {
        let mut rng = rand::thread_rng();
        Self(x25519_dalek::StaticSecret::random_from_rng(&mut rng))
    }

    /// Build a DH secret from 32 raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(x25519_dalek::StaticSecret::from(bytes))
    }

    /// Serialize the DH secret as 32 bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Derive the matching public key for this secret.
    pub fn public_key(&self) -> DhPublic {
        DhPublic(x25519_dalek::PublicKey::from(&self.0))
    }

    /// Perform Diffie-Hellman with a peer public key, returning the shared secret bytes.
    pub fn diffie_hellman(&self, peer: &DhPublic) -> Result<[u8; 32], DhError> {
        let ss = self.0.diffie_hellman(peer.as_inner()).to_bytes();
        if ss.ct_eq(&[0u8; 32]).unwrap_u8() == 1 {
            return Err(DhError::InvalidSharedSecret);
        }
        Ok(ss)
    }
}

impl fmt::Display for DhSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", encoding::encode_32_base64(self.to_bytes()))
    }
}

impl FromStr for DhSecret {
    type Err = ParseKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = encoding::decode_32_base64(s)?;
        Ok(DhSecret::from_bytes(bytes))
    }
}

fn triple_dh_key(dh1: [u8; 32], dh2: [u8; 32], dh3: [u8; 32]) -> [u8; 32] {
    let mut material = [0u8; 96];
    material[..32].copy_from_slice(&dh1);
    material[32..64].copy_from_slice(&dh2);
    material[64..].copy_from_slice(&dh3);

    Hash::digest(&material).to_bytes()
}

/// Derive a Triple-DH shared key from local and remote secrets/publics.
pub fn triple_dh(
    local_long_term: &DhSecret,
    local_ephemeral: &DhSecret,
    remote_long_term: &DhPublic,
    remote_ephemeral: &DhPublic,
) -> Result<[u8; 32], DhError> {
    let local_lt_pub = local_long_term.public_key();
    let local_eph_pub = local_ephemeral.public_key();

    let dh1 = local_long_term.diffie_hellman(remote_ephemeral)?;
    let dh2 = local_ephemeral.diffie_hellman(remote_long_term)?;
    let dh3 = local_ephemeral.diffie_hellman(remote_ephemeral)?;

    let local_id = (local_lt_pub.to_bytes(), local_eph_pub.to_bytes());
    let remote_id = (remote_long_term.to_bytes(), remote_ephemeral.to_bytes());
    let (first, second) = if local_id <= remote_id {
        (dh1, dh2)
    } else {
        (dh2, dh1)
    };

    Ok(triple_dh_key(first, second, dh3))
}

impl Serialize for DhSecret {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        DhSecretSerde(self.to_bytes()).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for DhSecret {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let DhSecretSerde(bytes) = DhSecretSerde::deserialize(deserializer)?;
        Ok(DhSecret::from_bytes(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::triple_dh;
    use super::{DhPublic, DhSecret};

    #[test]
    fn serde_json_round_trip_and_printing() {
        let secret = DhSecret::from_bytes([7u8; 32]);
        let public = secret.public_key();

        let secret_json = serde_json::to_string(&secret).expect("secret to json");
        let public_json = serde_json::to_string(&public).expect("public to json");

        let secret_val: serde_json::Value =
            serde_json::from_str(&secret_json).expect("secret json value");
        let public_val: serde_json::Value =
            serde_json::from_str(&public_json).expect("public json value");
        eprintln!("{:?}", secret_val);
        assert!(secret_val.is_string());
        assert!(public_val.is_string());

        let secret_back: DhSecret = serde_json::from_str(&secret_json).expect("secret from json");
        let public_back: DhPublic = serde_json::from_str(&public_json).expect("public from json");

        assert_eq!(secret.to_bytes(), secret_back.to_bytes());
        assert_eq!(public.to_bytes(), public_back.to_bytes());
    }

    #[test]
    fn triple_dh_is_symmetric() {
        let a_lt = DhSecret::from_bytes([1u8; 32]);
        let a_eph = DhSecret::from_bytes([2u8; 32]);
        let b_lt = DhSecret::from_bytes([3u8; 32]);
        let b_eph = DhSecret::from_bytes([4u8; 32]);

        let a_key =
            triple_dh(&a_lt, &a_eph, &b_lt.public_key(), &b_eph.public_key()).expect("a key");
        let b_key =
            triple_dh(&b_lt, &b_eph, &a_lt.public_key(), &a_eph.public_key()).expect("b key");

        assert_eq!(a_key, b_key);
    }

    #[test]
    fn dh_rejects_all_zero_shared_secret() {
        let secret = DhSecret::random();
        let low_order = DhPublic::from_bytes([0u8; 32]);
        assert!(secret.diffie_hellman(&low_order).is_err());
    }
}
