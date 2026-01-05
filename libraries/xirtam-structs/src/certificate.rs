use anyhow::bail;
use serde::{Deserialize, Serialize};
use xirtam_crypt::{
    dh::{DhPublic, DhSecret},
    hash::{BcsHashExt, Hash},
    signing::{Signable, Signature, SigningPublic, SigningSecret},
};

use crate::timestamp::Timestamp;

#[derive(Clone, Debug, Serialize, Deserialize)]
/// The identity public key of a device, that never changes throughout the lifetime of the device.
pub struct DevicePublic {
    pub sign_pk: SigningPublic,
    pub long_pk: DhPublic,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
/// The secret key material for a device.
pub struct DeviceSecret {
    pub sign_sk: SigningSecret,
    pub long_sk: DhSecret,
}

impl DeviceSecret {
    /// Return the public identity for this device.
    pub fn public(&self) -> DevicePublic {
        DevicePublic {
            sign_pk: self.sign_sk.public_key(),
            long_pk: self.long_sk.public_key(),
        }
    }

    /// Create a self-signed certificate for this device.
    pub fn self_signed(&self, expiry: Timestamp, can_sign: bool) -> DeviceCertificate {
        let pk = self.public();
        let signed_by = pk.sign_pk.bcs_hash();
        let mut cert = DeviceCertificate {
            pk,
            signed_by,
            expiry,
            can_sign,
            signature: Signature::from_bytes([0u8; 64]),
        };
        cert.sign(&self.sign_sk);
        cert
    }

    /// Issue a certificate for another device public key.
    pub fn issue_certificate(
        &self,
        subject: &DevicePublic,
        expiry: Timestamp,
        can_sign: bool,
    ) -> DeviceCertificate {
        let signed_by = self.sign_sk.public_key().bcs_hash();
        let mut cert = DeviceCertificate {
            pk: subject.clone(),
            signed_by,
            expiry,
            can_sign,
            signature: Signature::from_bytes([0u8; 64]),
        };
        cert.sign(&self.sign_sk);
        cert
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
/// The certificate of a particular device, which includes the public key and the capabilities of the device.
pub struct DeviceCertificate {
    pub pk: DevicePublic,
    pub signed_by: Hash,
    pub expiry: Timestamp,
    pub can_sign: bool,
    pub signature: Signature,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
/// A chain a certificates that ultimately represents a set of authorized devices.
pub struct CertificateChain(pub Vec<DeviceCertificate>);

impl Signable for DeviceCertificate {
    fn signed_value(&self) -> Vec<u8> {
        bcs::to_bytes(&(&self.pk, &self.signed_by, &self.expiry, &self.can_sign))
            .expect("bcs serialization failed")
    }

    fn signature_mut(&mut self) -> &mut Signature {
        &mut self.signature
    }

    fn signature(&self) -> &Signature {
        &self.signature
    }
}

impl CertificateChain {
    /// Verify the chain and return the non-expired certificates.
    pub fn verify(&self, trusted_pk_hash: Hash) -> anyhow::Result<Vec<DeviceCertificate>> {
        let now = unix_time();
        let mut trusted_signers: Vec<(Hash, SigningPublic)> = Vec::new();
        let mut valid = Vec::new();

        for (idx, cert) in self.0.iter().enumerate() {
            let signer = trusted_signers
                .iter()
                .find(|(hash, _)| *hash == cert.signed_by)
                .map(|(_, pk)| *pk);

            let signer = match signer {
                Some(pk) => pk,
                None if cert.signed_by == trusted_pk_hash => {
                    let cert_hash = cert.pk.sign_pk.bcs_hash();
                    if cert_hash != trusted_pk_hash {
                        bail!("certificate {} signed by unknown trusted key", idx);
                    }
                    cert.pk.sign_pk
                }
                None => bail!("certificate {} signed by unknown key", idx),
            };

            cert.verify(signer)
                .map_err(|err| anyhow::anyhow!(err.to_string()))?;

            if cert.expiry > now {
                trusted_signers.push((cert.pk.sign_pk.bcs_hash(), cert.pk.sign_pk));
                valid.push(cert.clone());
            }
        }

        Ok(valid)
    }
}

fn unix_time() -> Timestamp {
    use std::time::{SystemTime, UNIX_EPOCH};
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    Timestamp(seconds)
}
