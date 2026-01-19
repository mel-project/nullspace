use anyhow::bail;
use serde::{Deserialize, Serialize};
use xirtam_crypt::{
    hash::{BcsHashExt, Hash},
    signing::{Signable, Signature, SigningPublic, SigningSecret},
};

use crate::timestamp::Timestamp;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
/// The identity public key of a device, that never changes throughout the lifetime of the device.
pub struct DevicePublic(pub SigningPublic);

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
/// The secret key material for a device.
pub struct DeviceSecret(pub SigningSecret);

impl DeviceSecret {
    /// Generate a new random device secret.
    pub fn random() -> Self {
        Self(SigningSecret::random())
    }
    /// Return the public identity for this device.
    pub fn public(&self) -> DevicePublic {
        DevicePublic(self.0.public_key())
    }

    /// Create a self-signed certificate for this device.
    pub fn self_signed(&self, expiry: Timestamp, can_issue: bool) -> DeviceCertificate {
        let pk = self.public();
        let mut cert = DeviceCertificate {
            pk,
            expiry,
            can_issue,
            signature: Signature::from_bytes([0u8; 64]),
        };
        cert.sign(&self.0);
        cert
    }

    /// Issue a certificate for another device public key.
    pub fn issue_certificate(
        &self,
        subject: &DevicePublic,
        expiry: Timestamp,
        can_issue: bool,
    ) -> DeviceCertificate {
        let mut cert = DeviceCertificate {
            pk: subject.clone(),
            expiry,
            can_issue,
            signature: Signature::from_bytes([0u8; 64]),
        };
        cert.sign(&self.0);
        cert
    }
}

impl DevicePublic {
    pub fn signing_public(&self) -> SigningPublic {
        self.0
    }
}

impl std::ops::Deref for DevicePublic {
    type Target = SigningPublic;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::Deref for DeviceSecret {
    type Target = SigningSecret;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
/// The certificate of a particular device, which includes the public key and the capabilities of the device.
pub struct DeviceCertificate {
    pub pk: DevicePublic,
    pub expiry: Timestamp,
    pub can_issue: bool,
    pub signature: Signature,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
/// A chain of certificates that authenticates a single device public key.
pub struct CertificateChain {
    pub ancestors: Vec<DeviceCertificate>,
    pub this: DeviceCertificate,
}

impl Signable for DeviceCertificate {
    fn signed_value(&self) -> Vec<u8> {
        bcs::to_bytes(&(&self.pk, &self.expiry, &self.can_issue))
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
    /// Return the device certificate authenticated by this chain.
    pub fn last_device(&self) -> &DeviceCertificate {
        &self.this
    }

    pub fn iter(&self) -> impl Iterator<Item = &DeviceCertificate> {
        self.ancestors.iter().chain(std::iter::once(&self.this))
    }

    /// Verify the chain against a trusted root public key hash.
    pub fn verify(&self, trusted_pk_hash: Hash) -> anyhow::Result<()> {
        let now = unix_time();
        let mut trusted_signers: Vec<SigningPublic> = Vec::new();
        let mut pending = self.ancestors.clone();
        pending.push(self.this.clone());
        let mut trusted_root_found = false;
        let mut this_verified = false;

        let mut idx = 0;
        while idx < pending.len() {
            if pending[idx].pk.bcs_hash() == trusted_pk_hash {
                let cert = pending.remove(idx);
                cert.verify(cert.pk.signing_public())
                    .map_err(|err| anyhow::anyhow!(err.to_string()))?;
                if cert.expiry > now {
                    trusted_root_found = true;
                    if cert.can_issue {
                        trusted_signers.push(cert.pk.signing_public());
                    }
                    if cert == self.this {
                        this_verified = true;
                    }
                }
            } else {
                idx += 1;
            }
        }

        if !trusted_root_found {
            bail!("certificate chain does not include trusted root");
        }

        let mut progress = true;
        while progress && !pending.is_empty() {
            progress = false;
            let mut i = 0;
            while i < pending.len() {
                let cert = &pending[i];
                if !trusted_signers.iter().any(|pk| cert.verify(*pk).is_ok()) {
                    i += 1;
                    continue;
                };
                let cert = pending.remove(i);
                if cert.expiry > now {
                    if cert.can_issue {
                        trusted_signers.push(cert.pk.signing_public());
                    }
                    if cert == self.this {
                        this_verified = true;
                    }
                }
                progress = true;
            }
        }

        if !pending.is_empty() {
            bail!("certificate chain contains unverifiable entries");
        }

        if !this_verified {
            bail!("certificate chain does not authenticate leaf device");
        }

        Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use xirtam_crypt::hash::BcsHashExt;

    #[test]
    fn verify_allows_root_without_issue_rights() {
        let root_secret = DeviceSecret::random();
        let root_cert = root_secret.self_signed(Timestamp(u64::MAX), false);
        let root_hash = root_cert.pk.bcs_hash();
        let chain = CertificateChain {
            ancestors: Vec::new(),
            this: root_cert.clone(),
        };

        chain.verify(root_hash).expect("verify root");
        assert_eq!(chain.last_device(), &root_cert);
    }

    #[test]
    fn verify_rejects_leaf_signed_by_non_issuer() {
        let root_secret = DeviceSecret::random();
        let root_cert = root_secret.self_signed(Timestamp(u64::MAX), true);
        let root_hash = root_cert.pk.bcs_hash();

        let intermediate_secret = DeviceSecret::random();
        let leaf_secret = DeviceSecret::random();

        let intermediate_cert = root_secret.issue_certificate(
            &intermediate_secret.public(),
            Timestamp(u64::MAX),
            false,
        );
        let leaf_cert = intermediate_secret.issue_certificate(
            &leaf_secret.public(),
            Timestamp(u64::MAX),
            true,
        );

        let chain = CertificateChain {
            ancestors: vec![root_cert, intermediate_cert],
            this: leaf_cert,
        };
        assert!(chain.verify(root_hash).is_err());
    }

    #[test]
    fn verify_allows_leaf_signed_by_issuer() {
        let root_secret = DeviceSecret::random();
        let root_cert = root_secret.self_signed(Timestamp(u64::MAX), true);
        let root_hash = root_cert.pk.bcs_hash();

        let intermediate_secret = DeviceSecret::random();
        let leaf_secret = DeviceSecret::random();

        let intermediate_cert = root_secret.issue_certificate(
            &intermediate_secret.public(),
            Timestamp(u64::MAX),
            true,
        );
        let leaf_cert = intermediate_secret.issue_certificate(
            &leaf_secret.public(),
            Timestamp(u64::MAX),
            true,
        );

        let chain = CertificateChain {
            ancestors: vec![root_cert, intermediate_cert],
            this: leaf_cert.clone(),
        };
        chain.verify(root_hash).expect("verify chain");
        assert_eq!(chain.last_device(), &leaf_cert);
    }
}
