# Device certificates

This document describes device certificates and chains in a language-neutral way.

## Primitives

A **device public key** (DPK) is a long-lived Ed25519 signing public key for a device that stays stable for the lifetime of the device.

A **device secret key** (DSK) is the corresponding Ed25519 signing secret key for the device.

A **device certificate** is a BCS-encoded signed statement about a device public key with these fields:
- `pk`: the device public key being certified.
- `expiry`: a Unix timestamp after which the certificate is invalid.
- `can_issue`: whether this key is allowed to issue further device certificates.
- `signature`: Ed25519 signature over the BCS-encoded tuple `(pk, expiry, can_issue)` made by the issuer.

A **certificate chain** is a BCS-encoded struct with two fields:
- `ancestors`: an ordered list of certificates that lead from a trusted root to the issuer of `this`.
- `this`: the device certificate being authenticated.

The chain always contains at least one certificate because the `this` field is required. For a self-signed root device certificate, `ancestors` is empty and `this` is the root certificate.

## Verification rules

Given a trusted root public key hash:
- The chain must include a certificate whose public key hash matches the trusted root hash.
- The root certificate must be self-signed by its own public key.
- A non-expired certificate is accepted only if its signature verifies under a trusted signer.
- Any certificate with `can_issue = true` adds its public key to the trusted signer set.
- The `this` certificate must be non-expired and verifiable by a trusted signer.
- Expired certificates are ignored.
- Verification fails if no trusted root is found or if any remaining certificates cannot be verified.
