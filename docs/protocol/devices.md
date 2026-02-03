# Devices

## Primitives

A **device public key** (DPK) is a long-lived Ed25519 signing public key for a device that stays stable for the lifetime of the device.

A **device secret key** (DSK) is the corresponding Ed25519 signing secret key for the device.

A **device certificate** is BCS-encoded as:

```
[pk, expiry, can_issue, signature]
```

- `pk`: the device public key being certified
- `expiry`: a Unix timestamp after which the certificate is invalid
- `can_issue`: whether this key is allowed to issue further device certificates
- `signature`: an Ed25519 signature (by the issuer) over `bcs_encode([pk, expiry, can_issue])`

A **certificate chain** is BCS-encoded as:

```
[ancestors, this]
```

- `ancestors`: an ordered list of certificates that lead from a trusted root certificate to the issuer of `this`
- `this`: the device certificate being authenticated

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

## Adding a device

### "Proper" flow

To add a new device to an existing username, an already-authorized device issues a device certificate for the new device public key, and the new device publishes its updated certificate chain.

1) **New device generates keys**
   - Generate a fresh device signing keypair `(new_dsk, new_dpk)`.

2) **New device asks an authorized issuer to certify it**
   - The issuer is any existing device whose certificate is valid and has `can_issue = true` (often the root device).
   - The request should be authenticated out-of-band (for example, by scanning a QR code) and should include `new_dpk` and the requested `expiry` and `can_issue` policy.

3) **Issuer creates a device certificate**
   - The issuer signs `bcs_encode([new_dpk, expiry, can_issue])` with its device secret key, producing `signature`.
   - The resulting certificate is `new_cert = [new_dpk, expiry, can_issue, signature]`.

4) **Issuer constructs the new device's certificate chain**
   - If `issuer_chain = [ancestors, issuer_cert]`, then the new chain is:

```
issue_device_cert(issuer_dsk, new_dpk, expiry, can_issue):
    payload = [new_dpk, expiry, can_issue]
    signature = ed25519_sign(issuer_dsk, bcs_encode(payload))
    return [new_dpk, expiry, can_issue, signature]

extend_chain(issuer_chain, new_cert):
    [ancestors, issuer_cert] = issuer_chain
    return [ancestors + [issuer_cert], new_cert]
```

5) **New device publishes its chain**
   - The new device uploads its certificate chain to its current server so that other clients can fetch and verify it.
   - No directory update is required as long as the trusted root public key hash for the username is unchanged.

### In practice

A client may implement adding a device as a **single transfer** from an existing device to the new device.

Instead of having the new device generate a keypair and send only its public key to the issuer, the existing device generates a complete **device bundle** that contains everything the new device needs to become a fully functional device:

- the username
- a freshly generated device signing secret key (so the new device can authenticate as that device)
- a certificate chain for the corresponding public key, issued by the existing device, with the chosen `expiry` and `can_issue` settings

This bundle is encoded as opaque bytes for the UI to transfer (typically as a single QR code, or as copy/paste text). The UI does not need to understand any of the contents.

On the new device, the client:

1) decodes the bundle
2) looks up the user descriptor in the directory to obtain the trusted root public key hash and the current server name
3) verifies the bundled certificate chain against that trusted root
4) authenticates to the server using the bundled certificate chain (which also causes the server to start serving that chain for this device)
5) generates fresh medium-term Diffie-Hellman keys locally and registers the public key on the server, signed by the bundled device signing key

The device bundle contains a device signing secret key, so it must be transferred over a confidential, in-person channel (QR on a trusted screen, etc).
