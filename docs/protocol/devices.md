# Devices

This document specifies device identity and device membership for usernames.

The directory itself is specified in [directory](directory.md). This document specifies how Nullspace uses that generic key/value registry to represent:

- username records (keys starting with `@`)
- server descriptors (keys starting with `~`)

## Primitives

A **device public key** is a long-lived Ed25519 signing public key (32 bytes).

A **device secret key** is the corresponding private key.

### Device hashes

Some server APIs index devices by a 32-byte hash:

```
device_hash = H(BCS(device_pk))
```

where `H` is BLAKE3 as defined in [directory](directory.md).

## Directory key conventions

The raw directory stores generic per-key state:

```
key_state = [nonce_max, owners, value]
```

Nullspace defines two namespaces:

- **username keys**: `@name` (for example `@user_01`)
- **server keys**: `~name` (for example `~serv_01`)

The directory does not enforce these namespaces. They are a client-side convention.

## Username record value

For username keys, `value` is the BCS encoding of:

```
user_descriptor = [server_name, devices]
```

- `server_name`: server identifier string like `~serv_01`
- `devices`: sorted unique set of device signing public keys

For username keys, `owners` MUST equal `devices`. This ensures every listed device can authorize the next username update at the raw directory layer.

There is no per-device `active` or expiry flag in the descriptor. A device is authorized exactly when its key is present in `devices`.

## Username updates

Nullspace uses direct raw directory updates for username changes. There is no separate typed action object.

To update a username:

1. Read current `key_state` and decode `user_descriptor` if present.
2. Mutate the descriptor (for example add/remove a device or set `server_name`).
3. Build and sign:

```
update = [username_key, nonce, signer_pk, owners, value, signature]
owners = next_descriptor.devices
value = BCS(next_descriptor)
signature = ed25519_sign(signer_sk, BCS([username_key, nonce, signer_pk, owners, value]))
```

4. Submit `update` using `v1_insert_update` from [directory](directory.md).

Validation is enforced by the raw directory:

- `nonce` must be strictly increasing
- for first write, signer must appear in `owners`
- otherwise, signer must be in current `owners`

### Common mutations

- **Bootstrap / bind server**: for a missing username, initialize `user_descriptor = [server_name, {signer_pk}]`.
- **Add device**: insert the new device public key into `devices`.
- **Remove device**: remove the device public key from `devices` (clients must not leave the set empty).
- **Rebind server**: replace `server_name`.

## Provisioning bundle

Provisioning transfers a new device secret plus a signed raw username update from an existing authorized device to the new device.

Bundle payload:

```
[new_device_secret, add_device_update]
```

where `add_device_update` is a raw update that:

- targets the expected `username_key`
- includes `new_device_pk` in `owners`/descriptor `devices`
- has `owners == next_descriptor.devices`

The new device verifies these properties, submits `add_device_update`, waits for commit, then authenticates to the bound server and publishes a medium-term key.

## Server authentication

Device authentication to a server is challenge/response:

1. client asks server for a challenge with `(username, device_pk)`
2. server checks that `device_pk` is in the current username descriptor and returns a short-lived challenge
3. client signs `[username, device_pk, challenge]` with the device secret
4. server verifies the signature and re-checks username membership
5. server returns/reuses an auth token bound to `(username, device_hash)`
