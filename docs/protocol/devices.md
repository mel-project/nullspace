# Devices

## Primitives

A **device public key** (DPK) is a long-lived Ed25519 signing public key for one device.

A **device secret key** (DSK) is the corresponding private key.

At the raw directory layer, each key stores:

```
[nonce_max, owners, value]
```

For username keys (`@...`), the value is interpreted as a user descriptor:

```
[nonce_max, server_name_or_none, devices_map]
```

where `devices_map` is keyed by `hash(bcs_encode(device_pk))` and each device entry is:

```
[device_pk, can_issue, expiry, active]
```

- `device_pk`: device signing public key
- `can_issue`: whether this device can add/remove devices
- `expiry`: Unix timestamp after which this device cannot authorize typed user actions
- `active`: whether this device is currently enabled

## Typed username actions

The raw directory is untyped. Username semantics are implemented by directory client logic.

Typed username actions are:
- add device: `["add_device", device_pk, can_issue, expiry]`
- remove device: `["remove_device", device_pk]`
- bind server: `["bind_server", server_name]`

A prepared username action carries:

```
[nonce, signer_pk, action, next_user_descriptor, signature]
```

The signature is checked against the raw update tuple derived from `next_user_descriptor`:

```
[nonce, signer_pk, owners(next_user_descriptor), bcs(next_user_descriptor)]
```

where `owners(next_user_descriptor)` is the sorted unique list of active device public keys.

Typed validation rules:
- signer must be active and non-expired in current user descriptor
- add/remove device require signer with `can_issue = true`
- for an uninitialized username, the first action must be self-signed add-device
- nonce must be strictly greater than current nonce floor

## Mempool and nonce behavior

The directory accepts raw updates into a per-key mempool before chunk commit.

Nonce policy at the raw layer:
- new nonce must be greater than committed nonce and any accepted pending nonce for that key
- nonces can skip values

To support multi-step flows without waiting for chunk commit, the directory client keeps a local pending overlay for keys it has updated. This allows generating subsequent typed actions against the latest locally accepted state.

At commit time, updates for each key are applied in nonce order and the SMT leaf is replaced by the resulting key state.

## Add-device flow

### Bundle producer (existing device)

The existing device creates a bundle for the new device that contains:

- `username`
- a newly generated `new_device_secret`
- a prepared add-device action

Pseudocode:

```
make_bundle(existing_device, username, can_issue, expiry):
    descriptor = directory_get_user_descriptor(username)
    assert existing_device is active, non-expired, can_issue in descriptor

    new_device_secret = random_device_secret()
    nonce = choose_nonce_greater_than(descriptor.nonce_max)

    action = ["add_device", public(new_device_secret), can_issue, expiry]
    next_descriptor = apply_typed_action(descriptor, action, signer=public(existing_device), nonce)

    signature = sign(
        existing_device,
        bcs_encode([
            nonce,
            public(existing_device),
            owners(next_descriptor),
            bcs_encode(next_descriptor)
        ])
    )

    prepared = [nonce, public(existing_device), action, next_descriptor, signature]
    return encode([username, new_device_secret, prepared])
```

### Bundle receiver (new device)

The new device submits the bundled prepared action through the directory client, then authenticates to the bound server.

```
consume_bundle(bundle):
    [username, new_device_secret, prepared] = decode(bundle)

    dirclient_submit_prepared_user_action(username, prepared)
    wait_until_committed(username, prepared.nonce)

    descriptor = directory_get_user_descriptor(username)
    assert public(new_device_secret) is active in descriptor
    server_name = descriptor.server_name

    auth = server_auth_challenge(username, new_device_secret)
    publish_medium_key(auth, sign_medium_key(new_device_secret))
```

## Server authentication

Device authentication is challenge/response:

1) client asks server for challenge with `(username, device_pk)`
2) server checks directory state membership and returns a short-lived challenge
3) client signs `[username, device_pk, challenge]` with the device key
4) server verifies signature and re-checks directory state
5) server returns/reuses an auth token bound to `(username, device_hash)`

No certificate chain exchange is required.
