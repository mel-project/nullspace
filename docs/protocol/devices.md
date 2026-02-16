# Devices

This document specifies device identity and device membership for usernames.

The directory itself is specified in [directory](directory.md). This document specifies how Nullspace uses that generic key/value registry to represent:

- username device lists (keys starting with `@`)
- server descriptors (keys starting with `~`)

## Primitives

A **device public key** is a long-lived Ed25519 signing public key (32 bytes).

A **device secret key** is the corresponding private key.

### Device hashes

Devices are indexed by a 32-byte hash:

```
device_hash = H(BCS(device_pk))
```

where `H` is BLAKE3 as defined in [directory](directory.md).

## Directory key conventions

The directory stores generic per-key state:

```
key_state = [nonce_max, owners, value]
```

Nullspace defines the following key namespaces:

- **username keys**: a username is stored under the key `@name` (for example `@user_01`)
- **server keys**: a server name is stored under the key `~name` (for example `~serv_01`)

The directory does not enforce these conventions. They are part of the Nullspace protocol.

## Username record value

For username keys, `value` is the BCS encoding of a **user descriptor**:

```
user_descriptor = [nonce_max, server_name_or_null, devices_map]
```

- `nonce_max`: unsigned integer (MUST equal the directory key state’s `nonce_max`)
- `server_name_or_null`: `null` or a server name string like `~serv_01`
- `devices_map`: map `device_hash -> device_state`

Each device entry is:

```
device_state = [device_pk, can_issue, expiry, active]
```

- `device_pk`: device signing public key (32 bytes)
- `can_issue`: boolean, whether this device may add/remove devices
- `expiry`: Unix timestamp in seconds
- `active`: boolean

### Owners list for username keys

For username keys, the directory key state’s `owners` list MUST be:

```
owners = sorted_unique([device_pk for each device_state where active == true])
```

This ensures that any active device key can authorize further username updates at the raw directory layer.

## Typed username actions

The raw directory update replaces the entire `key_state` (see [directory](directory.md)). Nullspace defines *typed* username actions that deterministically transform a `user_descriptor`, and then produces the corresponding raw directory update.

Typed actions are:

- add device: `["add_device", device_pk, can_issue, expiry]`
- remove device: `["remove_device", device_pk]`
- bind server: `["bind_server", server_name]`

### Typed validation rules

Given the current `user_descriptor` for `@name`:

- the signer device MUST exist in `devices_map`
- the signer device MUST be `active == true` and not expired
- add/remove device requires signer with `can_issue == true`
- for an uninitialized username (directory key absent), the first action MUST be add-device and MUST be self-signed (`signer_pk == device_pk`)
- the raw directory update nonce MUST be strictly increasing (gaps allowed)

### Applying actions

Pseudocode for the typed transition:

```
apply_user_action(descriptor_or_null, signer_pk, nonce, action):
    if descriptor_or_null is null:
        assert action is ["add_device", device_pk, can_issue, expiry]
        assert signer_pk == device_pk
        descriptor = [nonce, null, {}]
        insert device_state for device_pk with active=true
        return descriptor

    descriptor = descriptor_or_null
    assert signer_pk is active, non-expired device in descriptor

    if action is add/remove:
        assert signer_pk has can_issue=true

    if action is ["add_device", device_pk, can_issue, expiry]:
        set devices_map[H(BCS(device_pk))] = [device_pk, can_issue, expiry, true]

    if action is ["remove_device", device_pk]:
        set devices_map[H(BCS(device_pk))].active = false

    if action is ["bind_server", server_name]:
        set server_name_or_null = server_name

    set descriptor.nonce_max = nonce
    return descriptor
```

### Producing the raw directory update

Given `username_key = "@name"` and `next_descriptor = apply_user_action(...)`, produce a raw directory update:

```
owners = sorted_unique([device_pk in next_descriptor where active == true])
value  = BCS(next_descriptor)
update = [username_key, nonce, signer_pk, owners, value, signature]
signature = ed25519_sign(signer_sk, BCS([username_key, nonce, signer_pk, owners, value]))
```

and submit `update` using `v1_insert_update` from [directory](directory.md).

## Add-device provisioning bundle

Device provisioning can be implemented as a single bundle transfer from an existing authorized device to a new device.

The bundle producer constructs a **prepared add-device action** that the bundle receiver can submit to the directory.

A prepared action is:

```
prepared_action = [username_key, nonce, signer_pk, action, next_user_descriptor, signature]
```

where `signature` is the raw directory update signature implied by `next_user_descriptor`:

```
owners = sorted_unique([device_pk in next_user_descriptor where active == true])
value  = BCS(next_user_descriptor)
signature = ed25519_sign(signer_sk, BCS([username_key, nonce, signer_pk, owners, value]))
```

The directory does not accept `prepared_action` directly. The receiver converts it into a raw directory update and submits it using `v1_insert_update` (see [directory](directory.md)).

### Bundle producer (existing device)

```
make_bundle(existing_device, username_key, can_issue, expiry):
    descriptor = directory_get_user_descriptor(username_key)
    assert existing_device is active, non-expired, can_issue in descriptor

    new_device_secret = random_device_secret()
    nonce = choose_nonce_greater_than(descriptor.nonce_max)

    action = ["add_device", public(new_device_secret), can_issue, expiry]
    next_descriptor = apply_user_action(descriptor, public(existing_device), nonce, action)

    prepared = [username_key, nonce, public(existing_device), action, next_descriptor, signature]
    return encode([new_device_secret, prepared])
```

### Bundle receiver (new device)

```
consume_bundle(bundle):
    [new_device_secret, prepared] = decode(bundle)

    assert prepared.action is ["add_device", public(new_device_secret), _, _]
    directory_submit_prepared(prepared)
    wait_until_committed(prepared.username_key, prepared.nonce)

    descriptor = directory_get_user_descriptor(prepared.username_key)
    assert public(new_device_secret) is active in descriptor
    server_name = descriptor.server_name

    auth = server_auth_challenge(prepared.username_key, new_device_secret)
    publish_medium_key(auth, sign_medium_key(new_device_secret))
```

## Server authentication

Device authentication to a server is challenge/response:

1) client asks server for a challenge with `(username, device_pk)`
2) server checks directory membership and returns a short-lived challenge
3) client signs `[username, device_pk, challenge]` with the device key
4) server verifies signature and re-checks directory membership
5) server returns/reuses an auth token bound to `(username, device_hash)`

No certificate chain exchange is required.
