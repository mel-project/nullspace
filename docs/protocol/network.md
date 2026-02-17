# Network architecture

## Participants

There are three kinds of participants in the protocol: **clients**, **servers**, and the **directory**.

### Clients

Clients are end-user devices. They:
- hold long-lived device signing keys
- talk to servers for mailbox access and medium-term key publication
- talk to the directory for username resolution, device authorization checks, and server resolution

Plaintext exists only on clients. Servers and the directory only see routing metadata, signatures, and encrypted payloads.

### Servers

Servers are untrusted concierge infrastructure.

Servers:
- host mailboxes (DM, group message, group management)
- enforce ACLs using auth tokens
- publish medium-term public keys for each authenticated device
- proxy requests to other servers or to the directory (optional)

Servers do **not** define identity membership. Device membership is validated against directory state.

### Directory service

The directory is the root of trust, but its raw protocol is intentionally generic.
See [directory](directory.md) for the raw directory specification and RPC API.

Each key in the directory is an arbitrary string, and each key stores:
- `nonce_max`
- `owners` (set of signing public keys allowed to edit this key)
- `value` (opaque bytes)

Each raw update is:

```
[key, nonce, signer_pk, owners, value, signature]
```

Rules at the raw directory layer:
- signature must verify under `signer_pk`
- nonce must be strictly increasing
- signer must already be in the current `owners` set (except first write, where signer must be included in new `owners`)

The directory keeps pending per-key updates in a mempool between chunk commits, so multiple updates can be accepted without waiting for separate chunk intervals.

User/server semantics are a client-side convention:
- keys starting with `@` are treated as user records
- keys starting with `~` are treated as server records
- this typed interpretation lives in [devices](devices.md) flows and directory client logic, not in the raw directory protocol

## Transparency and proofs

The directory still exposes blockchain-like synchronization:
- signed anchor
- header chain
- chunk stream
- inclusion proofs

The sparse Merkle tree commits to **current key state** (`[nonce_max, owners, value]`) only, not per-key history. Chunks carry raw updates for replay/audit.

## Identity model

- **Username**: user identifier like `@user_01` (stored under a key starting with `@`).
- **Server name**: server identifier like `~serv_01` (stored under a key starting with `~`).
- **User descriptor value**: `[server_name, devices]`.
- **Server descriptor value**: `[public_urls, server_pk]`.

Clients resolve usernames/servers from directory values and validate device keys from those values when verifying signed payloads.
