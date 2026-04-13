# Server RPC

This document specifies the RPC API exposed by a Nullspace server.

Servers provide:

- mailboxes (direct messages and groups)
- group registry storage for group key rotation state
- device authentication (challenge/response) and medium-term key publication
- a content-addressed fragment store for attachments
- a short-lived bidirectional channel primitive (used by [device provisioning](../protocol/provisioning.md))
- optional request proxying

For wire format, encoding conventions, and transport, see [basic concepts](basic-concepts.md).

## Server-specific primitives

### Blobs

Server methods that carry opaque payloads use a `blob`: raw bytes (base64url in JSON). The interpretation of blob contents depends on context — see [e2ee](../protocol/e2ee.md), [events](../protocol/events.md), and [groups](../protocol/groups.md).

### Mailboxes

A mailbox is identified by a 32-byte `mailbox_id`.

Mailbox access is key-based:
- A `mailbox_key` is a 20-byte secret. Possession of the key grants read access.
- The `mailbox_id` is derived from the key: `mailbox_id = h_keyed("nullspace-mailbox", mailbox_key_bytes)`.
- Sending to a mailbox requires only the `mailbox_id` (unauthenticated — anyone who knows the ID can send).
- There are no ACLs or token-based permissions on mailboxes.

#### DM mailboxes

Each user advertises a DM mailbox in their [profile](#profileusername---user_profile--null). The `mailbox_id` is included in the signed profile. Senders look up the recipient's profile to discover where to deliver DMs.

#### Group mailboxes

Group mailbox keys are derived from the [group bearer key](../protocol/groups.md#group-bearer-key-gbk). Each GBK rotation produces a new mailbox.

### Mailbox entries

Mailbox receive returns `mailbox_entry` values:

```
mailbox_entry = { body, received_at }
```

- `body`: `blob`
- `received_at`: server-assigned timestamp (nanoseconds), unique per mailbox

Clients use `received_at` as a mailbox cursor.

## Methods

### `chan_allocate(auth_token) -> channel_id`

Allocates a short-lived bidirectional channel used for pairing-style flows (see [device provisioning](../protocol/provisioning.md)).

Authorization:

- `auth_token` MUST be a valid device-authenticated token on this server (obtained from `device_auth_finish`).

Returns:

- `channel_id`: a small, non-negative integer

Notes:

- Channels are ephemeral and may expire after a short period of inactivity.
- Channel IDs may be reused after expiration.

### `chan_send(channel_id, direction, value) -> ()`

Writes a `blob` value into one direction of a channel. If a value already exists in that direction, it is overwritten.

Authorization:

- The channel MUST exist (allocated and not yet expired).
- `direction` MUST be either `forward` or `backward`.

Notes:

- This is intentionally unauthenticated; treat the channel contents as attacker-controlled unless protected by an end-to-end pairing protocol.

### `chan_recv(channel_id, direction) -> value | null`

Returns the latest `blob` value written to the requested channel direction.

Returns `null` if:

- no value has been posted yet, or
- the channel does not exist (expired or never allocated)

### `device_auth_start(username, device_pk) -> challenge`

Starts challenge/response authentication for a device.

Inputs:

- `username`: username string
- `device_pk`: Ed25519 signing public key (base64url)

Validation:

- The server MUST check that `username` exists in the directory and is bound to this server.
- The server MUST check that `device_pk` appears in the current device set for `username` (see [devices](../protocol/devices.md)).

Returns a `challenge` object:

```
challenge = { challenge, expires_at }
```

- `challenge`: a list of 32 integers in the range `0..=255` (one-time nonce bytes)
- `expires_at`: Unix timestamp (seconds)

### `device_auth_finish(signed_request) -> auth_token`

Finishes challenge/response authentication and returns an auth token.

Input:

```
signed_request = { request, signature }
request = { username, device_pk, challenge }
```

- `signature` is an Ed25519 signature (base64url) over:

```
BCS([username, device_pk, challenge])
```

Validation:

- The server MUST verify `signature` under `device_pk`.
- The server MUST verify that `challenge` was issued by `device_auth_start` and has not expired.
- The server MUST re-check directory membership and server binding for `username` (see [devices](../protocol/devices.md)).

Returns:

- `auth_token`: 20-byte auth token (hex)

Notes:

- Servers MAY reuse an existing token for the same `(username, device_pk)` rather than issuing a fresh one.

### `device_add_medium_pk(auth_token, signed_medium_pk) -> ()`

Stores a device's medium-term public key (used by [e2ee](../protocol/e2ee.md)).

Input:

```
signed_medium_pk = { medium_pk, created, signature }
```

- `medium_pk`: X25519 public key (base64url)
- `created`: Unix timestamp (seconds)
- `signature`: Ed25519 signature (base64url) over:

```
BCS([medium_pk, created])
```

Authorization:

- `auth_token` MUST be a valid device-authenticated token.
- The server MUST verify `signed_medium_pk.signature` under the authenticated device's signing public key.

Notes:

- The server stores the latest published medium-term key per device. Clients SHOULD refresh these keys periodically (see [e2ee](../protocol/e2ee.md)).

### `device_medium_pks(username) -> { device_hash: signed_medium_pk, ... }`

Returns medium-term public keys for devices associated with `username`.

Output:

- a JSON object mapping `device_hash` (hex) to `signed_medium_pk`

Notes:

- Servers MAY return a partial view (for example, only devices that have recently authenticated and published keys).
- Clients MUST validate returned keys by:
  - verifying the signature with the device signing key from the directory, and
  - using only devices present in the current directory descriptor (see [devices](../protocol/devices.md)).

### `profile(username) -> user_profile | null`

Fetches a user's profile, if present.

Returns `null` if no profile is stored.

Otherwise returns:

```
user_profile = { display_name, avatar, dm_mailbox, created, signature }
```

- `display_name`: string or `null`
- `avatar`: image attachment object or `null` (see [attachments](../protocol/attachments.md))
- `dm_mailbox`: the `mailbox_id` where DMs for this user should be delivered
- `created`: Unix timestamp (seconds)
- `signature`: Ed25519 signature (base64url)

Clients SHOULD verify the signature with a device key currently listed for `username` (see [devices](../protocol/devices.md)).

### `profile_set(username, user_profile) -> ()`

Stores a user profile for `username`.

Authorization and validation:

- The server MUST check that `username` exists in the directory and is bound to this server.
- The server MUST verify `user_profile.signature` under at least one currently listed device key for `username`.
- The server MUST reject updates where `user_profile.created` is not strictly greater than the stored profile's `created`.

### `mailbox_send(mailbox_id, message, ttl_seconds) -> received_at`

Appends a message into a mailbox.

Inputs:

- `mailbox_id`: 32-byte mailbox id (hex)
- `message`: `blob`
- `ttl_seconds`: unsigned integer; `0` means "no expiry"

Authorization:

- This method is unauthenticated. Anyone who knows the `mailbox_id` can send to it.

Returns:

- `received_at`: server-assigned timestamp (nanoseconds), unique per mailbox

### `mailbox_create(auth_token, mailbox_key) -> mailbox_id`

Creates a mailbox owned by the authenticated user, or returns the existing `mailbox_id` if the mailbox already exists.

Inputs:

- `auth_token`: a valid device-authenticated token
- `mailbox_key`: 20-byte mailbox key

Returns:

- `mailbox_id`: the 32-byte mailbox id derived from `mailbox_key`

Notes:

- The `mailbox_key` is the read credential for the mailbox. It is included in `mailbox_multirecv` args to prove read access.

### `mailbox_multirecv(args, timeout_ms) -> { mailbox_id: [mailbox_entry, ...], ... }`

Receives one or more messages from one or more mailboxes. This call is intended for long-polling across multiple mailboxes efficiently.

Inputs:

```
args = [ { mailbox, mailbox_key, after }, ... ]
```

- `mailbox`: the `mailbox_id` to poll
- `mailbox_key`: the 20-byte key proving read access
- `after`: mailbox cursor (nanoseconds). Only entries with `received_at > after` are eligible.
- `timeout_ms`: maximum time to wait

Authorization:

- For each mailbox, the server MUST verify that `h_keyed("nullspace-mailbox", mailbox_key_bytes)` equals the provided `mailbox_id`.

Return value:

- empty map if the timeout elapses without any eligible messages
- otherwise a map containing one or more mailboxes, each with a list of `mailbox_entry` values

Notes:

- The server MAY return only a subset of the requested mailboxes (including just one) to implement "first mailbox that becomes ready" semantics.
- The server MAY cap the number of returned entries per mailbox. Clients should repeat calls, advancing `after` to the last returned `received_at`.

### `group_create(auth_token, rotation) -> ()`

Creates a new group registry with the provided rotation as the initial entry.

Inputs:

- `auth_token`: a valid device-authenticated token
- `rotation`: a signed [group rotation entry](../protocol/groups.md#group-rotation-registry)

Authorization and validation:

- `auth_token` MUST be a valid device-authenticated token.
- `rotation.prev_hash` MUST be `null` (no predecessor for the first entry).
- `rotation.signer` MUST match the authenticated device.
- `rotation.signer` MUST be in `rotation.new_admin_set`.
- `rotation.new_admin_set` MUST be non-empty.
- `rotation.signature` MUST verify under `rotation.signer`.

Effect:

- Creates a new group registry keyed by `rotation.group_id`, storing the rotation at index 0.

### `group_update(rotation) -> ()`

Appends the next rotation entry to a group registry.

Input:

- `rotation`: a signed [group rotation entry](../protocol/groups.md#group-rotation-registry)

Validation:

- `rotation.prev_hash` MUST be non-null.
- `rotation.new_admin_set` MUST be non-empty.
- `rotation.signer` MUST be in the previous entry's `new_admin_set`.
- `rotation.signature` MUST verify under `rotation.signer`.

Effect:

- Appends the entry at the next sequential index.
- The previous entry's `new_admin_set` becomes the authorized set for the following update.

Notes:

- This method does not require an `auth_token`. The rotation's signature, validated against the previous admin set, serves as authorization.
- The current server implementation does not verify that `rotation.prev_hash` matches the stored head hash; clients must still validate the hash chain when reading rotations.

### `group_get(group_id, index) -> rotation | null`

Returns the rotation entry at `index` for the group identified by `group_id`.

Returns `null` if:

- no registry exists for `group_id`, or
- no entry exists at `index`

This method is intentionally unauthenticated and stateless so it can be cached aggressively.

### `frag_upload(auth_token, fragment, ttl_seconds) -> ()`

Uploads a fragment into the content-addressed store (see [attachments](../protocol/attachments.md)).

Inputs:

- `fragment`: a JSON tagged value, either `{"node":{...}}` or `{"leaf":{...}}` (see [attachments](../protocol/attachments.md))
- `ttl_seconds`: unsigned integer; `0` means "no expiry"

Authorization:

- `auth_token` MUST be a valid device-authenticated token.

Effect:

- Stores the fragment under its content hash:

```
fragment_id = H(BCS(fragment))
```

- If the fragment already exists, the server MAY extend its expiry but MUST NOT shorten it.

### `frag_download(fragment_id) -> fragment | null`

Downloads a fragment by content hash.

Returns `null` if the fragment does not exist (expired or never uploaded).

This method is intentionally unauthenticated.

### `proxy_server(auth_token, server_name, req) -> resp`

Proxies a raw JSON-RPC request to another server.

Authorization:

- `auth_token` MUST be a valid device-authenticated token.
- Proxying is optional; if proxying is disabled, or if the auth token is invalid, the server returns `not_supported`.

Inputs:

- `server_name`: server name string
- `req`: a JSON-RPC request object:

```
req = { jsonrpc: "2.0", method: string, params: [ ... ], id: string|number }
```

Returns:

- `resp`: a JSON-RPC response object from the upstream server.

Errors:

- `not_supported`
- `{"upstream": "..."}` (string message)

### `proxy_directory(auth_token, req) -> resp`

Proxies a raw JSON-RPC request to the directory.

Authorization:

- `auth_token` MUST be a valid device-authenticated token.
- If the auth token is invalid, the server returns `not_supported`.

Errors are otherwise the same as `proxy_server`.
