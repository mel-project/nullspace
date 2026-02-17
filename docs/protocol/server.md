# Server protocol spec

This document specifies the RPC API exposed by a Nullspace server.

Servers provide:

- mailboxes (direct messages and groups)
- device authentication (challenge/response) and medium-term key publication
- a content-addressed fragment store for attachments
- a short-lived multicast channel primitive (used by [device provisioning](provisioning.md))
- optional request proxying

Server RPC is JSON-RPC 2.0. Method names are versioned with a `v1_` prefix and use positional parameters.

## Encoding and primitives

### Binary encodings (JSON)

- 32-byte hashes: lowercase hex strings
- 20-byte auth tokens: lowercase hex strings
- Ed25519 public keys (32 bytes): URL-safe base64 without padding
- Ed25519 signatures (64 bytes): URL-safe base64 without padding
- X25519 public keys (32 bytes): URL-safe base64 without padding
- opaque bytes: URL-safe base64 without padding

Hashing uses BLAKE3 as defined in [directory](directory.md).

### Names

- username: string matching `^@[A-Za-z0-9_]{5,15}$`
- server name: string matching `^~[A-Za-z0-9_]{5,15}$`

### Timestamps

- seconds timestamps: Unix timestamp in seconds (unsigned integer)
- nanoseconds timestamps: Unix timestamp in nanoseconds (unsigned integer)

### Token hashes

Mailbox ACLs are keyed by:

```
token_hash = h(token_bytes)
```

where:

- `token_bytes` is the 20 raw bytes of the auth token
- `h(...)` is BLAKE3

The all-zero auth token is the **anonymous token**:

```
0000000000000000000000000000000000000000
```

### Blobs

Many server methods carry opaque payloads as a `blob`:

```
blob = { kind: string, inner: bytes }
```

- `kind`: string tag like `v1.direct_message` or `v1.group_message`
- `inner`: raw bytes (base64url)

`inner` is protocol payload bytes whose interpretation depends on `kind`. For message kinds and the BCS structures embedded in them, see [e2ee](e2ee.md), [events](events.md), and [groups](groups.md).

### Mailboxes

A mailbox is identified by a 32-byte `mailbox_id` (hex string).

#### Direct-message mailbox id

For a username `u` (including the leading `@`), the direct-message mailbox id is:

```
direct_mailbox_id(u) = h_keyed("direct-mailbox", utf8(u))
```

where:

```
h_keyed(domain, msg) = BLAKE3_KEYED(key = h(domain), msg = msg)
```

#### Group mailbox ids

Group mailbox ids are specified in [groups](groups.md).

### Mailbox entries

Mailbox receive returns `mailbox_entry` values:

```
mailbox_entry = { message, received_at, sender_auth_token_hash }
```

- `message`: `blob`
- `received_at`: server-assigned timestamp (nanoseconds), unique per mailbox
- `sender_auth_token_hash`: `token_hash` of the sender, or `null`

Clients use `received_at` as a mailbox cursor.

### Mailbox ACL entries

Mailbox ACLs are edited using:

```
mailbox_acl = { token_hash, can_edit_acl, can_send, can_recv }
```

ACL lookup for an `auth_token`:

1) If there is an entry for `h(auth_token_bytes)`, use it.
2) Otherwise, if there is an entry for `h(anonymous_token_bytes)`, use it.
3) Otherwise, treat permissions as all-false.

### Common errors

Methods that return a protocol error use one of:

- `access_denied`: permanent failure (auth/ACL/membership checks failed)
- `retry_later`: transient failure (clients should retry with backoff)

In JSON-RPC, the structured error value appears in the response error `data`.

## RPC methods

### `v1_multicast_allocate(auth_token) -> channel_id`

Allocates a short-lived multicast channel used for pairing-style flows (see [device provisioning](provisioning.md)).

Authorization:

- `auth_token` MUST be a valid device-authenticated token on this server (obtained from `v1_device_auth_finish`).

Returns:

- `channel_id`: a small, non-negative integer

Notes:

- Channels are ephemeral and may expire after a short period of inactivity.
- Channel IDs may be reused after expiration.

### `v1_multicast_post(channel_id, value) -> ()`

Writes a `blob` value into a multicast channel. If a value already exists, it is overwritten.

Authorization:

- The channel MUST exist (allocated and not yet expired).

Notes:

- This is intentionally unauthenticated; treat the channel contents as attacker-controlled unless protected by an end-to-end pairing protocol.

### `v1_multicast_poll(channel_id) -> value | null`

Returns the latest `blob` value written to the multicast channel.

Returns `null` if:

- no value has been posted yet, or
- the channel does not exist (expired or never allocated)

### `v1_device_auth_start(username, device_pk) -> challenge`

Starts challenge/response authentication for a device.

Inputs:

- `username`: username string
- `device_pk`: Ed25519 signing public key (base64url)

Validation:

- The server MUST check that `username` exists in the directory and is bound to this server.
- The server MUST check that `device_pk` is an active, non-expired device for `username` (see [devices](devices.md)).

Returns a `challenge` object:

```
challenge = { challenge, expires_at }
```

- `challenge`: a list of 32 integers in the range `0..=255` (one-time nonce bytes)
- `expires_at`: Unix timestamp (seconds)

### `v1_device_auth_finish(signed_request) -> auth_token`

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
- The server MUST verify that `challenge` was issued by `v1_device_auth_start` and has not expired.
- The server MUST re-check directory membership and server binding for `username` (see [devices](devices.md)).

Returns:

- `auth_token`: 20-byte auth token (hex)

Notes:

- Servers MAY reuse an existing token for the same `(username, device_pk)` rather than issuing a fresh one.
- Servers SHOULD ensure that the direct-message mailbox for `username` exists and is receivable by the returned `auth_token` (see “Mailboxes” methods).

### `v1_device_add_medium_pk(auth_token, signed_medium_pk) -> ()`

Stores a device’s medium-term public key (used by [e2ee](e2ee.md)).

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
- The server MUST verify `signed_medium_pk.signature` under the authenticated device’s signing public key.

Notes:

- The server stores the latest published medium-term key per device. Clients SHOULD refresh these keys periodically (see [e2ee](e2ee.md)).

### `v1_device_medium_pks(username) -> { device_hash: signed_medium_pk, ... }`

Returns medium-term public keys for devices associated with `username`.

Output:

- a JSON object mapping `device_hash` (hex) to `signed_medium_pk`

Notes:

- Servers MAY return a partial view (for example, only devices that have recently authenticated and published keys).
- Clients MUST validate returned keys by:
  - verifying the signature with the device signing key from the directory, and
  - using only active, non-expired devices from the directory (see [devices](devices.md)).

### `v1_profile(username) -> user_profile | null`

Fetches a user’s profile, if present.

Returns `null` if no profile is stored.

Otherwise returns:

```
user_profile = { display_name, avatar, created, signature }
```

- `display_name`: string or `null`
- `avatar`: attachment root object or `null` (see [attachments](attachments.md))
- `created`: Unix timestamp (seconds)
- `signature`: Ed25519 signature (base64url)

Clients SHOULD verify the signature with a currently active device key for `username` (see [devices](devices.md)).

### `v1_profile_set(username, user_profile) -> ()`

Stores a user profile for `username`.

Authorization and validation:

- The server MUST check that `username` exists in the directory and is bound to this server.
- The server MUST verify `user_profile.signature` under at least one active, non-expired device key for `username`.
- The server MUST reject updates where `user_profile.created` is not strictly greater than the stored profile’s `created`.

### `v1_mailbox_send(auth_token, mailbox_id, message, ttl_seconds) -> received_at`

Appends a message into a mailbox.

Inputs:

- `auth_token`: auth token (hex)
- `mailbox_id`: 32-byte mailbox id (hex)
- `message`: `blob`
- `ttl_seconds`: unsigned integer; `0` means “no expiry”

Authorization:

- The server MUST resolve mailbox permissions using the ACL rules above and require `can_send == true`.

Returns:

- `received_at`: server-assigned timestamp (nanoseconds), unique per mailbox

Notes:

- The stored mailbox entry includes `sender_auth_token_hash = h(auth_token_bytes)`.
- Servers commonly grant `can_send` to the anonymous token for direct-message mailboxes so that anyone can deliver a DM, but this is a server policy choice.

### `v1_mailbox_multirecv(args, timeout_ms) -> { mailbox_id: [mailbox_entry, ...], ... }`

Receives one or more messages from one or more mailboxes. This call is intended for long-polling across multiple mailboxes efficiently.

Inputs:

```
args = [ { auth_token, mailbox_id, after }, ... ]
```

- `after`: mailbox cursor (nanoseconds). Only entries with `received_at > after` are eligible.
- `timeout_ms`: maximum time to wait

Authorization:

- For each mailbox, the server MUST resolve mailbox permissions using the ACL rules above and require `can_recv == true`.
- Clients MUST only include mailboxes they are authorized to receive from; otherwise the call may fail with `access_denied`.

Return value:

- empty map if the timeout elapses without any eligible messages
- otherwise a map containing one or more mailboxes, each with a list of `mailbox_entry` values

Notes:

- The server MAY return only a subset of the requested mailboxes (including just one) to implement “first mailbox that becomes ready” semantics.
- The server MAY cap the number of returned entries per mailbox. Clients should repeat calls, advancing `after` to the last returned `received_at`.

### `v1_mailbox_acl_edit(auth_token, mailbox_id, acl) -> ()`

Edits the mailbox ACL entry for a specific `token_hash`.

Inputs:

- `auth_token`: auth token used as the caller capability
- `mailbox_id`: 32-byte mailbox id (hex)
- `acl`: `mailbox_acl` object

Authorization:

- If the caller’s effective ACL has `can_edit_acl == true`, the edit is permitted.
- Otherwise, the edit is permitted only if:
  - there is no existing ACL entry for `acl.token_hash`, and
  - the requested permissions are a subset of the caller’s effective permissions.

Self-removal:

- If `acl.token_hash == h(auth_token_bytes)` and all requested permissions are false, the server SHOULD delete the ACL entry for that token hash.

### `v1_register_group(auth_token, group_id) -> ()`

Creates the group mailboxes for `group_id` and grants the caller full ACL rights to both.

Authorization:

- `auth_token` MUST be a valid device-authenticated token.

Effect:

- Ensures that the group messages and management mailboxes exist (see [groups](groups.md)).
- Inserts/updates an ACL entry for `h(auth_token_bytes)` on both mailboxes with:
  - `can_edit_acl = true`
  - `can_send = true`
  - `can_recv = true`

### `v1_upload_frag(auth_token, fragment, ttl_seconds) -> ()`

Uploads a fragment into the content-addressed store (see [attachments](attachments.md)).

Inputs:

- `fragment`: a JSON tagged value, either `{"node":{...}}` or `{"leaf":{...}}` (see [attachments](attachments.md))
- `ttl_seconds`: unsigned integer; `0` means “no expiry”

Authorization:

- `auth_token` MUST be a valid device-authenticated token.

Effect:

- Stores the fragment under its content hash:

```
fragment_id = h(BCS(fragment))
```

- If the fragment already exists, the server MAY extend its expiry but MUST NOT shorten it.

### `v1_download_frag(fragment_id) -> fragment | null`

Downloads a fragment by content hash.

Returns `null` if the fragment does not exist (expired or never uploaded).

This method is intentionally unauthenticated.

### `v1_proxy_server(auth_token, server_name, req) -> resp`

Proxies a raw JSON-RPC request to another server.

Authorization:

- `auth_token` MUST be a valid device-authenticated token.
- Proxying is optional; servers that do not support it return `not_supported`.

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

### `v1_proxy_directory(auth_token, req) -> resp`

Proxies a raw JSON-RPC request to the directory.

Authorization and errors are the same as `v1_proxy_server`.
