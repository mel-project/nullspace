# Device provisioning

New devices are provisioned with a short out-of-band pairing code and a SPAKE exchange over a server bidirectional channel.

```mermaid
sequenceDiagram
  autonumber
  participant U as User
  participant B as Device B (new)
  participant A as Device A (existing)

  U->>B: Enter username
  U->>A: Open "Add device"
  A-->>U: Show pairing code
  U->>B: Enter pairing code
  B-->>U: Provisioning completes
```

## Bidirectional channel transport

Provisioning uses server channel RPCs from [server](server.md):

- `v1_chan_allocate(auth_token) -> channel_id`
- `v1_chan_send(channel_id, direction, blob) -> ()`
- `v1_chan_recv(channel_id, direction) -> blob | null`

Channel contents are unauthenticated. The SPAKE exchange and AEAD payload protect integrity and confidentiality.

Direction convention for provisioning:

- `forward` means A -> B
- `backward` means B -> A

## Pairing code

Device A allocates `channel_id`, generates a random 32-bit `token`, and encodes `(channel_id, token)` into a single unsigned integer `code`.

Encoding:

1. Start with bit `1`.
2. Append Elias-delta coding of `(channel_id + 1)`.
3. Append the full 32 bits of `token`.

If this bitstring exceeds 64 bits, provisioning must fail and A must retry with a new channel.

User-facing code strings may include separators (for example spaces or dashes), but decoding must recover the same integer `code`.

## SPAKE handshake

Both devices initialize SPAKE with:

- password: decimal string form of `code`
- identity: username string (for example `@alice`)

Message flow on the bidirectional channel:

1. A sends `v1.provision_helo` on `forward`.
2. B polls `forward` until it receives `v1.provision_helo`, then sends `v1.provision_ehlo` on `backward`.
3. A polls `backward` until it receives `v1.provision_ehlo`.
4. Both sides finish SPAKE and derive the same 32-byte shared key.

If no completion happens, A rotates to a fresh `(channel_id, token)` and displays a new code. A practical default is 15 seconds per attempt.

## Blob payloads

`v1.provision_helo` and `v1.provision_ehlo` use:

```json
{ "spake_msg": "base64url-encoded 33-byte value" }
```

`v1.provision_finish` uses:

```json
{
  "nonce": "base64url-encoded 24-byte nonce",
  "ciphertext": "base64url-encoded bytes"
}
```

The ciphertext is XChaCha20-Poly1305 over a JSON body using:

- key: SPAKE shared key
- nonce: `nonce` field
- associated data: empty bytes

Plaintext JSON:

```json
{
  "device_secret": "...",
  "add_device_update": "..."
}
```

`add_device_update` is a signed raw directory update of the shape:

`[username_key, nonce, signer_pk, owners, value, signature]`

## Receiver completion (device B)

After decrypting `v1.provision_finish`, B must:

1. verify the decrypted username matches the login username;
2. verify the signed update targets that username and adds the decrypted device key;
3. submit the signed update to the directory;
4. verify the new device is present in the resulting descriptor;
5. authenticate to the bound server and publish medium-term keys.

This completes provisioning.
