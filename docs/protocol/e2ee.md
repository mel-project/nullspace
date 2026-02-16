# End-to-end encryption

This protocol intentionally avoids per-message ratchets and uses periodic key rotation instead. The design prioritizes simpler implementation and better scaling for large groups.

## Primitives

### Event payload

An event is BCS-encoded as:

```
[recipient, sent_at, mime, body]
```

- `recipient`: `["user", username]` or `["group", group_id]`
- `sent_at`: Unix timestamp (nanoseconds)
- `mime`: MIME string
- `body`: opaque bytes

### Tagged blob

A tagged blob is:

```
[kind, inner]
```

Used kinds include `v1.message_content`, `v1.direct_message`, `v1.group_message`, and `v1.group_rekey`.

### Header encryption

Header-encrypted payload format:

```
[sender_epk, headers, body]
```

`headers` contains per-recipient wrapped message keys indexed by a short hash hint of recipient medium key.

### Device-signed payload

Device-signed payload format:

```
[sender_username, sender_device_pk, body, signature]
```

`signature` is over:

```
bcs_encode([sender_username, sender_device_pk, body])
```

Verification steps:
1) verify Ed25519 signature under `sender_device_pk`
2) fetch sender user state from directory
3) check `sender_device_pk` exists, is `active`, and not expired

Pseudocode:

```
device_sign(sender_username, sender_device_pk, sender_device_sk, body_bytes):
    payload = [sender_username, sender_device_pk, body_bytes]
    signature = ed25519_sign(sender_device_sk, bcs_encode(payload))
    return bcs_encode([sender_username, sender_device_pk, body_bytes, signature])


device_verify(device_signed_bytes):
    [sender, sender_device_pk, body, signature] = bcs_decode(device_signed_bytes)
    ed25519_verify(sender_device_pk, signature, bcs_encode([sender, sender_device_pk, body]))
    state = directory_get_user_state(sender)
    assert sender_device_pk is active and non-expired in state
    return (sender, body)
```

## DM encryption

Send flow:

```
send_dm(to_username, event):
    event_bytes = bcs_encode(event)
    msg_blob_bytes = bcs_encode(["v1.message_content", event_bytes])
    signed_bytes = device_sign(my_username, my_device_pk, my_device_sk, msg_blob_bytes)

    recipients_mpk = fetch_medium_public_keys(to_username)
    he_bytes = header_encrypt(recipients_mpk, signed_bytes)

    mailbox_send(mailbox=direct_mailbox(to_username), kind="v1.direct_message", body=he_bytes)
```

Receive flow:

```
recv_dm(he_bytes):
    signed_bytes = header_decrypt(my_medium_sk_current, he_bytes)
        or header_decrypt(my_medium_sk_previous, he_bytes)

    (sender_username, msg_blob_bytes) = device_verify(signed_bytes)
    [kind, inner] = bcs_decode(msg_blob_bytes)
    assert kind == "v1.message_content"
    return bcs_decode(inner)
```

## Group encryption

Group chat messages are encrypted under the current group symmetric key. The decrypted payload is still a device-signed event blob.

```
send_group_message(group_id, event):
    signed = device_sign(my_username, my_device_pk, my_device_sk, bcs_encode(event))
    nonce = random_bytes(24)
    ct = xchacha20_poly1305_encrypt(group_message_key_current, nonce, signed)
    mailbox_send(group_messages_mailbox(group_id), "v1.group_message", bcs_encode([nonce, ct]))
```

Rekeys are distributed with header encryption:

```
send_group_rekey(group_id, new_group_key_bytes):
    payload = bcs_encode([group_id, new_group_key_bytes])
    signed = device_sign(my_username, my_device_pk, my_device_sk, payload)
    recipients_mpk = fetch_medium_public_keys_of_active_members(group_id)
    he_bytes = header_encrypt(recipients_mpk, signed)
    mailbox_send(group_messages_mailbox(group_id), "v1.group_rekey", he_bytes)
```

Group semantics (invites, admins, bans, roster rules) are specified in [groups](groups.md).
