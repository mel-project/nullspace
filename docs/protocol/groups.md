# Groups

This document specifies Nullspace group chats: identifiers, mailboxes, invites, membership semantics, management messages, and rekeying. 

## Group identifiers and descriptor

A group is described by a **group descriptor**. The descriptor is BCS-encoded as:

```
[nonce, init_admin, created_at, server, management_key]
```

- `nonce`: 32 random bytes
- `init_admin`: username of the initial admin
- `created_at`: Unix timestamp (seconds)
- `server`: the server name hosting the group
- `management_key`: 32-byte XChaCha20-Poly1305 key (used for management messages)

The **group id** is:

```
group_id = h(bcs_encode(group_descriptor))
```

where `h` is BLAKE3.

## Mailboxes and access tokens

Each group has two mailboxes on the group’s server:

- **Group messages mailbox**: carries normal group chat messages and rekeys
- **Group management mailbox**: carries management messages (invites, bans, admin changes, leave)

Mailbox identifiers are derived from the group id as keyed hashes:

```
group_messages_mailbox_id   = h_keyed("group-messages",    group_id_bytes)
group_management_mailbox_id = h_keyed("group-management",  group_id_bytes)
```

Servers enforce mailbox access using opaque **auth tokens** (shared secrets). A token grants permissions via an ACL entry keyed by `h(token_bytes)`. The initial admin has a “group token” that can edit ACLs; invited members receive tokens that can send/receive.

## Cryptographic keys

Groups use two symmetric keys:

- **Group message key**: 32-byte XChaCha20-Poly1305 key used to encrypt regular group chat messages. This key is periodically rotated (“rekeyed”).
- **Management key**: 32-byte XChaCha20-Poly1305 key used to encrypt management messages. This key is distributed in invites as part of the group descriptor.

Clients keep both a current and previous group message key to tolerate out-of-order delivery.

## Message formats in group mailboxes

Mailbox entries in the group mailboxes are [tagged blobs](e2ee.md#tagged-blobs). Both regular group messages and group rekeys share this outer structure; they differ only in the `kind` tag and how the `inner` bytes are interpreted.

### Regular group message (`v1.group_message`)

The mailbox entry uses `kind = v1.group_message`, and the `inner` bytes are BCS-encoded as:

```
[nonce, ciphertext]
```

- `nonce`: 24 random bytes
- `ciphertext`: XChaCha20-Poly1305 ciphertext of a [device-signed](e2ee.md#device-signing) event.

The decrypted plaintext is a device-signed event. The event’s recipient (`event[0]`) must be the group id.

### Group rekey (`v1.group_rekey`)

The mailbox entry uses `kind = v1.group_rekey`, and the `inner` bytes are a header-encrypted, device-signed payload that carries the new 32-byte group message key.

The device-signed `body` is BCS-encoded as:

```
[group_id, new_group_key_bytes]
```

Recipients must accept a rekey only if the sender is an active admin according to the locally-derived roster.

## Management messages

Management messages are delivered as `v1.group_message` entries posted to the **management mailbox**, but encrypted using the **management key** rather than the group message key.

After decrypting and verifying the device-signed event, clients interpret it with these requirements:

- `recipient` is the group id
- `mime` is `application/vnd.nullspace.v1.group_manage`
- `body` is JSON

### Roster

Clients maintain a local **roster** for each group. The roster is a deterministic, derived data structure computed by replaying management messages in order.

The roster contains, for each username that is currently tracked:

- a **membership state**: `pending`, `accepted`, or `banned`
- an **admin flag** (boolean), meaningful only for non-banned members

Note that users who are not in the roster at all are treated differently from banned users, because the former can join the group, while the latter cannot join the group until they are unbanned.

Initialization:

- The roster starts with `init_admin` as `accepted` with `admin = true`.

Derivation rules:

- Process management messages in the order they are observed from the management mailbox.
- Each message updates the roster according to the authorization rules and the variant-specific effects described below.

### JSON schema

The management message body is a JSON tagged value (externally tagged, snake_case) with one of these forms:

| Variant | JSON form | Meaning |
| --- | --- | --- |
| Invite sent | `{"invite_sent":"@user"}` | Marks `@user` as pending |
| Invite accepted | `"invite_accepted"` | Marks sender as accepted |
| Ban | `{"ban":"@user"}` | Marks `@user` as banned |
| Unban | `{"unban":"@user"}` | Moves `@user` from banned → pending |
| Leave | `"leave"` | Removes sender from roster |
| Add admin | `{"add_admin":"@user"}` | Grants admin to an active member |
| Remove admin | `{"remove_admin":"@user"}` | Revokes admin from an active member |

### Authorization rules

Clients apply these rules when updating the roster:

- **invite_sent(target)**: sender must be active (pending or accepted). Target becomes pending unless already accepted or banned.
- **invite_accepted**: applies to the sender. If the sender is banned, ignore; otherwise mark accepted.
- **leave**: if sender is not banned, remove sender from roster.
- **ban / unban / add_admin / remove_admin (target)**: sender must be an active admin.

The roster is initialized with `init_admin` as accepted + admin.

## Flows

### Create a group

```
create_group():
    descriptor = [random32, my_username, now_seconds, my_server_name, random32]
    group_id = h(bcs_encode(descriptor))
    group_message_key = random32
    group_token = random20

    server.register_group(group_id)
    server.set_mailbox_acl(group_messages_mailbox_id,   group_token, can_send=true, can_recv=true, can_edit_acl=true)
    server.set_mailbox_acl(group_management_mailbox_id, group_token, can_send=true, can_recv=true, can_edit_acl=true)

    persist(descriptor, group_message_key_current=group_message_key, group_message_key_previous=group_message_key, group_token)
```

### Send a group chat message

```
send_group_message(group_id, event):
    // sign the event
    signed = device_sign(my_username, my_cert_chain, my_device_signing_sk, bcs_encode(event))

    // encrypt under current group message key
    nonce = random_bytes(24)
    ct = xchacha20_poly1305_encrypt(key=group_message_key_current, nonce=nonce, plaintext=signed)

    mailbox_send(mailbox=group_messages_mailbox_id, kind="v1.group_message", body=bcs_encode([nonce, ct]))
```

On receive from the group messages mailbox, clients do:

```
recv_group_message_entry(body_bytes):
    [nonce, ct] = bcs_decode(body_bytes)
    signed_bytes = xchacha20_poly1305_decrypt(key=group_message_key_current, nonce=nonce, ciphertext=ct)
        or xchacha20_poly1305_decrypt(key=group_message_key_previous, nonce=nonce, ciphertext=ct)

    (sender, payload_bytes) = device_verify(signed_bytes, directory_root_hash(sender))
    event = bcs_decode(payload_bytes)
    assert event[0] == group_id
    return event
```

### Invite a user

Invites have two parts:

1) A management message to update the roster, posted to the management mailbox.
2) A direct message to deliver the secret material (group key + token + descriptor) to the invitee.

```
invite_user(group_id, invitee_username):
    invite_token = random20
    server.set_mailbox_acl(group_messages_mailbox_id,   invite_token, can_send=true, can_recv=true)
    server.set_mailbox_acl(group_management_mailbox_id, invite_token, can_send=true, can_recv=true)

    // roster signal (management mailbox)
    send_group_management(group_id, {"invite_sent": invitee_username})

    // secret delivery (DM)
    dm_body_json = { descriptor, group_key: group_message_key_current, token: invite_token, created_at: now_nanos }
    invite_event = [invitee_username, now_nanos, "application/vnd.nullspace.v1.group_invite", dm_body_json]
    send_dm(invitee_username, invite_event)
```

### Accept an invite

```
accept_invite(invite):
    persist(invite.descriptor, group_message_key_current=invite.group_key, group_message_key_previous=invite.group_key, token=invite.token)

    // start reading management from the beginning; start reading messages from invite.created_at
    set_mailbox_cursor(group_management_mailbox_id, after=0)
    set_mailbox_cursor(group_messages_mailbox_id,   after=invite.created_at)

    send_group_management(group_id, "invite_accepted")
```

## Invite payload encoding

The group invite event body is a JSON object with fields:

- `descriptor`: a JSON object containing the group descriptor fields (`nonce`, `init_admin`, `created_at`, `server`, `management_key`)
- `group_key`: 32-byte group message key
- `token`: 20-byte auth token for group mailbox access
- `created_at`: Unix timestamp (nanoseconds)

JSON encoding rules for binary values:

- 32-byte keys (like `management_key` and `group_key`) are encoded as URL-safe base64 without padding.
- 20-byte auth tokens are encoded as lowercase hex.
- Hashes (like `nonce` and `group_id`) are encoded as lowercase hex.

### Send a management message

```
send_group_management(group_id, manage_json):
    manage_event = [group_id, now_nanos, "application/vnd.nullspace.v1.group_manage", manage_json]

    signed = device_sign(my_username, my_cert_chain, my_device_signing_sk, bcs_encode(manage_event))
    nonce = random_bytes(24)
    ct = xchacha20_poly1305_encrypt(key=management_key, nonce=nonce, plaintext=signed)
    mailbox_send(mailbox=group_management_mailbox_id, kind="v1.group_message", body=bcs_encode([nonce, ct]))
```

### Leave / ban / admin changes

These are all management messages with the JSON forms listed above, sent via `send_group_management`.

### Rekey

Rekeying is specified cryptographically in [e2ee.md](e2ee.md). Semantically:

- Only active admins’ rekeys are accepted.
- Rekeys are addressed to the medium-term keys of all active members (pending or accepted) and exclude banned/inactive members.
