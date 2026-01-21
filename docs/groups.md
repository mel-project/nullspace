# Groups

This document specifies Xirtam group chats: identifiers, mailboxes, invites, membership semantics, management messages, and rekeying. It is intended to be sufficient for a clean-room implementation of a compatible client.

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
group_id = H(bcs_encode(group_descriptor))
```

where `H` is BLAKE3.

## Mailboxes and access tokens

Each group has two mailboxes on the group’s server:

- **Group messages mailbox**: carries normal group chat messages and rekeys
- **Group management mailbox**: carries management messages (invites, bans, admin changes, leave)

Mailbox identifiers are derived from the group id as keyed hashes:

```
group_messages_mailbox_id   = H_keyed("group-messages",    group_id_bytes)
group_management_mailbox_id = H_keyed("group-management",  group_id_bytes)
```

Servers enforce mailbox access using opaque **auth tokens** (shared secrets). A token grants permissions via an ACL entry keyed by `H(token_bytes)`. The initial admin has a “group token” that can edit ACLs; invited members receive tokens that can send/receive.

## Cryptographic keys

Groups use two symmetric keys:

- **Group message key**: 32-byte XChaCha20-Poly1305 key used to encrypt regular group chat messages. This key is periodically rotated (“rekeyed”).
- **Management key**: 32-byte XChaCha20-Poly1305 key used to encrypt management messages. This key is distributed in invites as part of the group descriptor.

Clients keep both a current and previous group message key to tolerate out-of-order delivery.

## Message formats in group mailboxes

### Regular group message (`v1.group_message`)

The mailbox payload is BCS-encoded as:

```
[nonce, ciphertext]
```

- `nonce`: 24 random bytes
- `ciphertext`: XChaCha20-Poly1305 ciphertext of a signed group payload

The plaintext that is encrypted is BCS-encoded as:

```
[group_id, sender, cert_chain, message, signature]
```

The signature is over:

```
bcs_encode([group_id, sender, message])
```

This binds the message to the group and is defense-in-depth against malleability.

For normal chat messages, the tagged blob is `[kind, inner]` where `kind` is `v1.message_content` and `inner` is `bcs_encode(event)`. The event’s recipient (`event[0]`) must be the group id.

### Group rekey (`v1.group_rekey`)

The mailbox payload is a header-encrypted, device-signed tagged blob that carries the new 32-byte group message key.

The tagged blob is:

```
["v1.aead_key", bcs_encode([group_id, new_group_key_bytes])]
```

Recipients must accept a rekey only if the sender is an active admin according to the locally-derived roster.

## Management messages

Management messages are delivered as `v1.group_message` entries posted to the **management mailbox**, but encrypted using the **management key** rather than the group message key.

After decrypting and verifying the signed group payload, clients interpret `message` as a tagged blob:

- `message[0]` must be `v1.message_content`
- `message[1]` must decode as an event

The event fields must be:

- `recipient` is the group id
- `mime` is `application/vnd.xirtam.v1.group_manage`
- `body` is JSON

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

- **InviteSent(target)**: sender must be active (pending or accepted). Target becomes pending unless already accepted or banned.
- **InviteAccepted**: applies to the sender. If the sender is banned, ignore; otherwise mark accepted.
- **Leave**: if sender is not banned, remove sender from roster.
- **Ban/Unban/AddAdmin/RemoveAdmin(target)**: sender must be an active admin.

The roster is initialized with `init_admin` as accepted + admin.

## Flows

### Create a group

```
CreateGroup():
    descriptor = [random32, my_username, now_seconds, my_server_name, random32]
    group_id = H(bcs_encode(descriptor))
    group_message_key = random32
    group_token = random20

    Server.RegisterGroup(group_id)
    Server.SetMailboxAcl(group_messages_mailbox_id,   group_token, can_send=true, can_recv=true, can_edit_acl=true)
    Server.SetMailboxAcl(group_management_mailbox_id, group_token, can_send=true, can_recv=true, can_edit_acl=true)

    Persist(descriptor, group_message_key_current=group_message_key, group_message_key_previous=group_message_key, group_token)
```

### Send a group chat message

```
SendGroupMessage(group_id, event):
    // wrap event as tagged blob
    event_bytes = bcs_encode(event)
    msg_blob = ["v1.message_content", event_bytes]

    // sign and bind to group
    signature = Ed25519.Sign(my_device_signing_sk, bcs_encode([group_id, my_username, msg_blob]))
    signed = [group_id, my_username, my_cert_chain, msg_blob, signature]

    // encrypt under current group message key
    nonce = RandomBytes(24)
    ct = XChaCha20-Poly1305(key=group_message_key_current, nonce=nonce).Encrypt(bcs_encode(signed))

    MailboxSend(mailbox=group_messages_mailbox_id, kind="v1.group_message", body=bcs_encode([nonce, ct]))
```

On receive from the group messages mailbox, clients do:

```
RecvGroupMessageEntry(body_bytes):
    [nonce, ct] = bcs_decode(body_bytes)
    signed_bytes = XChaCha20-Poly1305(key=group_message_key_current, nonce=nonce).Decrypt(ct)
        or XChaCha20-Poly1305(key=group_message_key_previous, nonce=nonce).Decrypt(ct)
    signed = bcs_decode(signed_bytes)

    [signed_group_id, sender, cert_chain, message, signature] = signed
    assert signed_group_id == group_id
    VerifyCertificateChain(cert_chain, DirectoryRootHash(sender))
    Ed25519.Verify(cert_chain.leaf_device_public_key, signature, bcs_encode([group_id, sender, message]))

    // interpret tagged blob
    if message[0] == "v1.message_content":
        event = bcs_decode(message[1])
        assert event[0] == group_id
        return event
```

### Invite a user

Invites have two parts:

1) A management message to update the roster, posted to the management mailbox.
2) A direct message to deliver the secret material (group key + token + descriptor) to the invitee.

```
InviteUser(group_id, invitee_username):
    invite_token = random20
    Server.SetMailboxAcl(group_messages_mailbox_id,   invite_token, can_send=true, can_recv=true)
    Server.SetMailboxAcl(group_management_mailbox_id, invite_token, can_send=true, can_recv=true)

    // roster signal (management mailbox)
    SendGroupManagement(group_id, {"invite_sent": invitee_username})

    // secret delivery (DM)
    dm_body_json = { descriptor, group_key: group_message_key_current, token: invite_token, created_at: now_nanos }
    invite_event = [invitee_username, now_nanos, "application/vnd.xirtam.v1.group_invite", dm_body_json]
    SendDM(invitee_username, invite_event)
```

### Accept an invite

```
AcceptInvite(invite):
    Persist(invite.descriptor, group_message_key_current=invite.group_key, group_message_key_previous=invite.group_key, token=invite.token)

    // start reading management from the beginning; start reading messages from invite.created_at
    SetMailboxCursor(group_management_mailbox_id, after=0)
    SetMailboxCursor(group_messages_mailbox_id,   after=invite.created_at)

    SendGroupManagement(group_id, "invite_accepted")
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
SendGroupManagement(group_id, manage_json):
    manage_event = [group_id, now_nanos, "application/vnd.xirtam.v1.group_manage", manage_json]
    event_bytes = bcs_encode(manage_event)
    msg_blob = ["v1.message_content", event_bytes]

    signature = Ed25519.Sign(my_device_signing_sk, bcs_encode([group_id, my_username, msg_blob]))
    signed = [group_id, my_username, my_cert_chain, msg_blob, signature]
    nonce = RandomBytes(24)
    ct = XChaCha20-Poly1305(key=management_key, nonce=nonce).Encrypt(bcs_encode(signed))
    MailboxSend(mailbox=group_management_mailbox_id, kind="v1.group_message", body=bcs_encode([nonce, ct]))
```

### Leave / ban / admin changes

These are all management messages with the JSON forms listed above, sent via `SendGroupManagement`.

### Rekey

Rekeying is specified cryptographically in [e2ee.md](e2ee.md). Semantically:

- Only active admins’ rekeys are accepted.
- Rekeys are addressed to the medium-term keys of all active members (pending or accepted) and exclude banned/inactive members.
