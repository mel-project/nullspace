# Groups

This document specifies Nullspace group chats: identifiers, the group bearer key, the rotation registry, roster management, and all group-related flows.

## Design principles

### Security

The server is explicitly untrusted. The group design provides the following guarantees against a malicious server:

**Confidentiality.** The server cannot read group messages or learn who the members are.

**Message authenticity.** Members can verify that a message genuinely came from the device it claims to be from. The server cannot forge or inject messages.

**Membership control.** Only admins can add or remove members. The server cannot grant access to outsiders, cannot unilaterally revoke access, and cannot change who has admin authority.

**Bounded key-compromise blast radius.** Keys rotate on membership changes and roughly daily. Compromising the keys from one period does not expose messages from other periods.

**What the design does not protect against:**
- *Liveness*: the server can delay or withhold messages.
- *Traffic metadata*: the server observes which IP addresses access which mailboxes, though this is not directly tied to user identity.
- *Malicious admins*: admins are fully trusted and have unlimited power over the group.

### Scalability

The design is built to support very large groups without degrading UX. Sending a message costs the same regardless of group size — one encryption, one mailbox post. Inviting a new member requires a single DM; there is no work that scales with the number of existing members at join time. See [Scalability](#scalability) at the end of this document for a detailed comparison with other approaches.

## Group identifiers

A group is identified by a random 16-byte **group id** (UUID v4). Group IDs are generated client-side when a group is created.

## Group bearer key (GBK)

The GBK is the central capability for group membership. Possession of a GBK grants the ability to read from and write to the group's mailbox, and to encrypt and decrypt group messages.

A GBK is BCS-encoded as:

```
[group_id, server, random_nonce]
```

- `group_id`: the group identifier
- `server`: the server name hosting the group
- `random_nonce`: 32 random bytes (changed on every rotation)

### Derived keys

From the GBK, two keys are derived:

**Mailbox key** (20 bytes):
```
mailbox_key = h_keyed("ns-group-mailbox", bcs_encode(gbk))[0..20]
```

The `mailbox_key` is used to create and read from the group's mailbox. The corresponding `mailbox_id` is derived from the key as `h_keyed("nullspace-mailbox", mailbox_key_bytes)`.

**Symmetric encryption key** (32 bytes):
```
symmetric_key = h_keyed("ns-group-symmetric", bcs_encode(gbk))
```

Used as the XChaCha20-Poly1305 key for encrypting and decrypting group messages. See [e2ee — group encryption](e2ee.md#group-encryption) for the message format.

## Epochs

Each GBK defines a **mailbox epoch**. When the GBK changes (via a rotation), a new mailbox is created with new derived keys, starting a new epoch.

The group remains one logical event thread across all epochs. The `after` field always links within that one group thread, not to a per-epoch thread.

Within an epoch:
- The **roster snapshot** (embedded in the rotation entry) is the starting state for membership.
- **Admin action events** posted to the mailbox are deltas applied on top of the snapshot.

Clients poll only the current GBK mailbox. To avoid getting stuck on a stale GBK, they refresh the rotation registry before sending and may also refresh it periodically in the background. Rotation hints are an optimization, not the only recovery path.

## Group rotation registry

The rotation registry is a server-side append-only log, one per group. Each entry records a GBK rotation along with the new roster state.

A rotation entry is BCS-encoded as:

```
[group_id, prev_hash, signer, new_admin_set, gbk_rotation, roster_encrypted, signature]
```

- `group_id`: the group identifier
- `prev_hash`: hash of the previous rotation entry, or `null` for the first entry. Forms a hash chain that prevents the server from reordering, inserting, or silently replacing entries. Position in the log is implicit and tracked locally by clients.
- `signer`: the device signing public key of the admin submitting the rotation
- `new_admin_set`: set of device signing public keys for all admin devices (used to validate the next rotation's `signer`)
- `gbk_rotation`: a header-encrypted payload containing the [rotation payload](#rotation-payload)
- `roster_encrypted`: the roster snapshot encrypted under the new GBK
- `signature`: Ed25519 signature over `bcs_encode([group_id, prev_hash, signer, new_admin_set, gbk_rotation, roster_encrypted])`

The **rotation hash** of an entry is `H(bcs_encode(rotation))` (covering all fields including the signature).

Server validation rules:
- `prev_hash` MUST be `null` for the first entry, non-null for all subsequent entries
- `signer` MUST be in the previous entry's `new_admin_set`
- `signature` MUST verify under `signer`
- `new_admin_set` MUST be non-empty

The current server implementation does not check that the supplied `prev_hash` matches the stored head hash, so clients MUST still validate the full chain themselves.

Client validation rules (defense-in-depth — do not trust the server alone):
- `signature` MUST verify under `signer`
- `signer` MUST be in the locally stored `new_admin_set` from the previous rotation
- `prev_hash` MUST equal the locally stored hash of the previous rotation
- `prev_hash` MUST be `null` for the first entry
- When walking a chain of rotations (for example during refresh), each entry's `prev_hash` and `signer` MUST be validated against the preceding entry

### Rotation payload

The `gbk_rotation` field is header-encrypted to all members' medium-term keys, so every member can decrypt it. The plaintext is BCS-encoded as:

```
[gbk]
```

- `gbk`: the new [group bearer key](#group-bearer-key-gbk)

The roster travels separately in `roster_encrypted`, encrypted with the new GBK.

## Roster snapshot

The roster is a complete snapshot of group membership state, embedded in every rotation. BCS-encoded as:

```
[members, banned, metadata, settings]
```

- `members`: map of `{username: [is_admin, is_muted], ...}`
- `banned`: set of usernames
- `metadata`: `[title, description]` where both are optional strings
- `settings`: `[new_members_muted, allow_new_members_to_see_history]`

The roster snapshot is correctness-critical: it carries accumulated state across epoch boundaries so that new members (and members recovering from missed rotations) don't need access to previous epochs to reconstruct group state.

## What causes a new rotation (new epoch)

A rotation (and therefore a new GBK and mailbox epoch) is required when:

- **Group creation** — the initial rotation establishes the group.
- **Admin set change** — granting or revoking admin status requires a rotation so that `new_admin_set` in the chain stays consistent with actual admin authority.
- **Banning a member** — the banned member's access must be revoked by changing the GBK.
- **Admin leaving** — admin departure requires a rotation to update the admin set.
- **Periodic key rotation** — probabilistic, targeting ~1 rotation per day. Each hour, each admin independently rolls the dice with probability `1 / (24 * n_admins)`, so the expected aggregate interval is ~24 hours regardless of admin count.

Actions that do **not** require a rotation:
- Non-admin member leaving (sends a LEAVE_REQUEST event instead)
- Unbanning a member
- Mute changes, metadata changes, settings changes (sent as in-epoch events)
- Sharing an invite

## Admin action events

Within an epoch, admins (and non-admin leavers) can modify group state by posting [events](events.md) to the group mailbox. These are processed as roster deltas on top of the epoch's snapshot.

| Tag | Name | Authorization | Body | Effect |
|-----|------|---------------|------|--------|
| 5 | GROUP_PERMISSION_CHANGE | admin only | `{"username", "muted"}` | sets `is_muted` for the named member |
| 6 | GROUP_SETTINGS_CHANGE | admin only | `{"title", "description", "new_members_muted", "allow_new_members_to_see_history"}` | updates metadata and/or group-wide settings |
| 7 | GROUP_UNBAN | admin only | `{"username"}` | removes the named user from the banned set |
| 4 | LEAVE_REQUEST | any member | empty | removes sender from the roster |
| 2 | ROTATION_HINT | any member | empty | signals clients to check registry for a new rotation (not a roster change) |

Clients MUST verify that the event sender is an admin before applying tags 5–7. LEAVE_REQUEST (tag 4) is accepted from any member. ROTATION_HINT (tag 2) does not modify the roster.

Admin set changes are not delivered as in-epoch events — they go through the rotation registry instead, keeping `new_admin_set` authoritative and up to date.

## Flows

### Create a group

```
create_group(title, description):
    group_id = random_uuid()
    gbk = [group_id, my_server, random32]

    roster = {
        members: {my_username: [is_admin=true, is_muted=false]},
        banned: [],
        metadata: [title, description],
        settings: [new_members_muted=false, allow_history=false]
    }

    payload = [gbk]
    payload_encrypted = header_encrypt(my_medium_keys, bcs_encode(payload))
    roster_encrypted = encrypt_with_gbk(gbk, roster)

    rotation = [group_id, prev_hash=null, signer=my_device_pk, admin_set={my_device_pk}, payload_encrypted, roster_encrypted, signature]
    sign(rotation)

    server.group_create(auth_token, rotation)
    server.mailbox_create(auth_token, gbk.mailbox_key())
    persist(gbk, roster)
```

### Send a group message

See [e2ee — sending a group message](e2ee.md#sending-a-group-message).

### Receive a group message

```
recv_group_message(body_bytes, gbk, group_id):
    nonce = body_bytes[0..24]
    ct = body_bytes[24..]
    signed_bytes = xchacha20_poly1305_decrypt(key=gbk.symmetric_key(), nonce=nonce, ciphertext=ct)

    (sender, event_bytes) = device_verify(signed_bytes)
    event = bcs_decode(event_bytes)
    assert event.recipient == ["group", group_id]
    assert event.sender == sender

    if event.tag == ROTATION_HINT:
        check_and_adopt_rotation(group_id)
        return

    if event.tag in [GROUP_PERMISSION_CHANGE, GROUP_SETTINGS_CHANGE, LEAVE_REQUEST]:
        apply_admin_action(event)
        return

    // Regular message
    store_message(event)
```

### Invite a user

An admin DMs the current GBK to the invitee. No rotation is needed — the GBK is the capability.

```
invite_user(group_id, invitee_username):
    assert am_admin
    assert invitee not banned

    invitation = [group_id, current_gbk, current_rotation_index, title, description]
    event = [my_username, ["dm", invitee_username], now_nanos, after, TAG_GROUP_INVITATION, json_encode(invitation)]
    send_dm(invitee_username, event)
```

Sharing an invite does not itself insert the invitee into the roster. The GBK is the capability.

### Accept an invite

```
accept_invite(invitation):
    gbk = invitation.gbk

    rotation = server.group_get(gbk.group_id, invitation.rotation_index)
    verify(rotation)
    roster = decrypt_roster(gbk, rotation.roster_encrypted)

    persist(gbk, roster)

    // Later refreshes and rotation hints adopt newer rotations
    start_polling(gbk.mailbox_key())
```

### Ban a user

Banning requires a rotation because the banned member must lose access to the GBK.

```
ban_user(group_id, target_username):
    assert am_admin
    roster.members.remove(target_username)
    roster.banned.add(target_username)
    submit_rotation(group_id, roster)
```

### Admin leave

Admin departure requires a rotation to update the admin set.

```
admin_leave(group_id):
    assert am_admin
    roster.members.remove(my_username)
    submit_rotation(group_id, roster)
    delete_local_group_state(group_id)
```

### Non-admin leave

Non-admins post a LEAVE_REQUEST event and clean up locally. No rotation is needed.

```
non_admin_leave(group_id):
    event = [my_username, ["group", group_id], now_nanos, after, TAG_LEAVE_REQUEST, empty]
    send_group_message(group_id, event)
    delete_local_group_state(group_id)
```

### Periodic rotation

```
periodic_rotation():
    // Runs once per hour for each group where this device is an admin
    for each group where am_admin:
        n_admins = count of admins
        p = 1 / (24 * n_admins)
        if random() < p:
            submit_rotation(group_id, current_roster)
```

### Submit rotation (shared helper)

Used by ban, admin leave, and periodic rotation:

```
submit_rotation(group_id, roster):
    new_gbk = [group_id, server, random32]
    all_medium_keys = fetch_medium_keys(roster.members)
    admin_device_keys = fetch_device_keys(admins in roster.members)

    payload = [new_gbk]
    payload_encrypted = header_encrypt(all_medium_keys, bcs_encode(payload))
    roster_encrypted = encrypt_with_gbk(new_gbk, roster)

    rotation = [group_id, prev_hash=current_rotation_hash, signer=my_device_pk, admin_set=admin_device_keys, payload_encrypted, roster_encrypted, signature]
    sign(rotation)

    server.group_update(rotation)
    server.mailbox_create(auth_token, new_gbk.mailbox_key())

    // Notify members to refresh the registry promptly
    send_rotation_hint(group_id, old_gbk)

    persist(new_gbk, roster)
```

The rotation hint is a regular group message (encrypted with the old GBK's symmetric key) containing an event with tag ROTATION_HINT and empty body. It prompts clients to refresh the registry for the new rotation sooner than their next background or send-time refresh.

## Scalability

Nullspace groups are designed to scale to very large membership — tens or hundreds of thousands of members — without hitting fundamental protocol limits. This is in deliberate contrast to approaches like Signal's (and WhatsApp's) Sender Keys, which impose O(n) costs on operations that happen frequently.

### Signal's Sender Keys

Signal's group protocol gives each member a personal "sender key": a symmetric signing key used to encrypt that member's outgoing messages. The scheme achieves efficient O(1) message sending (encrypt once, server fans out), but creates severe scaling problems for membership operations:

- **Join**: the new member must receive a sender key from every existing member, requiring O(n) individual DMs. In practice, Signal caps groups at 1,000 members partly for this reason.
- **Member removal**: to maintain forward secrecy after someone leaves or is removed, all remaining members must redistribute their sender keys — again O(n) DMs.
- **State complexity**: each member must track a separate sender key per group member, which creates substantial per-device state and opportunities for "decryption failed" failures when keys fall out of sync.

### Nullspace's shared-key approach

Nullspace uses a single shared group key per epoch. This means:

- **Message send**: O(1). Encrypt once with the shared symmetric key, post to one mailbox.
- **Join**: O(1). The inviting admin sends one DM containing the current key.
- **Key rotation** (bans, admin changes, periodic): O(n). The rotating admin must encrypt the new key to every member's medium-term public key. This is the only operation that scales with group size.

Rotations are infrequent — bans and admin changes are rare, and periodic rotation happens roughly once per day per group regardless of how many messages are sent.

Importantly, the O(n) rotation cost is a single upload, not O(n) individual messages. The new key is header-encrypted to all members' public keys and packed into one blob posted to the server, avoiding "O(n) DMs" patterns. This means that at ~32 bytes of ciphertext overhead per member, a 100,000-member group — an absurdly large group — produces a rotation payload of roughly 3 MB, comparable to uploading and fanning out a single photo. Furthermore, this is a cost imposed on the admin, not on every single user.

So for large groups, the overhead of Nullspace encryption (versus a traditional unencrypted chat like Telegram) is effectively one admin sending a photo every time the admin set changes or somebody gets banned. This seems to be an intuitively small overhead; reasonably active groups have photos sent in them more frequently than people get banned!

### Why not ratcheting?

MLS (the IETF standard for scalable E2EE groups) reduces rotation cost from O(n) to O(log n) via a ratchet tree. 

But even setting aside MLS's significant protocol complexity, the O(n) rotation cost in Nullspace is already cheap enough in absolute terms — a single blob upload, not O(n) network round-trips — that the asymptotic improvement is not really meaningful. 

Furthermore, the Nullspace E2EE design deliberately avoids ratcheting for reasons that go beyond scalability. See [End-to-end encryption](e2ee.md) for the full rationale.
