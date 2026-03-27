# Events

An event is the plaintext payload inside encrypted messages. It is BCS-encoded as a tuple:

```
[sender, recipient, sent_at, after, tag, body]
```

- `sender`: the username of the event author
- `recipient`: `["dm", username]` (for DMs) or `["group", group_id]` (for group chats)
- `sent_at`: Unix timestamp (nanoseconds)
- `after`: optional hash of the previous event in the conversation (for causal ordering). Set to `null` for the first event in a thread.
- `tag`: a `u16` discriminator that determines how `body` is interpreted
- `body`: opaque bytes whose meaning depends on `tag`

The `sender` field is included in the event itself (not just in the device signature wrapper) so that the event hash commits to authorship. Recipients MUST verify that the `sender` in the event matches the device-signed sender.

The `recipient` field prevents replay attacks across conversation boundaries — a DM event cannot be replayed into a group mailbox, and vice versa. Recipients MUST verify that the `recipient` matches the conversation context.

The `after` field provides causal ordering within a conversation. It contains the hash of the event that this event follows. Clients SHOULD validate the link but MAY accept events whose `after` target is not yet known (out-of-order delivery).

## Event hash

The event hash is:

```
event_hash = H(bcs_encode(event))
```

where `H` is BLAKE3. This hash is used as the `after` link in subsequent events.

## Event tags

| Tag | Value | Context | Body |
|-----|-------|---------|------|
| MESSAGE | 1 | DM or group | BCS-encoded [MessagePayload](#messagepayload) |
| ROTATION_HINT | 2 | group | empty |
| GROUP_INVITATION | 3 | DM | BCS-encoded [GroupInvitationBody](#groupinvitationbody) |
| LEAVE_REQUEST | 4 | group | empty |
| GROUP_ADMIN_CHANGE | 5 | group | BCS-encoded [GroupAdminChangeBody](#groupadminchangebody) — reserved; admin set changes are handled via rotation |
| GROUP_MUTE_CHANGE | 6 | group | BCS-encoded [GroupMuteChangeBody](#groupmutechangebody) |
| GROUP_METADATA_CHANGE | 7 | group | BCS-encoded [GroupMetadataChangeBody](#groupmetadatachangebody) |
| GROUP_SETTINGS_CHANGE | 8 | group | BCS-encoded [GroupSettingsChangeBody](#groupsettingschangebody) |

Tags 2 and 4–8 are group management events. Their authorization and semantics are specified in [groups](groups.md).

## MessagePayload

A human chat message. BCS-encoded as:

```
[text, attachments, images, replies_to, metadata]
```

- `text`: either `["plain", string]` or `["rich", string]`
- `attachments`: list of file [attachments](attachments.md)
- `images`: list of image attachments (compressed images with thumbhash previews)
- `replies_to`: optional event hash (the hash of the event being replied to)
- `metadata`: key-value map of string pairs (extensible metadata)

## GroupInvitationBody

Sent as a DM (tag 3) from an admin to an invitee. BCS-encoded as:

```
[group_id, gbk, rotation_index, title, description]
```

- `group_id`: the group identifier
- `gbk`: the current [group bearer key](groups.md#group-bearer-key-gbk) (full capability)
- `rotation_index`: hint for which rotation entry to fetch first
- `title`: optional group title string
- `description`: optional group description string

See [groups — invitation flow](groups.md#invite-a-user) for the full flow.

## GroupAdminChangeBody

Sent in a group mailbox (tag 5) by an admin. BCS-encoded as:

```
[username, is_admin]
```

- `username`: the member whose admin status is changing
- `is_admin`: boolean — `true` to grant admin, `false` to revoke

## GroupMuteChangeBody

Sent in a group mailbox (tag 6) by an admin. BCS-encoded as:

```
[username, muted]
```

- `username`: the member whose mute status is changing
- `muted`: boolean — `true` to mute, `false` to unmute

## GroupMetadataChangeBody

Sent in a group mailbox (tag 7) by an admin. BCS-encoded as:

```
[title, description]
```

- `title`: optional new group title (or `null` to clear)
- `description`: optional new group description (or `null` to clear)

## GroupSettingsChangeBody

Sent in a group mailbox (tag 8) by an admin. BCS-encoded as:

```
[new_members_muted, allow_new_members_to_see_history]
```

- `new_members_muted`: boolean — whether newly invited members start muted
- `allow_new_members_to_see_history`: boolean — whether new members can see messages from before they joined
