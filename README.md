# xirtam: an experimental confederal protocol

What is a confederal protocol? [Read this blogpost first](https://nullchinchilla.substack.com/p/confederal) :)

## Implementation progress

- [x] Directory RPC + PoW updates + header sync (server + dirclient)
- [x] Gateway RPC + mailbox storage/ACLs + device auth
- [x] Core structs: handles, gateway descriptors, certificates, message kinds
- [x] DM encryption format (encrypted headers + signed medium keys)
- [ ] Group protocol (group IDs, rekeying, membership control)
- [ ] Directory privacy improvements (PIR/bucketed lookup)

## Broad-strokes design

- No blockchain yet, but with a centralized directory service that imitates a blockchain (e.g. expensive PoW-based rationing, multi-provider read replication, transparency logs)
	- Key constraint: updates must be somewhat expensive, and the whole protocol is designed around that fact
	- "Decentralizing the directory" can easily be done later
- Directory is append-only, with signed anchors and headers for snapshot verification
	- Updates are batched into chunks and retrieved via directory RPC
	- PoW uses EquiX with configurable effort
	- Clients avoid holding DB transactions across network fetches during header sync
- Internal RPC has a short timeout to surface UI hangs during development (except `next_event`)
- Confederal architecture
	- No gateway-to-gateway protocol (other than convenience proxies)

## Identity

Basic structure: directory + certificate chain.

| Term | Meaning |
| --- | --- |
| handle | User identifier like `@user_01`. |
| gateway name | Gateway identifier like `~gate_01`. |
| handle descriptor | Directory entry: handle -> gateway name + root cert hash. |
| gateway descriptor | Directory entry: gateway name -> public URLs + gateway pk. |
| root cert hash | Hash of the root signing key for a handle's device chain. |
| certificate chain | Ordered device certificates establishing authorized devices. |
| device certificate | Signed device key with expiry + can_sign flag. |

- Directory stores handle descriptors: handle -> gateway name + root cert hash
- Directory stores gateway descriptors: gateway name -> public URLs + gateway pk
- Gateway serves the certificate chain for a handle; device certs have expiry + can_sign

```
@nullchinchilla -> root cert hash, ~gate_01

~gate_01 -> https://gateway.example, gateway pk

root pk -> device 1
         -> device 2 (can_sign) -> device 3 (time-limited)
```

**Problem**: revocation
- Easiest/safest approach: revocation list in the directory. Every certificate, when presented, must have a proof of non-revocation.

**Problem**: directory sees too much metadata
- Easiest approach: full directory sync. This is not *too* bad:
	- All signal users: ~200M
	- 32 bytes of hash for each user: ~6 GB
- This is especially not bad if the *gateway* syncs this. The gateway can see a lot of metadata anyway.
- Eventually we could move to some sort of PIR system run by the individual gateway.
	- A compromise between PIR and direct lookups: bucket-based lookup (give me all certificates within this bucket, which is guaranteed to contain at least *k* other entries, for k-anonymity)

## Mailboxes

The most basic *underlying* protocol is the "mailbox protocol". It's a loosely SimpleX-like 1-to-1 DM protocol with a somewhat email like interface.

Each handle has a DM mailbox at its gateway. Device auth tokens get ACL entries (and optionally an anonymous ACL for public inboxes).

When reading from a mailbox, each item in the mailbox comes attached with the *hash* of the sender auth token used to push it there (if any).

### Encrypted DMs

DMs are encrypted with an `Envelope` payload (stored inside `v1.direct_message`). It has:

- `headers`: `BTreeMap<Hash, Bytes>` keyed by the recipient device hash (the cert's `bcs_hash`).
- `body`: AEAD-encrypted `Message` with zero nonce and empty AAD.

Each header is encrypted using a sender ephemeral DH key to the recipient medium-term key, and contains the BCS encoding of:

```
{
  sender_handle,
  sender_chain, // full certificate chain for sender device
  key,          // symmetric key K
  key_sig       // signature over K by sender device signing key
}
```

Senders fetch signed medium-term keys from the gateway (`v1_device_medium_pks`) and use them to encrypt headers. Recipients use their own medium-term secret to open the envelope. They then:
- verify the sender chain against the handle's root cert hash from the directory
- verify `key_sig` against the sender device signing key
- decrypt the body with `K` to recover `MessageContent { mime, body }`

Each mailbox has an ACL of auth token hashes, used by anybody wishing to subscribe to or write to that mailbox.

## DMs

DMs are routed to the handle's DM mailbox, with the kind `v1.direct_message` (or `v1.plaintext_direct_message`). There is no abstraction that represents a two-party conversation.

## Groups

Groups are uniquely identified by a **group ID**, which is the hash of the initial group descriptor. The descriptor includes
- a nonce
- an initial admin
- a creation time
- the gateway name
- a static management key (used only for the management mailbox)

Each group has two mailboxes (both derived from the group ID):
- **message mailbox**: group chat messages + rekeys (messages may expire)
- **management mailbox**: management messages only (never expires)

Messages in groups are encrypted symmetrically with the appropriate group key and a random 192-bit nonce (XChaCha20). These messages are of kind `v1.group_message` and are BCS encoded as `{ nonce, ciphertext }`.

The ciphertext decrypts to a signed payload:
- `group`
- `sender`
- `sender_chain`
- `message`
- `signature` over `(group, sender, message)`

This lets clients verify exactly who authored each management message and ignore invalid actions. The management mailbox uses the static management key from the descriptor; the message mailbox uses the current (rotating) group key.

Rekeys are posted to the **message mailbox** as `v1.group_rekey` messages, envelope-encrypted to all group members' devices, and carry the new 32-byte group key.

Group invites are sent via DMs as `MessageContent` with mime `application/vnd.xirtam.v1.group_invite` (JSON payload). Management actions are sent as `v1.group_message` in the management mailbox, carrying `MessageContent` with mime `application/vnd.xirtam.v1.group_manage`.

## Messages

Messages look like this:

```
Message {
    kind: "v1.direct_message",
    inner: <bytes>
}
```

The `v1.message_content` kind carries `MessageContent { mime, body }`.
