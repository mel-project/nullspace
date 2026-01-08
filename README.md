# xirtam: an experimental confederal protocol

What is a confederal protocol? [Read this blogpost first](https://nullchinchilla.substack.com/p/confederal) :)

## Implementation progress

- [x] Directory RPC + PoW updates + header sync (server + dirclient)
- [x] Gateway RPC + mailbox storage/ACLs + device auth
- [x] Core structs: handles, gateway descriptors, certificates, envelopes, message kinds
- [ ] Mailbox crypto protocol (DH mailbox keys, FS/PCS, sender/receiver flow)
- [ ] Group protocol (group IDs, rekeying, membership control)
- [ ] Directory privacy improvements (PIR/bucketed lookup)

## Broad-strokes design

- No blockchain yet, but with a centralized directory service that imitates a blockchain (e.g. expensive PoW-based rationing, multi-provider read replication, transparency logs)
	- Key constraint: updates must be somewhat expensive, and the whole protocol is designed around that fact
	- "Decentralizing the directory" can easily be done later
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
- "Good enough" approach: piggy-back revocation lists on various messages etc, and each participant (gateway and client) locally builds a grow-only revocation list.

**Problem**: directory sees too much metadata
- Easiest approach: full directory sync. This is not *too* bad:
	- All signal users: ~200M
	- 32 bytes of hash for each user: ~6 GB
- This is especially not bad if the *gateway* syncs this. The gateway can see a lot of metadata anyway.
- Eventually we could move to some sort of PIR system run by the individual gateway.
	- A compromise between PIR and direct lookups: bucket-based lookup (give me all certificates within this bucket, which is guaranteed to contain at least *k* other entries, for k-anonymity)

## Mailboxes

The most basic *underlying* protocol is the "mailbox protocol". It's a loosely SimpleX-like 1-to-1 DM protocol with a somewhat email like interface.

We use a *coarse-grained* mechanism to ensure forward secrecy and post-compromise secrecy:
- A DH **mailbox key** signed by the device key sits at the gateway.
- The mailbox key is updated at most every hour, with an anacron-style scheduling.
- Senders cache the recipient's DH key for an hour after looking it up at the recipient's gateway.
- Senders use a fully asynchronous approach (embed an ephemeral dh pk, a long-term dh pk signed by their device, and symmetrically encrypted body with key derived from triple-dh).
- Receivers keep around the current and previous mailbox key.

Each mailbox has an ACL of auth token hashes, used by anybody wishing to subscribe to or write to that mailbox.

When reading from a mailbox, each item in the mailbox comes attached with the *hash* of the sender auth token used to push it there (if any).

The low-level encrypted payloads sent to mailboxes are called *envelopes*; they carry a `Message` inside.

Each handle has a DM mailbox at its gateway. Device auth tokens get ACL entries (and optionally an anonymous ACL for public inboxes).

## DMs

DMs are routed to the handle's DM mailbox, with the kind `v1.direct_message` (or `v1.plaintext_direct_message`). There is no abstraction that represents a two-party conversation.

## Groups

Groups are uniquely identified by a **group ID**, which is the hash of the initial group descriptor.

Each group has its own hierarchy of cryptographic certificates. This assigns group admins, mods, etc, with differing permissions.

Each group is hosted on its own mailbox at a gateway. This means that groups have one, canonical gateway, and one canonical history.

From the canonical history, a group roster and an auth-token-hash -> handle mapping can be built.

Group membership changes and periodic rekeying are TODO.

## Messages

Messages look like this:

```
Message {
    kind: "v1.direct_message",
    inner: <bytes>
}
```

The `v1.message_content` kind is the common content carrier; the concrete payload schema is TBD.
