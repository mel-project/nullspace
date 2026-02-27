# Mailboxes

Mailboxes are now a much "dumber" primitive. A mailbox is a pair `(mailbox_id, mailbox_key)`, where `mailbox_id = H_keyed(key="nullspace-mailbox", mailbox_id)`. Mailboxes are created dynamically by authenticated clients on their proper server; this makes "blame" for server-side rate limiting and such possible.

Mailboxes are also changed to directly work with raw bytes, not a `Blob` abstraction, which is removed. We generally don't need to expose any sort of message type distinction at the mailbox level; this simplifies implementation as well as hiding a bit more metadata from servers.
# Events and ordering

**Events** (application-level messages, like DMs and group messages) that are in the same conversation form an eventually consistent *thread*.

This is done by `Event` having a `after: Option<Hash>` field that points to the hash of the most recent `Event` in the thread that the sender has seen. This most recent `Event` must be something *already* committed by the server.

This way, later (by server `received_at`) `Event`s that point to previous ones are rejected by clients. Faulty or malicious servers cannot retroactively reorder user messages this way.

Clients should implement a unified, efficient abstraction for representing event threads.

We also no longer have a MIME-type-based system for encoding event type. Instead, we use a custom `u16` tag. MIME types are not the right abstraction for this level, since basically no events correspond to existing MIME types. MIME types are going to be used only for Attachments.

The `MESSAGE` event tag is used for most messages. Its payload is a BCS-encoded document containing:
- payload: MessageText (an enum containing Plain and Rich cases; eventually we might support Markdown etc)
- attachments: `Vec<Attachment>`
- replies_to: `Option<Hash>` (the hash is the event hash)
- metadata: `BTreeMap<SmolStr, String>`

Note that `Attachment` should have a server name indicating where it's hosted, as it's not always clear by the context (especially if users move between servers).
# DMs

DMs are sent to a mailbox advertised in the user's **user profile**. The mailbox key to this mailbox is distributed through device provisioning to each new device the user creates, so this mailbox MUST never change (and thus cache coherence is a non-issue).

The underlying events are also copied to our own mailbox, encrypted for our own devices. This allows us to sync outgoing messages across devices.

# Groups

Groups use two server primitives: **mailboxes** for message delivery and a **group registry** for access control state.

## Group bearer key

At the client-to-client level, we introduce a new concept, a **group bearer key (GBK)**, containing:
- an opaque 20-byte Group ID
- the server that the group is hosted on
- the group registry nonce (see below)
- a random nonce

Then, we derive the **group mailbox key** (and thus its ID) as well as the **group symmetric key** using a KDF on the GBK.

Thus, the GBK is truly a *bearer credential for read/write access to the group*, that bundles server and cryptographic enforcement in one object.

The entire history of a group under a single GBK is a single event thread for the purposes of the `after` field. Group events are signed then encrypted with the GBK.

Of course, only using GBKs doesn't allow people to be kicked from groups. We also don't have any forward secrecy. Both of these problems are solved by **GBK rotation**, which is managed through the group registry.

## Group registry

The server maintains a **group registry**: a key-value store where keys are arbitrary nonces (chosen at group creation time) and values are append-only logs of **rotation entries**.

The server-side state for each group registry entry is:
- `admin_set: Set<SigningPublic>` — the current set of admin device keys, mutable (replaced on each append)
- `log: Vec<RotationEntry>` — append-only, indexed by position (starting at 0)

Each `RotationEntry` contains:
1. `new_admin_set: Set<SigningPublic>` — replaces the current admin set upon acceptance
2. `gbk_rotation_message: Bytes` — an opaque encrypted blob (not verified by the server)

**Server behavior on append:** verify that the signature on the entry comes from a key in the current `admin_set`. If valid, accept the entry, append it to the log, and replace `admin_set` with `new_admin_set`. The server must reject appends where `new_admin_set` is empty (to prevent permanently freezing the group).

**Server behavior on read:** expose an endpoint that, given the registry nonce and a rotation index `i`, returns the `i`th rotation entry. This is stateless and cacheable.

Concurrent admin appends are resolved by natural optimistic concurrency: the server accepts whichever arrives first, which updates the `admin_set`, potentially invalidating the second append's signature. The rejected admin retries against the new state.

## GBK rotation

GBK rotation is managed entirely through the group registry, not through the group mailbox. 

When an admin rotates the GBK:
1. They construct a new GBK (with a fresh random nonce, same Group ID, same server, same registry nonce).
2. They construct the `gbk_rotation_message`: encrypted per-member blobs containing the new GBK, wrapped in device encryption so that only non-banned members receive it. This message also includes the **full group roster**, which allows any member to fully reconstruct group state from a single rotation entry.
3. They construct the `new_admin_set` reflecting any admin changes.
4. They sign and submit the rotation entry to the group registry.

**Client polling:** each client tracks the latest rotation index it has processed for each group. To check for rotations, it requests `get_rotation(nonce, last_index + 1)`. If a new entry exists, the client decrypts the GBK rotation message, derives the new mailbox key, and starts polling the new mailbox. This is simple, reliable, and gap-free — just a monotonic integer.

After processing a GBK rotation, clients should briefly (for a few hours) continue polling the old mailbox to catch messages from members who sent under the old GBK before they processed the rotation.

When an admin bans a user, they must also rotate the GBK (the banned user is simply excluded from the encrypted rotation message). Admins should also periodically rotate GBKs for forward secrecy purposes.

## Inline admin actions

Administrative actions that do **not** affect read access (muting, group name/description changes, role changes that don't modify the admin set) are sent inline as group events with the `GROUP_ADMIN_ACTION` tag. These are "soft" permissions that control client behavior — muted users' messages are ignored, only admins' inline actions take effect, etc.

The group roster for these soft permissions is reconstructed by processing inline admin actions. Since loss of a soft action is non-catastrophic (someone isn't muted when they should be), this is acceptable. Any drift is corrected at the next GBK rotation, which includes the full roster.

## Inviting people to groups

Anybody with an up-to-date GBK can join a group by starting to poll the mailbox. This is "lurking" and does not reveal membership until the user sends something.

When the user sends something, then the roster on every device changes to include that user and the message, unless the roster contains the "new users are muted" flag.

There is inherently no way of implementing a "new users must be approved by an admin to **read** the group" system. Existing users can always spy for other people, so you must allow users to freely invite others at least in a read only capacity. Otherwise it's pure security theater.

When you invite a person using a GBK, you only reveal messages sent under that and later GBKs. If you want to share previous history, you must keep previous GBKs.

But that would break forward secrecy. Thus, the group roster contains an advisory bit for "allow new users to see old messages" that can be set by admins. This advises (honest) clients whether or not to keep previous GBKs. (Dishonest clients can break FS anyway.)

**Currently, we should not expose the GBK in a "portable" way in the UI that lets people paste it around. For example, group invites, after they are accepted, should have the GBK inside of it redacted from the local database, and they should not be forwardable. Otherwise, forward secrecy may easily be accidentally defeated**.

Stable invite links will eventually be supported by a system that allows people to *request* being sent a GBK.
