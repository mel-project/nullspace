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

Servers are no longer "group-aware" in any way. We continue to use the same dumb mailbox primitive.
## Group bearer key

At the client-to-client level, we introduce a new concept, a **group bearer key**, containing:
- an opaque 20-byte Group ID
- (if this is not the first GBK) a previous GBK hash
- the server that the group is hosted on
- a random nonce

Then, we derive the **group mailbox key** (and thus its ID) as well as the **group symmetric key** using a KDF on the GBK.

Thus, the GBK is truly a *bearer credential for read/write access to the group*, that bundles server and cryptographic enforcement in one object.

The entire history of a group is a single event thread for the purposes of the `after` field. Group events are signed then encrypted with the GBK.

Of course, only using GBKs doesn't allow people to be kicked from groups. We also don't have any forward secrecy. Both of these problems are solved by **GBK rotation**. But before we talk about that, we need to talk about administrative actions in general.
## Admin actions

Admin actions in groups are events of tag `GROUP_ADMIN_ACTION`. They have two main purposes: 
- Transitioning the **group roster**, which contains the permissions for everybody in the group. These permissions are "soft" permissions that control client behavior; for example, only admins' admin actions actually take effect, and muted/absent users' messages are entirely ignored. The group roster is not stored at the server, but rather *reconstructed by everybody in the group as they process admin actions*.
- GBK rotation. This is a message instructing all group members to move to a different GBK for the group. The actual GBK itself is wrapped in device encryption so that only non-banned members of the group are notified of the new GBK.

All admin actions contain a one-by-one increasing counter to prevent races. Ties are broken by earlier received_at.

When an admin bans a user, it must also send a GBK rotation. Otherwise, it periodically sends GBK rotations for forward secrecy purposes.

When we receive a GBK rotation, we continue polling the old mailbox to catch any out of order messages from people who haven't seen the GBK rotation yet. 
## Inviting people to groups 

Anybody with an up to date GBK can join a group by starting to poll the mailbox. This is "lurking" and does not reveal membership until the user sends something.

When the user sends something, then the roster on every device changes to include that user and the message, unless the roster contains the "new users are muted" flag.

There is inherently no way of implementing a "new users must be approved by an admin to **read** the group" system. Existing users can always spy for other people, so you must allow users to freely invite others at least in a read only capacity. Otherwise it's pure security theater.

When you invite a person using a GBK, you only reveal messages sent under that and later GBKs. If you want to share previous history, you must keep previous GBKs.

But that would break forward secrecy. Thus, the group roster contains an advisory bit for "allow new users to see old messages" that can be set by admins. This advises (honest) clients whether or not to keep previous GBKs. (Dishonest clients can break FS anyway.)

**Currently, we should not expose the GBK in a "portable" way in the UI that lets people paste it around. For example, group invites, after they are accepted, should have the GBK inside of it redacted from the local database, and they should not be forwardable. Otherwise, forward secrecy may easily be accidentally defeated**.

Stable invite links will eventually be supported by a system that allows people to *request* being sent a GBK.
