# End-to-end encryption

The Signal Protocol (formerly known as Axolotl) and variations on it is the de facto standard for end-to-end encrypted messaging. Software using it includes Signal, WhatsApp, Facebook Messenger, Matrix (through its Olm and Megolm variations), Google Messages...

But Xirtam intentionally uses an E2EE scheme *very different from Signal Protocol*. We systematically avoid the "key ratcheting" design of Signal Protocol, etc, etc.

## Interesting design features

Some parts of the E2EE design are fairly conventional (e.g. we use XChaCha20, Ed25519, and Curve25519). Here we list some of the most "contrarian" design features.

- **We intentionally don't care about deniability**. 
    - Deniability complicates protocol design and is effectively impossible for large groups, where each message's authenticity must be verifiable by an unbounded number of counterparties, so triple-DH-style implicit authentication isn't going to work. (Even MLS isn't an exception to this rule; deniability there requires O(n^2) communication patterns over deniable 1-to-1 channels to distribute per-group signing keys on joining/leaving, which largely defeats the purpose of the complex machinery required to make ratcheting scale). 
    - Varying deniability between groups and DMs, or small groups and large groups, is unintuitive to users. Users will be surprised if, say, nobody can fake a chat transcript in a group, but people can fake chat transcripts in DMs; "can I ask for proof for this scandalous Xirtam convo going viral" should have a uniform answer either way.
    - Deniability also disproportionately impacts *more user-empowering* forms of non-repudiation while minimally affecting problematic forms. Powerful third parties have really good ways of getting proof that somebody said something, like subpoenaing server logs and confiscating devices, that don't require cryptographic non-repudiation. Deniable systems also don't prevent providers from offering effectively non-deniable "abuse report" features, i.e. users snitching each other out to the server (a unique server-side ID of the message and a copy of the unique symmetric key used to encrypt that message is enough to prove to the server that somebody said something). On the other hand, users can no longer trust, say, forwarded messages purporting to be from other users; if preventing forging "message quotes" is done by server-side logic instead, then it's even worse, since malicious servers can easily fool users who are accustomed to trusting the "original author" field displayed in the UI.
- **We use periodic rekeying rather than ratcheting**. Yes, this does mean we give up message-level FS/PCS.
    - Real-world compromise blast radii are *far* bigger than compromising a single key. There just isn't a realistic scenario where 1. all the keys on a device get compromised 2. no previous message history gets compromised 3. the attacker can't impersonate the user to download more messages, participate in further ratcheting, etc, at least for a small amount of time. 
    - This means that a *cryptographic* compromise blast radius of smaller than a few hours is unlikely to improve security. Message-granularity FS/PCS is way overkill. Periodic rekeying is a perfectly reasonable way of getting coarse-grained FS/PCS, where compromising all keys on a device allows decrypting messages within a few hours in the future and the past, but nothing further.
    - In return, we get totally game-changing implementation and performance benefits:
        - Huge group sizes are possible. "Discord server"-sized communites that are entirely E2EE are now realistic.
        - Client implementations are far less complex and stateful. Signal and WhatsApp are probably the only Signal Protocol implementations that don't occasionally glitch out with "decryption failed".
        - Client correctness no longer relies on atomically durable storage, restoring devices from old backups no longer cause catastrophic failures, ...

## Basic primitives

Before we discuss the specific protocols, it's useful to outline three primitives.

### Events

An event is the plaintext payload carried inside encrypted messages. It contains:
- `recipient`, either a username (for DMs) or a group ID (for group chats)
- `sent_at`, a timestamp
- `mime`, a MIME type string
- `body`, opaque bytes

### Header encryption

Header encryption encrypts a message such that any member of a group of devices, each with their own Diffie-Hellman keypair, can decrypt it. For reasons that will be clear later, the keys that these devices hold are known as the **medium-term keys** of the devices.

Header encryption, by itself, provides no authentication of the sender or contents whatsoever. It's insecure used by itself!

A header-encrypted message is BCS-encoded with the following fields:
- `sender_epk`, an ephemeral, one-time DH public key (the secret side is called `sender_esk`)
- `headers`, a list of headers, each of which contains:
    - `headers[i].receiver_mpk_short`, the first 2 bytes of the hash of the receiver medium-term public key, `H(receiver_mpk)`. This may collide, that is fine.
    - `headers[i].receiver_key`, the 32-byte, per-message symmetric key `K` encrypted with `DH(sender_esk, receiver_mpk)` using XChaCha20 (no Poly1305) with a zero nonce.
- `body`, a message encrypted with `K` using XChaCha20-Poly1305 with a zero nonce, and aad being `[sender_epk, headers]`

### Device signing

Device signing signs an arbitrary message in such a way that proves that it's signed by a device belonging to a particular username, as long as the recipient has access to directory lookups for that username. This is useful to allow recipients to avoid fetching device lists from "foreign" servers in order to decrypt messages, only to encrypt them.

A device-signed message is BCS-encoded with the following fields:
- `sender`, a username
- `cert_chain`, a [certificate chain](devices.md) identifying a device owned by `sender`
- `body`, arbitrary plaintext bytes
- `signature`, an ed25519 signature over the BCS encoding of `(sender, cert_chain, body)`

## DM encryption

If Alice wants to send a plaintext [event](events.md) as a DM to Bob:
- Alice device-signs the plaintext she wants to send, using one of her device secret keys.
- Alice fetches all of Bob's device medium-term keys.
- Alice header-encrypts the device-signed plaintext to all of Bob's devices.
- Alice sends the header-encrypted bundle to Bob's mailbox, as a blob of kind `v1.direct_message`.

Each participant periodically refreshes their medium-term keys, at an interval *not more frequent than* once every hour (so that caching lookups for 1 hour is always safe). Participants also keep around their previous medium-term key to decrypt any out-of-order messages.

This ensures FS/PCS within 2 hours.

## Group encryption

Group messages are encrypted with a symmetric group key shared by all active members. If Alice wants to send a plaintext [event](events.md) to a group:
- Alice device-signs the plaintext she wants to send.
- Alice encrypts the device-signed payload with the current group key using XChaCha20-Poly1305 with a random nonce.
- Alice sends the ciphertext as a blob of kind `v1.group_message` to the group's message mailbox.
- Recipients decrypt using the current group key, falling back to the previous group key, then verify the device signature against the sender's directory root.

Group rekeys are distributed with header encryption:
- An active admin periodically generates a fresh group key.
- The admin wraps the new key bytes in a blob of kind `v1.aead_key`, device-signs it, and header-encrypts it to all active members' medium-term keys.
- The header-encrypted blob is sent to the group's message mailbox as kind `v1.group_rekey`.
- Recipients decrypt using their medium-term keys, verify the device signature, ensure the sender is an active admin, and then rotate the previous/current group keys.
