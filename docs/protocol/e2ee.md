# End-to-end encryption

The Signal Protocol (formerly known as Axolotl) and variations on it is the de facto standard for end-to-end encrypted messaging. Software using it includes Signal, WhatsApp, Facebook Messenger, Matrix (through its Olm and Megolm variations), Google Messages...

But Nullspace intentionally uses an E2EE scheme *very different from Signal Protocol*. We systematically avoid the "key ratcheting" design of Signal Protocol, etc, etc.

## Interesting design features

Some parts of the E2EE design are fairly conventional (e.g. we use XChaCha20, Ed25519, and Curve25519). Here we list some of the most "contrarian" design features.

- **We intentionally don't care about deniability**. 
    - Deniability complicates protocol design and is effectively impossible for large groups, where each message's authenticity must be verifiable by an unbounded number of counterparties, so triple-DH-style implicit authentication isn't going to work. (Even MLS isn't an exception to this rule; deniability there requires O(n^2) communication patterns over deniable 1-to-1 channels to distribute per-group signing keys on joining/leaving, which largely defeats the purpose of the complex machinery required to make ratcheting scale). 
    - Varying deniability between groups and DMs, or small groups and large groups, is unintuitive to users. Users will be surprised if, say, nobody can fake a chat transcript in a group, but people can fake chat transcripts in DMs; "can I ask for proof for this scandalous Nullspace convo going viral" should have a uniform answer either way.
    - Deniability also disproportionately impacts *more user-empowering* forms of non-repudiation while minimally affecting problematic forms. Powerful third parties have really good ways of getting proof that somebody said something, like subpoenaing server logs and confiscating devices, that don't require cryptographic non-repudiation. Deniable systems also don't prevent providers from offering effectively non-deniable "abuse report" features, i.e. users snitching each other out to the server (a unique server-side ID of the message and a copy of the unique symmetric key used to encrypt that message is enough to prove to the server that somebody said something). On the other hand, users can no longer trust, say, forwarded messages purporting to be from other users; if preventing forging "message quotes" is done by server-side logic instead, then it's even worse, since malicious servers can easily fool users who are accustomed to trusting the "original author" field displayed in the UI.
- **We use periodic rekeying rather than ratcheting**. Yes, this does mean we give up message-level FS/PCS.
    - Real-world compromise blast radii are *far* bigger than compromising a single key. There just isn't a realistic scenario where 1. all the keys on a device get compromised 2. no previous message history gets compromised 3. the attacker can't impersonate the user to download more messages, participate in further ratcheting, etc, at least for a small amount of time. 
    - This means that a *cryptographic* compromise blast radius of smaller than a few hours is unlikely to improve security. Message-granularity FS/PCS is way overkill. Periodic rekeying is a perfectly reasonable way of getting coarse-grained FS/PCS, where compromising all keys on a device allows decrypting messages within a few hours in the future and the past, but nothing further.
    - In return, we get totally game-changing implementation and performance benefits:
        - Huge group sizes are possible. "Discord server"-sized communites that are entirely E2EE are now realistic.
        - Client implementations are far less complex and stateful. Signal and WhatsApp are probably the only Signal Protocol implementations that don't occasionally glitch out with "decryption failed".
        - Client correctness no longer relies on atomically durable storage, restoring devices from old backups no longer cause catastrophic failures, ...

## Basic primitives

Before we discuss the specific protocols, it's useful to outline a few primitives.

### Events

An event is the plaintext payload carried inside encrypted messages. It is BCS-encoded as:

```
[recipient, sent_at, mime, body]
```

- `recipient`: `["user", username]` (for DMs) or `["group", group_id]` (for group chats)
- `sent_at`: Unix timestamp (nanoseconds)
- `mime`: a MIME type string
- `body`: opaque bytes

### Tagged blobs

Many places in the protocol carry opaque, tagged payloads as a **tagged blob**:

```
[kind, inner]
```

- `kind`: a string tag like `v1.message_content` or `v1.group_message`
- `inner`: raw bytes whose interpretation depends on `kind`

Tagged blobs are BCS-encoded.

### Header encryption

Header encryption encrypts a message such that any member of a group of devices, each with their own Diffie-Hellman keypair, can decrypt it. For reasons that will be clear later, the keys that these devices hold are known as the **medium-term keys** of the devices.

Header encryption, by itself, provides no authentication of the sender or contents whatsoever. It's insecure used by itself!

Structure:
- A header-encrypted message is a BCS-encoded tuple `[sender_epk, headers, body]`.
- `sender_epk` is a fresh ephemeral Diffie-Hellman public key generated per message.
- `headers` is a list of per-recipient entries. Each entry carries an index hint derived from the recipient's medium-term public key, plus an encrypted copy of a fresh per-message AEAD key.
- `body` is the message ciphertext encrypted under that per-message AEAD key, with AAD that commits to `sender_epk` and `headers`.

In pseudocode:

```
header_encrypt(recipients_mpk[], plaintext_bytes):
    sender_esk = x25519_random_secret()
    sender_epk = x25519_public(sender_esk)
    k = random_bytes(32)  // per-message AEAD key

    headers = []
    for receiver_mpk in recipients_mpk:
        receiver_mpk_short = h(bcs_encode(receiver_mpk))[0..2]
        ss = x25519_dh(sender_esk, receiver_mpk)
        receiver_key = xchacha20_encrypt(key=ss, nonce=0, plaintext=k)  // stream cipher, no auth
        headers += [receiver_mpk_short, receiver_key]

    aad = bcs_encode([sender_epk, headers])
    body = xchacha20_poly1305_encrypt(key=k, nonce=0, aad=aad, plaintext=plaintext_bytes)
    return bcs_encode([sender_epk, headers, body])

header_decrypt(my_msk, header_encrypted_bytes):
    [sender_epk, headers, body] = bcs_decode(header_encrypted_bytes)
    my_mpk_short = h(bcs_encode(x25519_public(my_msk)))[0..2]
    ss = x25519_dh(my_msk, sender_epk)
    aad = bcs_encode([sender_epk, headers])

    for header in headers where header.receiver_mpk_short == my_mpk_short:
        k = xchacha20_decrypt(key=ss, nonce=0, ciphertext=header.receiver_key)
        if xchacha20_poly1305_decrypt(key=k, nonce=0, aad=aad, ciphertext=body) succeeds:
            return plaintext_bytes

    fail
```

Notes:
- `h(...)` is BLAKE3.
- The 2-byte `receiver_mpk_short` is only an index hint and may collide; the decryptor tries all matching candidates.
- Nonce `0` is safe here because both `ss` and `k` are per-message fresh.

### Device signing

Device signing signs an arbitrary message in such a way that proves that it's signed by a device belonging to a particular username, as long as the recipient has access to directory lookups for that username. This is useful to allow recipients to avoid fetching device lists from "foreign" servers in order to decrypt messages, only to encrypt them.

Structure:
- A device-signed message is a BCS-encoded tuple `[sender, cert_chain, body, signature]`.
- `sender` and `cert_chain` identify which device is doing the signing, and allow recipients to validate that the device belongs to `sender` via directory verification.
- `body` is opaque bytes; recipients interpret it according to the context where device signing is used.
- `signature` authenticates the tuple `(sender, cert_chain, body)`.

In pseudocode:

```
device_sign(sender_username, sender_cert_chain, sender_device_signing_sk, body_bytes):
    payload = [sender_username, sender_cert_chain, body_bytes]
    signature = ed25519_sign(sender_device_signing_sk, bcs_encode(payload))
    return bcs_encode([sender_username, sender_cert_chain, body_bytes, signature])

device_verify(device_signed_bytes, trusted_root_hash):
    [sender, cert_chain, body, signature] = bcs_decode(device_signed_bytes)
    verify_certificate_chain(cert_chain, trusted_root_hash)  // see [devices.md](devices.md)
    sender_device_pk = cert_chain.leaf_device_public_key
    ed25519_verify(sender_device_pk, signature, bcs_encode([sender, cert_chain, body]))
    return (sender, body)
```

The signature is over the full tuple `(sender, cert_chain, body)` rather than just `body` as defense-in-depth against malleability.

## DM encryption

If Alice wants to send a plaintext [event](events.md) as a DM to Bob:

- A DM is sent as a mailbox entry whose `kind` is `v1.direct_message`.
- The mailbox `body` is a header-encrypted payload (see "Header encryption").
- The header-encrypted plaintext is a device-signed payload (see "Device signing").
- The device-signed `body` is a tagged blob whose `kind` is `v1.message_content`, and whose `inner` is a BCS-encoded [event](events.md).

```
send_dm(to_username, event):
    event_bytes = bcs_encode(event)
    msg_blob_bytes = bcs_encode(["v1.message_content", event_bytes])
    signed_bytes = device_sign(my_username, my_cert_chain, my_device_signing_sk, msg_blob_bytes)
    recipients_mpk = fetch_all_medium_public_keys(to_username)
    he_bytes = header_encrypt(recipients_mpk, signed_bytes)
    mailbox_send(mailbox=direct_mailbox(to_username), kind="v1.direct_message", body=he_bytes)
```

On receive, Bob does:

```
recv_dm(he_bytes):
    signed_bytes = header_decrypt(my_medium_sk_current, he_bytes)
        or header_decrypt(my_medium_sk_previous, he_bytes)
    (sender_username, msg_blob_bytes) = device_verify(signed_bytes, directory_root_hash(sender_username))
    [kind, inner] = bcs_decode(msg_blob_bytes)
    assert kind == "v1.message_content"
    event = bcs_decode(inner)
    return event
```

Each participant periodically refreshes their medium-term keys, at an interval *not more frequent than* once every hour (so that caching lookups for 1 hour is always safe). Participants also keep around their previous medium-term key to decrypt any out-of-order messages.

This ensures FS/PCS within 2 hours.

## Group encryption

Group messages are encrypted with a symmetric group key shared by all active members. The exact group message format and the group management semantics are specified in [groups.md](groups.md).

### Group rekeys

- A group rekey is sent as a mailbox entry whose `kind` is `v1.group_rekey`.
- The mailbox `body` is a header-encrypted payload (see "Header encryption").
- The header-encrypted plaintext is a device-signed payload (see "Device signing").
- The device-signed `body` is a BCS-encoded tuple `[group_id, new_group_key_bytes]`.

Group rekeys are distributed with header encryption:

```
send_group_rekey(group_id, new_group_key_bytes):
    payload_bytes = bcs_encode([group_id, new_group_key_bytes])
    signed_bytes = device_sign(my_username, my_cert_chain, my_device_signing_sk, payload_bytes)
    recipients_mpk = fetch_all_medium_public_keys_of_active_members(group_id)
    he_bytes = header_encrypt(recipients_mpk, signed_bytes)
    mailbox_send(mailbox=group_messages_mailbox(group_id), kind="v1.group_rekey", body=he_bytes)
```

Group membership, invites, bans, admins, and management messages are specified in [groups.md](groups.md). Ultimately, these messages make sure everybody has the same understanding of the **roster** (who's in the group and who has what permissions), which is important for rekeys to be decryptable by the correct set of participants.
