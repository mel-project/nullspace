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

Before we discuss the specific protocols, it's useful to outline a few primitives.

### Events

An event is the plaintext payload carried inside encrypted messages. It is BCS-encoded as:

```
[recipient, sent_at, mime, body]
```

- `recipient`: either a username (for DMs) or a group ID (for group chats)
- `sent_at`: a timestamp
- `mime`: a MIME type string
- `body`: opaque bytes

### Tagged blobs

Many places in the protocol carry opaque, tagged payloads as a **tagged blob**:

```
[kind, inner]
```

- `kind`: a string tag like `v1.message_content` or `v1.aead_key`
- `inner`: raw bytes whose interpretation depends on `kind`

Tagged blobs are BCS-encoded.

### Header encryption

Header encryption encrypts a message such that any member of a group of devices, each with their own Diffie-Hellman keypair, can decrypt it. For reasons that will be clear later, the keys that these devices hold are known as the **medium-term keys** of the devices.

Header encryption, by itself, provides no authentication of the sender or contents whatsoever. It's insecure used by itself!

In pseudocode:

```
HeaderEncrypt(recipients_mpk[], plaintext_bytes):
    sender_esk = X25519.RandomSecret()
    sender_epk = X25519.Public(sender_esk)
    K = RandomBytes(32)  // per-message AEAD key

    headers = []
    for receiver_mpk in recipients_mpk:
        receiver_mpk_short = H(bcs_encode(receiver_mpk))[0..2]
        ss = X25519.DH(sender_esk, receiver_mpk)
        receiver_key = XChaCha20(key=ss, nonce=0).Encrypt(K)  // stream cipher, no auth
        headers += [receiver_mpk_short, receiver_key]

    aad = bcs_encode([sender_epk, headers])
    body = XChaCha20-Poly1305(key=K, nonce=0, aad=aad).Encrypt(plaintext_bytes)
    return bcs_encode([sender_epk, headers, body])

HeaderDecrypt(my_msk, header_encrypted_bytes):
    [sender_epk, headers, body] = bcs_decode(header_encrypted_bytes)
    my_mpk_short = H(bcs_encode(X25519.Public(my_msk)))[0..2]
    ss = X25519.DH(my_msk, sender_epk)
    aad = bcs_encode([sender_epk, headers])

    for header in headers where header.receiver_mpk_short == my_mpk_short:
        K = XChaCha20(key=ss, nonce=0).Decrypt(header.receiver_key)
        if XChaCha20-Poly1305(key=K, nonce=0, aad=aad).Decrypt(body) succeeds:
            return plaintext_bytes

    fail
```

Notes:
- `H(...)` is BLAKE3.
- The 2-byte `receiver_mpk_short` is only an index hint and may collide; the decryptor tries all matching candidates.
- Nonce `0` is safe here because both `ss` and `K` are per-message fresh.

### Device signing

Device signing signs an arbitrary message in such a way that proves that it's signed by a device belonging to a particular username, as long as the recipient has access to directory lookups for that username. This is useful to allow recipients to avoid fetching device lists from "foreign" servers in order to decrypt messages, only to encrypt them.

In pseudocode:

```
DeviceSign(sender_username, sender_cert_chain, sender_device_signing_sk, body_bytes):
    payload = [sender_username, sender_cert_chain, body_bytes]
    signature = Ed25519.Sign(sender_device_signing_sk, bcs_encode(payload))
    return bcs_encode([sender_username, sender_cert_chain, body_bytes, signature])

DeviceVerify(device_signed_bytes, trusted_root_hash):
    [sender, cert_chain, body, signature] = bcs_decode(device_signed_bytes)
    VerifyCertificateChain(cert_chain, trusted_root_hash)  // see [devices.md](devices.md)
    sender_device_pk = cert_chain.leaf_device_public_key
    Ed25519.Verify(sender_device_pk, signature, bcs_encode([sender, cert_chain, body]))
    return (sender, body)
```

The signature is over the full tuple `(sender, cert_chain, body)` rather than just `body` as defense-in-depth against malleability.

## DM encryption

If Alice wants to send a plaintext [event](events.md) as a DM to Bob:

```
SendDM(to_username, event):
    event_bytes = bcs_encode(event)
    msg_blob_bytes = bcs_encode(["v1.message_content", event_bytes])
    signed_bytes = DeviceSign(my_username, my_cert_chain, my_device_signing_sk, msg_blob_bytes)
    recipients_mpk = FetchAllMediumPublicKeys(to_username)
    he_bytes = HeaderEncrypt(recipients_mpk, signed_bytes)
    MailboxSend(mailbox=DirectMailbox(to_username), kind="v1.direct_message", body=he_bytes)
```

On receive, Bob does:

```
RecvDM(he_bytes):
    signed_bytes = HeaderDecrypt(my_medium_sk_current, he_bytes)
        or HeaderDecrypt(my_medium_sk_previous, he_bytes)
    (sender_username, msg_blob_bytes) = DeviceVerify(signed_bytes, DirectoryRootHash(sender_username))
    [kind, inner] = bcs_decode(msg_blob_bytes)
    assert kind == "v1.message_content"
    event = bcs_decode(inner)
    return event
```

Each participant periodically refreshes their medium-term keys, at an interval *not more frequent than* once every hour (so that caching lookups for 1 hour is always safe). Participants also keep around their previous medium-term key to decrypt any out-of-order messages.

This ensures FS/PCS within 2 hours.

## Group encryption

Group messages are encrypted with a symmetric group key shared by all active members. The exact group message format and the group management semantics are specified in [groups.md](groups.md).

Group rekeys are distributed with header encryption:

```
SendGroupRekey(group_id, new_group_key_bytes):
    key_blob_bytes = bcs_encode(["v1.aead_key", bcs_encode([group_id, new_group_key_bytes])])
    signed_bytes = DeviceSign(my_username, my_cert_chain, my_device_signing_sk, key_blob_bytes)
    recipients_mpk = FetchAllMediumPublicKeysOfActiveMembers(group_id)
    he_bytes = HeaderEncrypt(recipients_mpk, signed_bytes)
    MailboxSend(mailbox=GroupMessagesMailbox(group_id), kind="v1.group_rekey", body=he_bytes)
```

Group membership, invites, bans, admins, and management messages are specified in [groups.md](groups.md).
