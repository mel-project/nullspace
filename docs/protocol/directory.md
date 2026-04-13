# Directory

This document specifies the directory service: a public, verifiable key/value registry.

The directory is intentionally *untyped*: it does not know what any key “means”. Higher-level protocol layers define conventions for which keys exist (for example `@...` usernames) and what their values encode.

## Data model

The directory stores a sparse Merkle tree (SMT) whose leaves commit to **per-key state**:

```
key_state = [nonce_max, owners, value]
```

- `nonce_max`: unsigned integer
- `owners`: set of signing public keys
- `value`: bytes (empty bytes allowed)

`key_state` is BCS-encoded and stored as the SMT leaf value bytes.

### Key strings

Keys are arbitrary UTF-8 strings. The SMT path is derived from the bytes of the UTF-8 string.

### Key absence vs. empty payload

There are two distinct situations:

- **key absent**: the SMT stores an empty byte string for the leaf
- **key present with empty payload**: the SMT stores `BCS(key_state)` where `value = []`

## Cryptographic primitives

### Hashes

`H(x)` is unkeyed BLAKE3, producing 32 bytes.

When transported as JSON:
- 32-byte hashes are hex strings

### Signing keys

Keys and signatures use Ed25519:

- signing public key: 32 bytes
- signature: 64 bytes

When transported as JSON:
- keys and signatures are URL-safe base64 without padding

### Sparse Merkle tree hashing

The SMT uses two domain-separated keyed BLAKE3 hashes:

- `hash_data(bytes)`:
  - if `bytes` is empty, return `[0; 32]`
  - otherwise return `BLAKE3_KEYED(key = H("smt_datablock"), msg = bytes)`
- `hash_node(left, right)`:
  - if `left == [0; 32]` and `right == [0; 32]`, return `[0; 32]`
  - otherwise return `BLAKE3_KEYED(key = H("smt_node"), msg = left || right)`

The SMT path for a directory key `k` is derived from:

```
path_key = H(utf8_bytes(k))
```

and then interpreting `path_key` as 256 bits (MSB-first).

## Transparency log

The directory exposes a linear chain of headers and associated chunks.

### Header

A header is:

```
header = [prev, smt_root, time_unix]
```

- `prev`: hash of the previous header (or `[0; 32]` for genesis)
- `smt_root`: SMT root hash after applying this chunk
- `time_unix`: Unix timestamp in seconds

The **header hash** is:

```
header_hash = H(BCS(header))
```

Headers form a chain where:

```
header[i].prev == header_hash[i-1]
```

### Chunk

A chunk is:

```
chunk = [header, updates_by_key]
```

where `updates_by_key` maps `key -> [update, update, ...]`.

Chunks are for replay/audit; the SMT commits only to current `key_state`.

### Anchor

An anchor authenticates the current directory head:

```
anchor = [directory_id, last_header_height, last_header_hash, signature]
```

The signature covers:

```
sign_bytes = BCS([directory_id, last_header_height, last_header_hash])
signature = ed25519_sign(directory_secret, sign_bytes)
```

Clients MUST know the directory public key out-of-band and MUST verify the anchor signature before trusting the head.

## Updates

An update replaces the entire key state (owners + value) and increments the nonce:

```
update = [key, nonce, signer_pk, owners, value, signature]
```

The signature covers:

```
sign_bytes = BCS([key, nonce, signer_pk, owners, value])
signature = ed25519_sign(signer_sk, sign_bytes)
```

## Proof-of-work (rate limiting)

Updates are rate-limited with a proof-of-work (PoW) challenge.

A PoW seed is:

```
pow_seed = [algo, seed, use_before]
```

- `algo`: currently `equix(effort)`
- `seed`: 32 bytes
- `use_before`: Unix timestamp in seconds

A PoW solution is:

```
pow_solution = [seed, nonce, solution_bytes]
```

The directory verifies that:
- `pow_solution.seed` is an issued seed that has not expired
- `pow_solution` satisfies the configured `effort` for that seed under the chosen algorithm

## Merkle proofs

`get_item` returns a Merkle branch proving inclusion or non-inclusion of the key’s current leaf value under a specific header’s `smt_root`.

A full proof is a list of 256 sibling hashes:

```
full_proof = [sib_0, sib_1, ..., sib_255]
```

where each `sib_i` is 32 bytes.

To verify:

1) Compute `path_key = H(utf8_bytes(key))`.
2) Let `bits` be the 256 bits of `path_key` in MSB-first order.
3) Let `node = hash_data(leaf_value_bytes)`, where `leaf_value_bytes` is:
   - empty bytes for non-inclusion
   - `BCS(key_state)` for inclusion
4) For `i` from 255 down to 0:
   - if `bits[i] == 0`: `node = hash_node(node, full_proof[i])`
   - if `bits[i] == 1`: `node = hash_node(full_proof[i], node)`
5) The proof is valid if `node == smt_root`.

### Proof compression

To reduce size, the directory transmits a compressed proof:

```
compressed_proof = bitmap || siblings
```

- `bitmap`: 32 bytes (256 bits, MSB-first)
- `siblings`: concatenation of all non-zero sibling hashes (each 32 bytes), in increasing level order `0..255`

The bitmap has:
- bit `i = 1` if `sib_i` is the all-zero hash `[0; 32]`
- bit `i = 0` otherwise (and then a 32-byte sibling is present in `siblings`)

Clients can decompress by walking the bitmap left-to-right and consuming 32-byte hashes from `siblings` for each zero bit.

## RPC API

The directory RPC methods are specified in [Directory RPC](../rpc/directory.md).
