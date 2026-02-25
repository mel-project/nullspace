# Directory RPC

This document specifies the RPC API exposed by the Nullspace directory service, corresponding to the `DirectoryProtocol` trait.

The directory is a public, verifiable key/value registry. For the data model, cryptographic primitives, transparency log, and Merkle proof format, see the [directory protocol spec](../protocol/directory.md).

For wire format, encoding conventions, and transport, see the [RPC overview](./).

## Methods

### `v1_get_pow_seed() -> pow_seed`

Returns a [proof-of-work seed](../protocol/directory.md#proof-of-work-rate-limiting) that can be used to rate-limit an update submission.

Clients SHOULD fetch a fresh seed shortly before calling `v1_insert_update`.

### `v1_get_anchor() -> anchor`

Returns the current signed [anchor](../protocol/directory.md#anchor) (directory head).

Clients MUST verify the anchor signature with the trusted directory public key.

### `v1_get_headers(first, last) -> [header]`

Returns [headers](../protocol/directory.md#header) in the inclusive range `[first, last]`.

Clients use this to sync and validate the header chain up to the anchor height.

### `v1_get_chunk(height) -> chunk`

Returns the [chunk](../protocol/directory.md#chunk) at `height`.

Clients MAY fetch chunks for audit, mirroring, or debugging. Inclusion proofs do not require chunks.

### `v1_get_item(key) -> [leaf_value_bytes_or_null, proof_height, compressed_proof_bytes]`

Returns:

- `leaf_value_bytes_or_null`: `null` for key absence, otherwise SMT leaf value bytes
- `proof_height`: the height of the header whose `smt_root` the proof targets
- `compressed_proof_bytes`: [compressed Merkle proof](../protocol/directory.md#proof-compression) bytes

Clients MUST:
- sync headers up to `proof_height`
- verify the Merkle proof against `header[proof_height].smt_root`

### `v1_insert_update(update, pow_solution) -> ()`

Submits an [update](../protocol/directory.md#updates) for the key/value registry.

Validation rules:
- `pow_solution` must be valid and unexpired
- update signature must verify under `signer_pk`
- `nonce` must be strictly greater than the current nonce floor for `key`
- authorization:
  - if the key has no committed owners, then the update MUST include `signer_pk` in `owners`
  - otherwise, `signer_pk` MUST be in the committed owners list

If accepted, the update is placed into the per-key mempool and will be applied at the next commit.

The directory MAY accept multiple updates for the same key without an intervening commit, as long as nonces are strictly increasing.

## Errors

In addition to the [common errors](./), the directory may return:

- `update_rejected(reason)`: permanent rejection for the given update (clients should not retry the same update)
