# Attachments

This document specifies Nullspace file attachments: how files are represented, uploaded, sent, and downloaded.

## Overview

An attachment is sent as a normal [event](events.md) whose:

- `mime` is `application/vnd.nullspace.v1.attachment`
- `body` is a JSON-encoded **attachment root**

The attachment root is an index that:

- names the file (`filename`) and its media type (`mime`)
- contains a symmetric content key (`content_key`) used to encrypt file data
- points to the file bytes via a content-addressed fragment tree (`children`)

Fragments are stored on the uploader’s server in a content-addressed store and are fetched by recipients from that server.

Image messages use a related event MIME, `application/vnd.nullspace.v1.imageattachment`, whose JSON body is:

- `width`: original image width in pixels
- `height`: original image height in pixels
- `thumbhash`: base91 ThumbHash string
- `inner`: attachment root object

## Content addressing

Fragments and roots are identified by a 32-byte hash:

```
id(x) = blake3(BCS_encode(x))
```

In particular, a fragment’s ID is computed from the fragment value’s **BCS encoding** (sometimes called a “BCS hash”). This is independent of how the fragment is transported over RPC (for example, as JSON).

Recipients SHOULD verify that downloaded objects hash to their expected IDs.

## Attachment root (event body)

The attachment root is a JSON object with these fields:

- `filename`: string (suggested save name)
- `mime`: string (media type, e.g. `image/png`)
- `children`: list of `[hash, size]` pairs, where:
  - `hash` is the fragment ID (hex string)
  - `size` is the fragment’s total plaintext size in bytes (integer)
- `content_key`: 32-byte symmetric key (URL-safe base64 without padding)

If `children` is empty, the attachment is the empty file.

### Confidentiality

Leaf fragments contain ciphertext and recipients decrypt each leaf using:

- algorithm: XChaCha20-Poly1305
- nonce: 24 bytes (stored in the leaf)
- AAD: empty

## Fragment formats

Fragments are uploaded and downloaded using server RPC calls (see “Upload and download”).

A fragment is one of these structured values:

- `node`: contains a list of child pointers
- `leaf`: contains a file chunk (plaintext or ciphertext)

Fragment IDs are computed from the BCS encoding of these structured values. Implementations MUST NOT compute fragment IDs by hashing JSON text or any other transport-level encoding.

### BCS encoding of a fragment (tagged variant)

For hashing, the fragment value is encoded as a BCS **externally tagged variant**:

1) Encode the variant tag as ULEB128 `u32`.
2) Encode that variant's payload immediately after the tag.

Canonical tags for this protocol are:

- `0` = `node`
- `1` = `leaf`

So the hashed value is:

- `node(children)` -> `BCS([0, children])`
- `leaf(nonce, data)` -> `BCS([1, nonce, data])`

where:

- `children` is a list of `[hash, size]`
- `nonce` is 24 bytes
- `data` is bytes

### Fragment node

A node contains a list of `[hash, size]` child pointers. The `children` list is interpreted the same way as the root’s `children`.

### Fragment leaf

A leaf contains:

- `nonce`: 24 bytes
- `data`: bytes

`data` is an AEAD ciphertext.

## Upload and download

### Uploading fragments

To upload a fragment to a server’s fragment store:

```
v1_upload_frag(auth_token, fragment, ttl_seconds)
```

- The server MUST reject uploads if `auth_token` is not authorized.
- `ttl_seconds = 0` means “no expiry”.

### Downloading fragments

To download a fragment by ID:

```
v1_download_frag(fragment_id) -> fragment | null
```

If the server returns `null`, the fragment is missing (expired or never uploaded).

## End-to-end flow

### Sending an attachment

At a high level:

```
send_attachment(file_bytes, filename, file_mime):
    content_key = random_32_bytes()
    leaves = chunk(file_bytes)

    for each leaf:
        nonce = random_24_bytes()
        leaf.data = aead_encrypt(content_key, nonce, plaintext_chunk)
        upload leaf

    build and upload internal nodes
    root = { filename, mime: file_mime, children: top_level_children, content_key }
    send event with (mime = application/vnd.nullspace.v1.attachment, body = json_encode(root))
```

Chunk size and tree shape are not protocol-visible as long as `children` sizes sum to the total plaintext length.

### Receiving an attachment

On receive of an attachment event:

1) Decode the JSON root from the event body.
2) Optionally compute `attachment_id = id(root)` as a stable local identifier.
3) When the user chooses to download:
   - resolve the sender’s server via the directory
   - recursively fetch fragments from the sender’s server
   - verify each fragment’s hash matches its expected ID
   - decrypt leaf chunks
   - write the resulting bytes to disk
