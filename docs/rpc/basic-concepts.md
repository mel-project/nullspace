# Basic concepts

There are two RPC protocols:

| Protocol | Participants | Purpose |
| --- | --- | --- |
| [Server RPC](server.md) | client ↔ server | Mailboxes, device auth, key publication, attachments, proxying |
| [Directory RPC](directory.md) | client ↔ directory | Verifiable key/value registry lookups and updates |

## JSON-RPC 2.0

All Nullspace RPC protocols use the [JSON-RPC 2.0](https://www.jsonrpc.org/specification) wire format with **positional parameters** (JSON arrays, not named objects).

Method names are the exported RPC method names themselves. The current implementation does not add a `v1_` prefix on the wire.

## Transport

RPC calls are transported over one of:

- **HTTPS** — standard HTTP POST with `Content-Type: application/json`
- **TCP** — raw TCP streams carrying newline-delimited JSON-RPC messages
- **LZ4-TCP** — LZ4-compressed TCP streams

### URL scheme

Endpoints are identified by URLs. The URL scheme selects the transport:

| Scheme | Transport |
| --- | --- |
| `http://`, `https://` | HTTP POST |
| `tcp://` | Raw TCP |
| `lz4tcp://` | LZ4-compressed TCP |

For instance, `http://example.com/some-path` indicates a JSON-RPC endpoint hosted at `example.com` at the `POST /some-path` endpoint, and `lz4tcp://example.com:12345` indicates LZ4-TCP on port 12345.

### LZ4-TCP

Both TCP and LZ4-TCP use the same framing: newline-delimited JSON-RPC messages over a persistent TCP connection. Each line is a complete JSON-RPC request or response object.

LZ4-TCP wraps the entire bidirectional byte stream in [LZ4 frame compression](https://github.com/lz4/lz4/blob/dev/doc/lz4_Frame_format.md). The compressor is flushed after every message so that each JSON-RPC message is delivered immediately without waiting for the compressor's internal buffer to fill.

In other words, the layering is:

```
TCP socket
 └─ LZ4 frame stream (each direction independently compressed)
     └─ newline-delimited JSON lines
         └─ JSON-RPC 2.0 request/response objects
```

Since most messages in Nullspace are encrypted, the purpose of LZ4-TCP isn't *really* compression; instead, it's to squash away any inefficiencies due to JSON encoding. For instance, attachment uploads/downloads are necessarily Base64-encoded, but over LZ4-TCP the bandwidth overhead is basically nil. This means we don't have to figure out clever ways of efficiently encoding objects. 

## Common encoding conventions

### Binary values in JSON

| Type | Size | JSON encoding |
| --- | --- | --- |
| BLAKE3 hash | 32 bytes | lowercase hex string |
| Auth token | 20 bytes | lowercase hex string |
| Ed25519 public key | 32 bytes | URL-safe base64, no padding |
| Ed25519 signature | 64 bytes | URL-safe base64, no padding |
| X25519 public key | 32 bytes | URL-safe base64, no padding |
| Opaque bytes | variable | URL-safe base64, no padding |

### Hashing

`H(x)` is unkeyed BLAKE3, producing 32 bytes.

Keyed hashing is:

```
h_keyed(domain, msg) = BLAKE3_KEYED(key = H(domain), msg = msg)
```

### Names

- **Username**: string matching `^@[A-Za-z0-9_]{5,15}$`
- **Server name**: string matching `^~[A-Za-z0-9_]{5,15}$`

### Timestamps

- **Seconds timestamps**: Unix timestamp in seconds (unsigned integer)
- **Nanoseconds timestamps**: Unix timestamp in nanoseconds (unsigned integer)

## Common errors

Methods that return a protocol error use one of:

| Error | Meaning |
| --- | --- |
| `access_denied` | Permanent failure (auth, ACL, or membership check failed) |
| `retry_later` | Transient failure (clients should retry with backoff) |

In JSON-RPC, the structured error value appears in the response error `data` field.

Individual protocols may define additional error types; see the per-protocol pages for details.
