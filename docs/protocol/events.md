# Events

An event is the plaintext payload carried inside encrypted messages. It is BCS-encoded as a tuple:

```
[recipient, sent_at, mime, body]
```

- `recipient`: `["user", username]` (for DMs) or `["group", group_id]` (for group chats)
- `sent_at`: Unix timestamp (nanoseconds)
- `mime`: a MIME type string
- `body`: opaque bytes

The `mime` field indicates how to interpret `body`. For human chat messages, `body` is usually the raw bytes of the text. For structured messages (like group invites or group management commands), `body` is typically JSON and the MIME value identifies the schema.

## Supported MIME types

| MIME type | Description | Body encoding | Recipient |
| --- | --- | --- | --- |
| `text/plain` | Human chat message | Raw UTF-8 text bytes | Username or group ID |
| `text/markdown` | Human chat message with Markdown | Raw UTF-8 text bytes | Username or group ID |
| `application/vnd.nullspace.v1.group_invite` | Group invite payload | JSON | Username |
| `application/vnd.nullspace.v1.group_manage` | Group management command | JSON | Group ID |
| `application/vnd.nullspace.v1.attachment` | File attachment root | JSON | Username or group ID |
