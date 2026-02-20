# nullspace-client

A runtime-agnostic local service that encapsulates the entire nullspace
encrypted messaging protocol behind a clean JSON-RPC interface.

## Architecture

`nullspace-client` follows a **local-service** design inspired by Telegram's TDLib: a
single [`Client`] instance spawns a self-contained background thread that
manages all networking, cryptography, key management, and persistence
internally.  Frontends interact exclusively through a typed
[`InternalClient`] RPC handle -- they never touch raw protocol messages,
encryption keys, or server connections.

```text
 ┌─────────────┐         JSON-RPC            ┌──────────────────────────┐
 │   Frontend  │◄────── (in-process) ─────►│     nullspace-client     │
 │  (egui, Qt, │  InternalClient / C FFI     │                          │
 │   GTK, …)  │                             │  ┌────────┐ ┌─────────┐  │
 └─────────────┘                             │  │ SQLite │ │  Tokio  │  │
                                             │  │   DB   │ │ Runtime │  │
                                             │  └────────┘ └─────────┘  │
                                             │  ┌────────────────────┐  │
                                             │  │   E2EE · Key Mgmt  │  │
                                             │  │   Long Poll · DMs  │  │
                                             │  │   Groups · Attach. │  │
                                             │  └────────────────────┘  │
                                             └──────────────────────────┘
```

## What the client abstracts away

- **End-to-end encryption** -- messages are encrypted per-recipient with
  medium-term Diffie-Hellman keys
- **Key lifecycle** -- medium-term keys rotate automatically every hour,
  with the previous key retained for in-flight messages.  Device
  authentication tokens are cached and refreshed transparently.
- **Reliable delivery** -- outgoing messages are persisted to a local
  SQLite queue and retried with exponential backoff until acknowledged.
  Send failures are recorded, never silently dropped.
- **Efficient polling** -- mailbox long-polling uses AIMD congestion
  control and batches multiple mailboxes
  into a single server round-trip.
- **Multi-device provisioning** -- new devices are paired through a
  SPAKE2-based flow over ephemeral server channels.
- **Attachments** -- files are chunked, encrypted with a random content
  key, uploaded as a Merkle tree of fragments, and reassembled on
  download -- all with streaming progress events.

## Quick start

```rust
use nullspace_client::{Client, Config};

// 1. Create the client -- spawns the background service.
let client = Client::new(config);

// 2. Obtain an RPC handle (cheap to clone).
let rpc = client.rpc();

// 3. Use the typed API.
let convos = rpc.convo_list().await?;
let id    = rpc.convo_send(convo_id, message).await?;

// 4. React to push events in a background loop.
loop {
    match rpc.next_event().await {
        Event::ConvoUpdated { convo_id } => { /* refresh UI */ }
        Event::State { logged_in }       => { /* update auth state */ }
        _ => {}
    }
}
```

## C FFI

The crate also compiles as a `cdylib` and exposes a C-compatible interface
(`nullspace_start`, `nullspace_stop`, `nullspace_rpc`) for embedding in
non-Rust frontends.

The API uses a **slot** system -- each slot holds an independent client
instance.  `nullspace_rpc` takes a shared buffer: write the JSON-RPC
request into it, call the function, and read the response back from
the same buffer.

```c
#include <stdio.h>
#include <string.h>

// Provided by libnullspace_client.so / nullspace_client.dll
int nullspace_start(int slot, const char *toml_cfg);
int nullspace_stop(int slot);
int nullspace_rpc(int slot, char *jrpc_inout, size_t jrpc_inout_maxlen);

int main(void) {
    const char *cfg =
        "db_path = '/tmp/nullspace.db'\n"
        "dir_endpoint = 'https://directory.example.com'\n"
        "dir_anchor_pk = '<base64-key>'\n";

    // Start the client on slot 0.
    if (nullspace_start(0, cfg) != 0) return 1;

    // Call an RPC method -- write request, read response in-place.
    char buf[4096];
    snprintf(buf, sizeof(buf),
        "{\"jsonrpc\":\"2.0\",\"id\":1,"
         "\"method\":\"convo_list\",\"params\":[]}");

    int len = nullspace_rpc(0, buf, sizeof(buf));
    if (len > 0)
        printf("response: %.*s\n", len, buf);

    nullspace_stop(0);
    return 0;
}
```
