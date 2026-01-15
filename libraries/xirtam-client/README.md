# xirtam-client

`xirtam-client` is a TDLib-like local service for Xirtam. It owns identity, storage,
encryption, and networking so that UIs never need to speak crypto or server APIs
directly. The UI only uses a small JSON-RPC surface and renders events.

## What the GUI talks to

The GUI calls the internal JSON-RPC methods on a local `Client` instance:

- `register_start(username) -> Option<RegisterStartInfo>`
- `register_finish(RegisterFinish) -> Result<()>`
- `new_device_bundle(can_issue, expiry) -> NewDeviceBundle`
- `dm_send(peer, mime, body) -> message_id`
- `dm_history(peer, before, after, limit) -> [DmMessage]`
- `next_event() -> Event` (infallible, long-polling)

`next_event()` is the only push-style API. It blocks until the next event arrives.
Events are emitted only by the internal event loop in response to DB changes.

## High-level architecture

The client is a single process with structured concurrency:

- An RPC loop serving GUI requests.
- An event loop that watches the DB and emits `Event::State` + `Event::DmUpdated`.
- A worker loop that starts send/recv + key rotation after login.

All three loops are raced together, and they all share the same `AnyCtx`.

```mermaid
sequenceDiagram
  participant GUI
  participant Client as xirtam-client
  participant DB as sqlite
  participant Dir as directory
  participant GW as server

  GUI->>Client: register_start(@alice)
  Client->>Dir: lookup username
  Dir-->>Client: descriptor or none
  Client-->>GUI: Option<RegisterStartInfo>

  GUI->>Client: register_finish(...)
  Client->>Dir: add owner + set user descriptor
  Client->>GW: device_auth + add_medium_pk
  Client->>DB: persist identity
  Client-->>GUI: ok

  GUI->>Client: next_event()
  Client-->>GUI: Event::State { logged_in: true }
```

## Login + registration flow

There are only two states: logged out and logged in. On startup, the client checks
`client_identity`:

- If present, it starts the worker loop and emits `Event::State { logged_in: true }`.
- If absent, it emits `Event::State { logged_in: false }`.

### Register a new username

1. GUI picks a username and server name.
2. GUI calls `register_finish(RegisterFinish::BootstrapNewUser { .. })`.
3. Client creates device identity, registers the username in the directory, and
   registers the device on the server.
4. Client persists identity and emits `Event::State { logged_in: true }`.

### Add a new device

1. An existing, logged-in device calls `new_device_bundle(can_issue, expiry)` and
   renders the opaque bundle (e.g., QR).
2. The new device calls `register_finish(RegisterFinish::AddDevice { bundle })`.
3. Client registers the device on the server, stores identity, and emits
   `Event::State { logged_in: true }`.

The bundle is opaque to the UI. Crypto is handled internally.

```mermaid
sequenceDiagram
  participant GUI1 as GUI (existing device)
  participant GUI2 as GUI (new device)
  participant Client1 as client (existing)
  participant Client2 as client (new)
  participant Dir as directory
  participant GW as server

  GUI1->>Client1: new_device_bundle(can_issue, expiry)
  Client1-->>GUI1: bundle (opaque)
  GUI1-->>GUI2: QR / transfer
  GUI2->>Client2: register_finish(AddDevice { bundle })
  Client2->>Dir: lookup user descriptor
  Client2->>GW: device_auth + add_medium_pk
  Client2->>Client2: persist identity
  Client2-->>GUI2: ok
```

## DM flow

DM sending and receiving are fully automated:

- `dm_send(peer, mime, body)` inserts into `dm_messages` with `received_at = NULL`.
- `send_loop` sees pending rows and sends encrypted envelopes to the server.
- `recv_loop` long-polls the mailbox, decrypts, verifies, and inserts new rows.
- The event loop emits `Event::DmUpdated { peer }` for new rows.

```mermaid
sequenceDiagram
  participant GUI
  participant Client
  participant DB
  participant GW as server

  GUI->>Client: dm_send(@bob, "text/plain", "hi")
  Client->>DB: insert pending dm
  Client-->>GUI: message_id
  Client->>GW: mailbox_send(encrypted envelope)
  Client->>DB: update received_at
  Client-->>GUI: next_event() -> DmUpdated { @bob }
```

## Key rotation (internal)

Medium-term keys rotate automatically every hour. The previous key is retained so
late messages can be decrypted. These keys are never exposed to the UI.

## Data model (sqlite)

- `client_identity`: one row holding identity + key material (including cached server name).
- `dm_messages`: plaintext history (incoming + outgoing).
- `mailbox_state`: mailbox cursor for long-polling.

## Event semantics

Events are derived from the DB:

- `Event::State { logged_in }` whenever identity appears/disappears.
- `Event::DmUpdated { peer }` whenever new rows appear for a peer.

No other component emits events directly; all producers simply update the DB and
call `DbNotify::touch()`.

## Notes for UI authors

- Treat the client as a local service. All heavy lifting is internal.
- `next_event()` is the main driver; call it in a long-polling loop.
- For message display, call `dm_history(peer, before, after, limit)` with
  `before = None` to load latest messages, then page backward by `before = id`.
