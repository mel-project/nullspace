# nullspace-client

`nullspace-client` is a TDLib-like local service for Nullspace. It owns identity, storage,
encryption, and networking so that UIs never need to speak crypto or server APIs
directly. The UI only uses a small JSON-RPC surface and renders events.

## What the GUI talks to

The GUI calls the internal JSON-RPC methods on a local `Client` instance:

- `register_start(username) -> Option<RegisterStartInfo>`
- `register_finish(RegisterFinish) -> Result<()>`
- `provision_host_start() -> ProvisionHostStart`
- `provision_host_status(session_id) -> ProvisionHostStatus`
- `provision_host_stop(session_id) -> Result<()>`
- `convo_list() -> [ConvoSummary]`
- `convo_history(convo_id, before, after, limit) -> [ConvoMessage]`
- `convo_send(convo_id, message) -> message_id`
- `convo_create_group(server) -> ConvoId`
- `group_invite(group, username) -> Result<()>`
- `group_members(group) -> [GroupMember]`
- `group_accept_invite(dm_id) -> GroupId`
- `own_server() -> ServerName`
- `next_event() -> Event` (infallible, long-polling)

`next_event()` is the only push-style API. It blocks until the next event arrives.
Events are emitted only by the internal event loop in response to DB changes.

## High-level architecture

The client is a single process with structured concurrency:

- An RPC loop serving GUI requests.
- An event loop that watches the DB and emits `Event::State` + `Event::ConvoUpdated` + `Event::GroupUpdated`.
- A worker loop that starts send/recv + key rotation after login.

All three loops are raced together, and they all share the same `AnyCtx`.

```mermaid
sequenceDiagram
  participant GUI
  participant Client as nullspace-client
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

1. The existing device calls `provision_host_start()` and shows
   the pairing code from `ProvisionHostStart`.
2. While waiting, the GUI polls `provision_host_status(session_id)` for refreshed
   codes and completion.
3. The new device calls
   `register_finish(RegisterFinish::AddDeviceByCode { username, code })`.
4. Client submits the signed add-device directory update, registers the new device on the
   server, stores identity, and emits
   `Event::State { logged_in: true }`.

```mermaid
sequenceDiagram
  participant GUI1 as GUI (existing device)
  participant GUI2 as GUI (new device)
  participant Client1 as client (existing)
  participant Client2 as client (new)
  participant Dir as directory
  participant GW as server

  GUI1->>Client1: provision_host_start()
  Client1-->>GUI1: session_id + pairing code
  GUI1->>Client1: provision_host_status(session_id) (poll)
  GUI1-->>GUI2: pairing code
  GUI2->>Client2: register_finish(AddDeviceByCode { username, code })
  Client2->>Dir: lookup user descriptor
  Client2->>Dir: submit signed add-device update
  Client2->>GW: device_auth + add_medium_pk
  Client2->>Client2: persist identity
  Client2-->>GUI2: ok
```

## Convo flow

Direct messages and group messages share a unified convo API:

- `convo_send(convo_id, message)` inserts into `convo_messages` with `received_at = NULL`.
- The send loops look for pending rows (`received_at = NULL`, `send_error IS NULL`) and send encrypted payloads.
- On send failures, the client records `send_error` and sets a synthetic `received_at` to stop retries.
- The recv loops long-poll mailboxes, decrypt, verify, and insert new rows.
- The event loop emits `Event::ConvoUpdated { convo_id }` for new rows.

```mermaid
sequenceDiagram
  participant GUI
  participant Client
  participant DB
  participant GW as server

  GUI->>Client: convo_send(ConvoId::Direct(@bob), OutgoingMessage::PlainText("hi"))
  Client->>DB: insert pending convo message
  Client-->>GUI: message_id
  Client->>GW: mailbox_send(header-encrypted message)
  Client->>DB: update received_at
  Client-->>GUI: next_event() -> ConvoUpdated { convo_id }
```

## Key rotation (internal)

Medium-term keys rotate automatically every hour. The previous key is retained so
late messages can be decrypted. These keys are never exposed to the UI.

## Data model (sqlite)

- `client_identity`: one row holding identity + key material (including cached server name).
- `convos`: conversation registry (direct + group), allows empty convos.
- `convo_messages`: plaintext history for both direct and group conversations, with optional `send_error`.
- `groups`: group descriptors + keys + tokens.
- `group_members`: roster entries (for crypto and membership enforcement).
- `mailbox_state`: mailbox cursor for long-polling.

## Event semantics

Events are derived from the DB:

- `Event::State { logged_in }` whenever identity appears/disappears.
- `Event::ConvoUpdated { convo_id }` whenever new convo rows appear.
- `Event::GroupUpdated { group }` whenever roster state changes.

No other component emits events directly; all producers simply update the DB and
call `DbNotify::touch()`.

## Notes for UI authors

- Treat the client as a local service. All heavy lifting is internal.
- `next_event()` is the main driver; call it in a long-polling loop.
- For message display, call `convo_history(convo_id, before, after, limit)` with
  `before = None` to load latest messages, then page backward by `before = id`.
