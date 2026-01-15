CREATE TABLE client_identity (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    username TEXT NOT NULL,
    device_secret BLOB NOT NULL,
    cert_chain BLOB NOT NULL,
    medium_sk_current BLOB NOT NULL,
    medium_sk_prev BLOB NOT NULL
);

CREATE TABLE dm_messages (
    id INTEGER PRIMARY KEY,
    peer_username TEXT NOT NULL,
    sender_username TEXT NOT NULL,
    mime TEXT NOT NULL,
    body BLOB NOT NULL,
    received_at INTEGER
);

CREATE UNIQUE INDEX dm_messages_unique_idx
    ON dm_messages (peer_username, sender_username, received_at);

CREATE INDEX dm_messages_peer_received_idx
    ON dm_messages (peer_username, received_at);

CREATE TABLE mailbox_state (
    server_name TEXT NOT NULL,
    mailbox_id BLOB NOT NULL,
    after_timestamp INTEGER NOT NULL,
    PRIMARY KEY (server_name, mailbox_id)
);
