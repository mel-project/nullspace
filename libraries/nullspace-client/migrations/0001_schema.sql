CREATE TABLE client_identity (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    username TEXT NOT NULL,
    server_name TEXT,
    device_secret BLOB NOT NULL,
    cert_chain BLOB NOT NULL,
    medium_sk_current BLOB NOT NULL,
    medium_sk_prev BLOB NOT NULL
);

CREATE TABLE convos (
    id INTEGER PRIMARY KEY,
    convo_type TEXT NOT NULL CHECK (convo_type IN ('direct', 'group')),
    convo_counterparty TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE UNIQUE INDEX convos_unique_idx
    ON convos (convo_type, convo_counterparty);

CREATE TABLE convo_messages (
    id INTEGER PRIMARY KEY,
    convo_id INTEGER NOT NULL,
    sender_username TEXT NOT NULL,
    mime TEXT NOT NULL,
    body BLOB NOT NULL,
    sent_at INTEGER NOT NULL,
    send_error TEXT,
    received_at INTEGER,
    CHECK (send_error IS NULL OR received_at IS NOT NULL),
    FOREIGN KEY (convo_id) REFERENCES convos(id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX convo_messages_sent_idx
    ON convo_messages (convo_id, sent_at);

CREATE INDEX convo_messages_idx
    ON convo_messages (convo_id, sender_username, received_at);

CREATE INDEX convo_messages_convo_received_idx
    ON convo_messages (convo_id, received_at);

CREATE TABLE groups (
    group_id BLOB PRIMARY KEY,
    descriptor BLOB NOT NULL,
    server_name TEXT NOT NULL,
    token BLOB NOT NULL,
    group_key_current BLOB NOT NULL,
    group_key_prev BLOB NOT NULL,
    roster_version INTEGER NOT NULL
);

CREATE TABLE group_members (
    group_id BLOB NOT NULL,
    username TEXT NOT NULL,
    is_admin INTEGER NOT NULL CHECK (is_admin IN (0, 1)),
    status TEXT NOT NULL CHECK (status IN ('pending', 'accepted', 'banned')),
    PRIMARY KEY (group_id, username),
    FOREIGN KEY (group_id) REFERENCES groups(group_id) ON DELETE CASCADE
);

CREATE INDEX group_members_by_group
    ON group_members (group_id);

CREATE TABLE mailbox_state (
    server_name TEXT NOT NULL,
    mailbox_id BLOB NOT NULL,
    after_timestamp INTEGER NOT NULL,
    PRIMARY KEY (server_name, mailbox_id)
);
