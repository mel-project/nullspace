CREATE TABLE groups (
    group_id BLOB PRIMARY KEY,
    descriptor BLOB NOT NULL,
    gateway_name TEXT NOT NULL,
    token BLOB NOT NULL,
    group_key_current BLOB NOT NULL,
    group_key_prev BLOB NOT NULL,
    roster_version INTEGER NOT NULL
);

CREATE TABLE group_members (
    group_id BLOB NOT NULL,
    handle TEXT NOT NULL,
    is_admin INTEGER NOT NULL CHECK (is_admin IN (0, 1)),
    status TEXT NOT NULL CHECK (status IN ('pending', 'accepted', 'banned')),
    PRIMARY KEY (group_id, handle),
    FOREIGN KEY (group_id) REFERENCES groups(group_id) ON DELETE CASCADE
);

CREATE INDEX group_members_by_group
    ON group_members (group_id);

CREATE TABLE group_messages (
    id INTEGER PRIMARY KEY,
    group_id BLOB NOT NULL,
    sender_handle TEXT NOT NULL,
    mime TEXT NOT NULL,
    body BLOB NOT NULL,
    received_at INTEGER,
    FOREIGN KEY (group_id) REFERENCES groups(group_id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX group_messages_unique_idx
    ON group_messages (group_id, sender_handle, received_at);

CREATE INDEX group_messages_group_received_idx
    ON group_messages (group_id, received_at);
