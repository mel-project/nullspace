CREATE TABLE client_identity (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    username TEXT NOT NULL,
    server_name TEXT,
    device_secret BLOB NOT NULL,
    medium_sk_current BLOB NOT NULL,
    medium_sk_prev BLOB NOT NULL,
    dm_mailbox_key BLOB NOT NULL
);

CREATE TABLE event_threads (
    id INTEGER PRIMARY KEY,
    thread_kind TEXT NOT NULL CHECK (thread_kind IN ('direct', 'group')),
    thread_counterparty TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE UNIQUE INDEX event_threads_unique_idx
    ON event_threads (thread_kind, thread_counterparty);

CREATE TABLE thread_events (
    id INTEGER PRIMARY KEY,
    thread_id INTEGER NOT NULL,
    sender_username TEXT NOT NULL,
    event_tag INTEGER NOT NULL,
    event_body BLOB NOT NULL,
    event_after BLOB,
    event_hash BLOB NOT NULL,
    sent_at INTEGER NOT NULL,
    send_error TEXT,
    received_at INTEGER,
    CHECK (send_error IS NULL OR received_at IS NOT NULL),
    FOREIGN KEY (thread_id) REFERENCES event_threads(id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX thread_events_hash_idx
    ON thread_events (thread_id, event_hash);

CREATE UNIQUE INDEX thread_events_sent_idx
    ON thread_events (thread_id, sent_at);

CREATE INDEX thread_events_idx
    ON thread_events (thread_id, sender_username, received_at);

CREATE INDEX thread_events_thread_received_idx
    ON thread_events (thread_id, received_at);

CREATE TABLE mailbox_state (
    server_name TEXT NOT NULL,
    mailbox_id BLOB NOT NULL,
    after_timestamp INTEGER NOT NULL,
    PRIMARY KEY (server_name, mailbox_id)
);

CREATE TABLE attachment_roots (
    hash BLOB PRIMARY KEY,
    root BLOB NOT NULL
);

CREATE TABLE attachment_paths (
    hash BLOB PRIMARY KEY,
    download_path TEXT NOT NULL
);

CREATE TABLE user_descriptor_cache (
    username TEXT NOT NULL PRIMARY KEY,
    descriptor BLOB NOT NULL,
    fetched_at INTEGER NOT NULL
);

CREATE TABLE user_info_cache (
    username TEXT NOT NULL PRIMARY KEY,
    fetched_at INTEGER NOT NULL
);

CREATE TABLE user_devices_cache (
    username TEXT NOT NULL PRIMARY KEY,
    devices BLOB NOT NULL
);

CREATE TABLE user_device_medium_pks_cache (
    username TEXT NOT NULL PRIMARY KEY,
    medium_pks BLOB NOT NULL
);

CREATE INDEX user_descriptor_cache_idx
    ON user_descriptor_cache (username);

CREATE INDEX user_info_cache_idx
    ON user_info_cache (username);

CREATE INDEX user_devices_cache_idx
    ON user_devices_cache (username);

CREATE INDEX user_device_medium_pks_cache_idx
    ON user_device_medium_pks_cache (username);

CREATE TABLE message_reads (
    message_id INTEGER PRIMARY KEY,
    read_at INTEGER NOT NULL,
    FOREIGN KEY (message_id) REFERENCES thread_events(id) ON DELETE CASCADE
);

CREATE INDEX message_reads_read_at_idx
    ON message_reads (read_at);

CREATE TABLE group_keys (
    group_id BLOB NOT NULL,
    rotation_index INTEGER NOT NULL,
    gbk BLOB NOT NULL,
    server_name TEXT NOT NULL,
    admin_set BLOB NOT NULL,
    rotation_hash BLOB NOT NULL,
    PRIMARY KEY (group_id, rotation_index)
);

CREATE TABLE group_rosters (
    group_id BLOB NOT NULL PRIMARY KEY,
    rotation_index INTEGER NOT NULL,
    roster BLOB NOT NULL
);

CREATE TABLE group_state_current (
    group_id BLOB PRIMARY KEY,
    rotation_index INTEGER NOT NULL,
    title TEXT,
    description TEXT,
    new_members_muted INTEGER NOT NULL,
    allow_new_members_to_see_history INTEGER NOT NULL
);

CREATE TABLE group_members_current (
    group_id BLOB NOT NULL,
    username TEXT NOT NULL,
    is_admin INTEGER NOT NULL,
    is_muted INTEGER NOT NULL,
    is_banned INTEGER NOT NULL,
    PRIMARY KEY (group_id, username),
    FOREIGN KEY (group_id) REFERENCES group_state_current(group_id) ON DELETE CASCADE
);

CREATE INDEX group_members_current_username_idx
    ON group_members_current (username, is_banned);
