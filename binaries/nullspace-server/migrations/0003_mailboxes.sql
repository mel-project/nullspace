CREATE TABLE mailboxes (
    mailbox_id BLOB PRIMARY KEY,
    mailbox_key_hash BLOB NOT NULL,
    owner_username TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE mailbox_entries (
    mailbox_id BLOB NOT NULL,
    entry_id INTEGER PRIMARY KEY AUTOINCREMENT,
    received_at INTEGER NOT NULL,
    message_body BLOB NOT NULL,
    expires_at INTEGER,
    UNIQUE (mailbox_id, received_at),
    FOREIGN KEY (mailbox_id) REFERENCES mailboxes(mailbox_id) ON DELETE CASCADE
);

CREATE INDEX mailbox_entries_by_mailbox_time
    ON mailbox_entries (mailbox_id, received_at, entry_id);

CREATE INDEX mailbox_entries_by_expires_at
    ON mailbox_entries (expires_at);
