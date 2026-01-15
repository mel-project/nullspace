CREATE TABLE mailboxes (
    mailbox_id BLOB PRIMARY KEY,
    created_at INTEGER NOT NULL
);

CREATE TABLE mailbox_entries (
    mailbox_id BLOB NOT NULL,
    entry_id INTEGER PRIMARY KEY AUTOINCREMENT,
    received_at INTEGER NOT NULL,
    message_kind TEXT NOT NULL,
    message_body BLOB NOT NULL,
    sender_auth_token_hash BLOB,
    expires_at INTEGER,
    UNIQUE (mailbox_id, received_at),
    FOREIGN KEY (mailbox_id) REFERENCES mailboxes(mailbox_id) ON DELETE CASCADE
);

CREATE INDEX mailbox_entries_by_mailbox_time
    ON mailbox_entries (mailbox_id, received_at, entry_id);

CREATE INDEX mailbox_entries_by_expires_at
    ON mailbox_entries (expires_at);

CREATE TABLE mailbox_acl (
    mailbox_id BLOB NOT NULL,
    token_hash BLOB NOT NULL,
    can_edit_acl INTEGER NOT NULL CHECK (can_edit_acl IN (0, 1)),
    can_send INTEGER NOT NULL CHECK (can_send IN (0, 1)),
    can_recv INTEGER NOT NULL CHECK (can_recv IN (0, 1)),
    PRIMARY KEY (mailbox_id, token_hash),
    FOREIGN KEY (mailbox_id) REFERENCES mailboxes(mailbox_id) ON DELETE CASCADE
);

CREATE INDEX mailbox_acl_by_mailbox
    ON mailbox_acl (mailbox_id);
