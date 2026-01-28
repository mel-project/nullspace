CREATE TABLE fragments (
    hash BLOB PRIMARY KEY,
    created_at INTEGER NOT NULL,
    expires_at INTEGER,
    size INTEGER NOT NULL
);

CREATE INDEX fragments_by_expires_at
    ON fragments (expires_at);
