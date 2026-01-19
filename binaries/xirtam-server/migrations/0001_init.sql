CREATE TABLE IF NOT EXISTS server_meta (
    id INTEGER PRIMARY KEY CHECK (id = 0),
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS device_certificates (
    device_hash BLOB PRIMARY KEY,
    username TEXT NOT NULL,
    cert_chain BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS device_certificates_username_idx
    ON device_certificates (username);
