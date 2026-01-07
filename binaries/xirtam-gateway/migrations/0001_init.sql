CREATE TABLE IF NOT EXISTS gateway_meta (
    id INTEGER PRIMARY KEY CHECK (id = 0),
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS device_certificates (
    handle TEXT PRIMARY KEY,
    cert_chain BLOB NOT NULL
);
