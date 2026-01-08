CREATE TABLE IF NOT EXISTS device_auth_tokens (
    handle TEXT NOT NULL,
    device_hash BLOB NOT NULL,
    auth_token BLOB NOT NULL,
    PRIMARY KEY (handle, device_hash)
);
