CREATE TABLE IF NOT EXISTS device_auth_tokens (
    username TEXT NOT NULL,
    device_hash BLOB NOT NULL,
    auth_token BLOB NOT NULL,
    PRIMARY KEY (username, device_hash)
);
