CREATE TABLE device_medium_pks (
    device_hash BLOB NOT NULL PRIMARY KEY,
    medium_pk BLOB NOT NULL,
    created INTEGER NOT NULL,
    signature BLOB NOT NULL
);

CREATE UNIQUE INDEX device_auth_tokens_auth_token_uidx
    ON device_auth_tokens (auth_token);
