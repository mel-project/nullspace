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
