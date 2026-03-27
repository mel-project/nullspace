CREATE TABLE group_rosters (
    group_id BLOB NOT NULL PRIMARY KEY,
    rotation_index INTEGER NOT NULL,
    roster BLOB NOT NULL
);

CREATE TABLE group_invitations (
    id INTEGER PRIMARY KEY,
    group_id BLOB NOT NULL,
    server_name TEXT NOT NULL,
    rotation_index INTEGER NOT NULL,
    gbk BLOB NOT NULL,
    inviter_username TEXT NOT NULL,
    title TEXT,
    description TEXT,
    received_at INTEGER NOT NULL,
    accepted INTEGER NOT NULL DEFAULT 0
);
