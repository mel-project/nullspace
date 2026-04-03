CREATE TABLE group_state_current (
    group_id BLOB PRIMARY KEY,
    rotation_index INTEGER NOT NULL,
    title TEXT,
    description TEXT,
    new_members_muted INTEGER NOT NULL,
    allow_new_members_to_see_history INTEGER NOT NULL
);

CREATE TABLE group_members_current (
    group_id BLOB NOT NULL,
    username TEXT NOT NULL,
    is_admin INTEGER NOT NULL,
    is_muted INTEGER NOT NULL,
    is_banned INTEGER NOT NULL,
    PRIMARY KEY (group_id, username),
    FOREIGN KEY (group_id) REFERENCES group_state_current(group_id) ON DELETE CASCADE
);

CREATE INDEX group_members_current_username_idx
    ON group_members_current (username, is_banned);
