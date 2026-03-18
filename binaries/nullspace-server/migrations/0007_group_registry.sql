CREATE TABLE group_rotations (
    group_id BLOB NOT NULL,
    rotation_index INTEGER NOT NULL,
    entry BLOB NOT NULL,
    PRIMARY KEY (group_id, rotation_index)
);

CREATE INDEX group_rotations_by_group_idx
    ON group_rotations (group_id, rotation_index);
