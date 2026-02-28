DROP TABLE IF EXISTS attachment_roots;

CREATE TABLE attachment_roots (
    hash BLOB PRIMARY KEY,
    root BLOB NOT NULL
);
