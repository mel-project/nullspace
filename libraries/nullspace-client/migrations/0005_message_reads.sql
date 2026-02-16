CREATE TABLE message_reads (
    message_id INTEGER PRIMARY KEY,
    read_at INTEGER NOT NULL,
    FOREIGN KEY (message_id) REFERENCES convo_messages(id) ON DELETE CASCADE
);

CREATE INDEX message_reads_read_at_idx
    ON message_reads (read_at);
