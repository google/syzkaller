CREATE TABLE locks (
    lock_id text,
    owner text,
    last_acquired timestamptz,
    PRIMARY KEY (lock_id)
);
