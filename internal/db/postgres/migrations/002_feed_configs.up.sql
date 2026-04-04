CREATE TABLE feed_configs (
    feed_name     TEXT        PRIMARY KEY,
    enabled       BOOLEAN     NOT NULL,
    mode          TEXT        NOT NULL CHECK (mode IN ('self', 'external')),
    sync_interval INTERVAL,
    api_key       TEXT,
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
