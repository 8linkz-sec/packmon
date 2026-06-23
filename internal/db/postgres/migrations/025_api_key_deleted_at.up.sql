ALTER TABLE api_keys
    ADD COLUMN deleted_at TIMESTAMPTZ;

CREATE INDEX idx_api_keys_deleted_at
    ON api_keys(deleted_at)
    WHERE deleted_at IS NOT NULL;
