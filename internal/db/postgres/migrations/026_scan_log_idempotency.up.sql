ALTER TABLE scan_log
    ADD COLUMN IF NOT EXISTS idempotency_key TEXT,
    ADD COLUMN IF NOT EXISTS request_digest TEXT NOT NULL DEFAULT '';

CREATE UNIQUE INDEX IF NOT EXISTS idx_scan_log_idempotency_key
    ON scan_log(idempotency_key)
    WHERE idempotency_key IS NOT NULL;
