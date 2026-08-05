DROP INDEX IF EXISTS idx_scan_log_idempotency_key;

ALTER TABLE scan_log
    DROP COLUMN IF EXISTS request_digest,
    DROP COLUMN IF EXISTS idempotency_key;
