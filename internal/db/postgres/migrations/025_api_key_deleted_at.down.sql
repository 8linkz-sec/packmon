DROP INDEX IF EXISTS idx_api_keys_deleted_at;

ALTER TABLE api_keys
    DROP COLUMN IF EXISTS deleted_at;
