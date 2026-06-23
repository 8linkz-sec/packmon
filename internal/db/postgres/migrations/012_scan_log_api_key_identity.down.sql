ALTER TABLE scan_log
    DROP COLUMN IF EXISTS api_key_name,
    DROP COLUMN IF EXISTS api_key_id;
