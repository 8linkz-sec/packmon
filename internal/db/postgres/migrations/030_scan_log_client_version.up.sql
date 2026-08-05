ALTER TABLE scan_log
    ADD COLUMN IF NOT EXISTS client_version TEXT;
