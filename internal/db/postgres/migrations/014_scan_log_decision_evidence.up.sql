ALTER TABLE scan_log
    ADD COLUMN findings_blocking BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN block_threshold TEXT NOT NULL DEFAULT '',
    ADD COLUMN correlation_id TEXT NOT NULL DEFAULT '',
    ADD COLUMN feed_status TEXT NOT NULL DEFAULT '',
    ADD COLUMN feed_versions JSONB NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN finding_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN finding_severities JSONB NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN manual_advisories_count INTEGER NOT NULL DEFAULT 0;
