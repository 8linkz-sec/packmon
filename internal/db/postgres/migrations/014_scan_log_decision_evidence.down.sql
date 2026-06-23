ALTER TABLE scan_log
    DROP COLUMN IF EXISTS manual_advisories_count,
    DROP COLUMN IF EXISTS finding_severities,
    DROP COLUMN IF EXISTS finding_ids,
    DROP COLUMN IF EXISTS feed_versions,
    DROP COLUMN IF EXISTS feed_status,
    DROP COLUMN IF EXISTS correlation_id,
    DROP COLUMN IF EXISTS block_threshold,
    DROP COLUMN IF EXISTS findings_blocking;
