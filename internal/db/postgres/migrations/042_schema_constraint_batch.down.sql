ALTER TABLE feed_configs
    DROP CONSTRAINT IF EXISTS feed_configs_sync_interval_minimum_check;

ALTER TABLE api_keys
    DROP CONSTRAINT IF EXISTS api_keys_deleted_not_before_revoked_check,
    DROP CONSTRAINT IF EXISTS api_keys_last_used_not_before_created_check,
    DROP CONSTRAINT IF EXISTS api_keys_deleted_not_before_created_check,
    DROP CONSTRAINT IF EXISTS api_keys_revoked_not_before_created_check,
    DROP CONSTRAINT IF EXISTS api_keys_deleted_requires_revoked_check;

ALTER TABLE scan_log
    DROP CONSTRAINT IF EXISTS scan_log_finding_severities_array_check,
    DROP CONSTRAINT IF EXISTS scan_log_finding_ids_array_check,
    DROP CONSTRAINT IF EXISTS scan_log_feed_versions_object_check,
    DROP CONSTRAINT IF EXISTS scan_log_feed_status_check,
    DROP CONSTRAINT IF EXISTS scan_log_block_threshold_check,
    DROP CONSTRAINT IF EXISTS scan_log_manual_advisories_count_nonnegative_check,
    DROP CONSTRAINT IF EXISTS scan_log_duration_ms_nonnegative_check,
    DROP CONSTRAINT IF EXISTS scan_log_findings_count_nonnegative_check,
    DROP CONSTRAINT IF EXISTS scan_log_packages_count_nonnegative_check,
    DROP CONSTRAINT IF EXISTS scan_log_api_key_id_fkey;

ALTER TABLE refresh_queue
    DROP CONSTRAINT IF EXISTS refresh_queue_priority_check;

ALTER TABLE refresh_queue
    DROP CONSTRAINT IF EXISTS refresh_queue_status_check;

ALTER TABLE feed_sync_status
    DROP CONSTRAINT IF EXISTS feed_sync_status_duration_nonnegative_check;

ALTER TABLE feed_sync_status
    DROP CONSTRAINT IF EXISTS feed_sync_status_entries_order_check;

ALTER TABLE feed_sync_status
    DROP CONSTRAINT IF EXISTS feed_sync_status_entries_nonnegative_check;

ALTER TABLE feed_sync_status
    DROP CONSTRAINT IF EXISTS feed_sync_status_status_check;

ALTER TABLE scan_log
    ALTER COLUMN block_threshold SET DEFAULT '',
    ALTER COLUMN feed_status SET DEFAULT '';

ALTER TABLE refresh_queue
    ADD CONSTRAINT refresh_queue_status_check
        CHECK (status IN ('pending', 'processing', 'paused', 'done', 'error')) NOT VALID,
    ADD CONSTRAINT refresh_queue_priority_check
        CHECK (priority BETWEEN 0 AND 3) NOT VALID;

ALTER TABLE feed_sync_status
    ADD CONSTRAINT feed_sync_status_status_check
        CHECK (last_sync_status IN (
            'pending', 'running', 'success', 'error', 'skipped',
            'disabled', 'external', 'rejected', 'permanent_error'
        )) NOT VALID,
    ADD CONSTRAINT feed_sync_status_entries_nonnegative_check
        CHECK (entries_synced >= 0 AND entries_total >= 0) NOT VALID,
    ADD CONSTRAINT feed_sync_status_entries_order_check
        CHECK (entries_synced <= entries_total) NOT VALID,
    ADD CONSTRAINT feed_sync_status_duration_nonnegative_check
        CHECK (last_sync_duration IS NULL OR last_sync_duration >= INTERVAL '0') NOT VALID;

ALTER TABLE refresh_queue VALIDATE CONSTRAINT refresh_queue_status_check;
ALTER TABLE refresh_queue VALIDATE CONSTRAINT refresh_queue_priority_check;

ALTER TABLE feed_sync_status VALIDATE CONSTRAINT feed_sync_status_status_check;
ALTER TABLE feed_sync_status VALIDATE CONSTRAINT feed_sync_status_entries_nonnegative_check;
ALTER TABLE feed_sync_status VALIDATE CONSTRAINT feed_sync_status_entries_order_check;
ALTER TABLE feed_sync_status VALIDATE CONSTRAINT feed_sync_status_duration_nonnegative_check;
