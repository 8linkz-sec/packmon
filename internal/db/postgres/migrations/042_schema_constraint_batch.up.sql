ALTER TABLE feed_sync_status
    DROP CONSTRAINT IF EXISTS feed_sync_status_duration_nonnegative_check;

ALTER TABLE feed_sync_status
    DROP CONSTRAINT IF EXISTS feed_sync_status_entries_order_check;

ALTER TABLE feed_sync_status
    DROP CONSTRAINT IF EXISTS feed_sync_status_entries_nonnegative_check;

ALTER TABLE feed_sync_status
    DROP CONSTRAINT IF EXISTS feed_sync_status_status_check;

ALTER TABLE refresh_queue
    DROP CONSTRAINT IF EXISTS refresh_queue_priority_check;

ALTER TABLE refresh_queue
    DROP CONSTRAINT IF EXISTS refresh_queue_status_check;

ALTER TABLE scan_log
    DROP CONSTRAINT IF EXISTS scan_log_api_key_id_fkey,
    DROP CONSTRAINT IF EXISTS scan_log_packages_count_nonnegative_check,
    DROP CONSTRAINT IF EXISTS scan_log_findings_count_nonnegative_check,
    DROP CONSTRAINT IF EXISTS scan_log_duration_ms_nonnegative_check,
    DROP CONSTRAINT IF EXISTS scan_log_manual_advisories_count_nonnegative_check,
    DROP CONSTRAINT IF EXISTS scan_log_block_threshold_check,
    DROP CONSTRAINT IF EXISTS scan_log_feed_status_check,
    DROP CONSTRAINT IF EXISTS scan_log_feed_versions_object_check,
    DROP CONSTRAINT IF EXISTS scan_log_finding_ids_array_check,
    DROP CONSTRAINT IF EXISTS scan_log_finding_severities_array_check;

ALTER TABLE api_keys
    DROP CONSTRAINT IF EXISTS api_keys_deleted_not_before_revoked_check,
    DROP CONSTRAINT IF EXISTS api_keys_last_used_not_before_created_check,
    DROP CONSTRAINT IF EXISTS api_keys_deleted_not_before_created_check,
    DROP CONSTRAINT IF EXISTS api_keys_revoked_not_before_created_check,
    DROP CONSTRAINT IF EXISTS api_keys_deleted_requires_revoked_check;

ALTER TABLE feed_configs
    DROP CONSTRAINT IF EXISTS feed_configs_sync_interval_minimum_check;

UPDATE scan_log
SET api_key_id = NULL
WHERE api_key_id IS NOT NULL
  AND NOT EXISTS (
    SELECT 1
    FROM api_keys
    WHERE api_keys.id = scan_log.api_key_id
  );

UPDATE scan_log
SET block_threshold = UPPER(TRIM(block_threshold))
WHERE UPPER(TRIM(block_threshold)) IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE')
  AND block_threshold IS DISTINCT FROM UPPER(TRIM(block_threshold));

UPDATE scan_log
SET block_threshold = 'CRITICAL'
WHERE TRIM(block_threshold) = '';

UPDATE scan_log
SET feed_status = LOWER(TRIM(feed_status))
WHERE LOWER(TRIM(feed_status)) IN ('healthy', 'degraded', 'error')
  AND feed_status IS DISTINCT FROM LOWER(TRIM(feed_status));

UPDATE scan_log
SET feed_status = 'healthy'
WHERE TRIM(feed_status) = '';

ALTER TABLE scan_log
    ALTER COLUMN block_threshold SET DEFAULT 'CRITICAL',
    ALTER COLUMN feed_status SET DEFAULT 'healthy';

ALTER TABLE feed_sync_status
    ADD CONSTRAINT feed_sync_status_status_check
        CHECK (last_sync_status IN (
            'pending', 'running', 'success', 'error', 'skipped',
            'disabled', 'external', 'rejected', 'permanent_error'
        )) NOT VALID,
    ADD CONSTRAINT feed_sync_status_entries_nonnegative_check
        CHECK (entries_synced >= 0 AND entries_total >= 0) NOT VALID,
    ADD CONSTRAINT feed_sync_status_entries_order_check
        CHECK (entries_total <= 0 OR entries_synced <= entries_total) NOT VALID,
    ADD CONSTRAINT feed_sync_status_duration_nonnegative_check
        CHECK (last_sync_duration IS NULL OR last_sync_duration >= INTERVAL '0') NOT VALID;

ALTER TABLE refresh_queue
    ADD CONSTRAINT refresh_queue_status_check
        CHECK (status IN ('pending', 'processing', 'paused', 'done', 'error')) NOT VALID,
    ADD CONSTRAINT refresh_queue_priority_check
        CHECK (priority BETWEEN 0 AND 3) NOT VALID;

ALTER TABLE scan_log
    ADD CONSTRAINT scan_log_api_key_id_fkey
        FOREIGN KEY (api_key_id) REFERENCES api_keys(id) ON DELETE SET NULL NOT VALID,
    ADD CONSTRAINT scan_log_packages_count_nonnegative_check
        CHECK (packages_count >= 0) NOT VALID,
    ADD CONSTRAINT scan_log_findings_count_nonnegative_check
        CHECK (findings_count >= 0) NOT VALID,
    ADD CONSTRAINT scan_log_duration_ms_nonnegative_check
        CHECK (duration_ms >= 0) NOT VALID,
    ADD CONSTRAINT scan_log_manual_advisories_count_nonnegative_check
        CHECK (manual_advisories_count >= 0) NOT VALID,
    ADD CONSTRAINT scan_log_block_threshold_check
        CHECK (block_threshold IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE')) NOT VALID,
    ADD CONSTRAINT scan_log_feed_status_check
        CHECK (feed_status IN ('healthy', 'degraded', 'error')) NOT VALID,
    ADD CONSTRAINT scan_log_feed_versions_object_check
        CHECK (feed_versions IS NULL OR jsonb_typeof(feed_versions) = 'object') NOT VALID,
    ADD CONSTRAINT scan_log_finding_ids_array_check
        CHECK (finding_ids IS NULL OR jsonb_typeof(finding_ids) = 'array') NOT VALID,
    ADD CONSTRAINT scan_log_finding_severities_array_check
        CHECK (finding_severities IS NULL OR jsonb_typeof(finding_severities) = 'array') NOT VALID;

ALTER TABLE api_keys
    ADD CONSTRAINT api_keys_deleted_requires_revoked_check
        CHECK (deleted_at IS NULL OR revoked_at IS NOT NULL) NOT VALID,
    ADD CONSTRAINT api_keys_revoked_not_before_created_check
        CHECK (revoked_at IS NULL OR revoked_at >= created_at) NOT VALID,
    ADD CONSTRAINT api_keys_deleted_not_before_created_check
        CHECK (deleted_at IS NULL OR deleted_at >= created_at) NOT VALID,
    ADD CONSTRAINT api_keys_last_used_not_before_created_check
        CHECK (last_used_at IS NULL OR last_used_at >= created_at) NOT VALID,
    ADD CONSTRAINT api_keys_deleted_not_before_revoked_check
        CHECK (deleted_at IS NULL OR revoked_at IS NULL OR deleted_at >= revoked_at) NOT VALID;

ALTER TABLE feed_configs
    ADD CONSTRAINT feed_configs_sync_interval_minimum_check
        CHECK (sync_interval IS NULL OR sync_interval >= INTERVAL '15 minutes') NOT VALID;

ALTER TABLE feed_sync_status VALIDATE CONSTRAINT feed_sync_status_status_check;
ALTER TABLE feed_sync_status VALIDATE CONSTRAINT feed_sync_status_entries_nonnegative_check;
ALTER TABLE feed_sync_status VALIDATE CONSTRAINT feed_sync_status_entries_order_check;
ALTER TABLE feed_sync_status VALIDATE CONSTRAINT feed_sync_status_duration_nonnegative_check;

ALTER TABLE refresh_queue VALIDATE CONSTRAINT refresh_queue_status_check;
ALTER TABLE refresh_queue VALIDATE CONSTRAINT refresh_queue_priority_check;

ALTER TABLE scan_log VALIDATE CONSTRAINT scan_log_api_key_id_fkey;
ALTER TABLE scan_log VALIDATE CONSTRAINT scan_log_packages_count_nonnegative_check;
ALTER TABLE scan_log VALIDATE CONSTRAINT scan_log_findings_count_nonnegative_check;
ALTER TABLE scan_log VALIDATE CONSTRAINT scan_log_duration_ms_nonnegative_check;
ALTER TABLE scan_log VALIDATE CONSTRAINT scan_log_manual_advisories_count_nonnegative_check;
ALTER TABLE scan_log VALIDATE CONSTRAINT scan_log_block_threshold_check;
ALTER TABLE scan_log VALIDATE CONSTRAINT scan_log_feed_status_check;
ALTER TABLE scan_log VALIDATE CONSTRAINT scan_log_feed_versions_object_check;
ALTER TABLE scan_log VALIDATE CONSTRAINT scan_log_finding_ids_array_check;
ALTER TABLE scan_log VALIDATE CONSTRAINT scan_log_finding_severities_array_check;

ALTER TABLE api_keys VALIDATE CONSTRAINT api_keys_deleted_requires_revoked_check;
ALTER TABLE api_keys VALIDATE CONSTRAINT api_keys_revoked_not_before_created_check;
ALTER TABLE api_keys VALIDATE CONSTRAINT api_keys_deleted_not_before_created_check;
ALTER TABLE api_keys VALIDATE CONSTRAINT api_keys_last_used_not_before_created_check;
ALTER TABLE api_keys VALIDATE CONSTRAINT api_keys_deleted_not_before_revoked_check;

ALTER TABLE feed_configs VALIDATE CONSTRAINT feed_configs_sync_interval_minimum_check;
