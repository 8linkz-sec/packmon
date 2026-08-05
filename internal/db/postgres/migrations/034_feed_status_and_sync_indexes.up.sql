UPDATE feed_sync_status
SET last_sync_status = LOWER(TRIM(last_sync_status))
WHERE last_sync_status IS DISTINCT FROM LOWER(TRIM(last_sync_status))
  AND LOWER(TRIM(last_sync_status)) IN (
    'pending', 'running', 'success', 'error', 'skipped',
    'disabled', 'external', 'rejected', 'permanent_error'
  );

UPDATE feed_sync_status
SET last_sync_status = 'error',
    last_error = COALESCE(NULLIF(last_error, ''), 'normalized invalid feed sync status during migration 034')
WHERE last_sync_status NOT IN (
    'pending', 'running', 'success', 'error', 'skipped',
    'disabled', 'external', 'rejected', 'permanent_error'
);

UPDATE feed_sync_status
SET entries_synced = GREATEST(entries_synced, 0),
    entries_total = GREATEST(entries_total, 0)
WHERE entries_synced < 0 OR entries_total < 0;

UPDATE feed_sync_status
SET entries_total = entries_synced
WHERE entries_synced > entries_total;

UPDATE feed_sync_status
SET last_sync_duration = NULL
WHERE last_sync_duration < INTERVAL '0';

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'feed_sync_status_status_check') THEN
        ALTER TABLE feed_sync_status
            ADD CONSTRAINT feed_sync_status_status_check
            CHECK (last_sync_status IN (
                'pending', 'running', 'success', 'error', 'skipped',
                'disabled', 'external', 'rejected', 'permanent_error'
            )) NOT VALID;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'feed_sync_status_entries_nonnegative_check') THEN
        ALTER TABLE feed_sync_status
            ADD CONSTRAINT feed_sync_status_entries_nonnegative_check
            CHECK (entries_synced >= 0 AND entries_total >= 0) NOT VALID;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'feed_sync_status_entries_order_check') THEN
        ALTER TABLE feed_sync_status
            ADD CONSTRAINT feed_sync_status_entries_order_check
            CHECK (entries_synced <= entries_total) NOT VALID;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'feed_sync_status_duration_nonnegative_check') THEN
        ALTER TABLE feed_sync_status
            ADD CONSTRAINT feed_sync_status_duration_nonnegative_check
            CHECK (last_sync_duration IS NULL OR last_sync_duration >= INTERVAL '0') NOT VALID;
    END IF;
END $$;

ALTER TABLE feed_sync_status VALIDATE CONSTRAINT feed_sync_status_status_check;
ALTER TABLE feed_sync_status VALIDATE CONSTRAINT feed_sync_status_entries_nonnegative_check;
ALTER TABLE feed_sync_status VALIDATE CONSTRAINT feed_sync_status_entries_order_check;
ALTER TABLE feed_sync_status VALIDATE CONSTRAINT feed_sync_status_duration_nonnegative_check;

CREATE INDEX IF NOT EXISTS idx_reputation_reportable_sync
    ON package_reputation_cache(source, ecosystem, name, version)
    INCLUDE (updated_at)
    WHERE status IN ('malicious', 'removed', 'risk');
