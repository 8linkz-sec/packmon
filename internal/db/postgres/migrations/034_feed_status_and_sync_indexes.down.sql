DROP INDEX IF EXISTS idx_reputation_reportable_sync;

ALTER TABLE feed_sync_status
    DROP CONSTRAINT IF EXISTS feed_sync_status_duration_nonnegative_check;

ALTER TABLE feed_sync_status
    DROP CONSTRAINT IF EXISTS feed_sync_status_entries_order_check;

ALTER TABLE feed_sync_status
    DROP CONSTRAINT IF EXISTS feed_sync_status_entries_nonnegative_check;

ALTER TABLE feed_sync_status
    DROP CONSTRAINT IF EXISTS feed_sync_status_status_check;
