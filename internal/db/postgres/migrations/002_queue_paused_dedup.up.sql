-- Include paused jobs in queue deduplication so pausing a job does not allow
-- duplicate pending work for the same package/source.
DROP INDEX IF EXISTS idx_queue_dedup;

CREATE UNIQUE INDEX idx_queue_dedup
    ON refresh_queue(ecosystem, name, source)
    WHERE status IN ('pending', 'processing', 'paused');
