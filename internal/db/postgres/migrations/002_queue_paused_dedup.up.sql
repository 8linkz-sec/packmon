-- Include paused jobs in queue deduplication so pausing a job does not allow
-- duplicate pending work for the same package/source.
DROP INDEX IF EXISTS idx_queue_dedup;

WITH ranked_refresh_queue AS (
    SELECT
        id,
        ROW_NUMBER() OVER (
            PARTITION BY ecosystem, name, source
            ORDER BY
                CASE status
                    WHEN 'processing' THEN 0
                    WHEN 'pending' THEN 1
                    WHEN 'paused' THEN 2
                    ELSE 3
                END,
                priority ASC,
                requested_at ASC,
                id ASC
        ) AS duplicate_rank
    FROM refresh_queue
    WHERE status IN ('pending', 'processing', 'paused')
)
DELETE FROM refresh_queue q
USING ranked_refresh_queue ranked
WHERE q.id = ranked.id
  AND ranked.duplicate_rank > 1;

CREATE UNIQUE INDEX idx_queue_dedup
    ON refresh_queue(ecosystem, name, source)
    WHERE status IN ('pending', 'processing', 'paused');
