DROP INDEX IF EXISTS idx_queue_dedup;

CREATE UNIQUE INDEX idx_queue_dedup
    ON refresh_queue(ecosystem, name, source)
    WHERE status IN ('pending', 'processing');
