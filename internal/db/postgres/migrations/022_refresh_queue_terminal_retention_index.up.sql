CREATE INDEX idx_queue_terminal_processed_at
    ON refresh_queue(COALESCE(processed_at, requested_at))
    WHERE status IN ('done', 'error');
