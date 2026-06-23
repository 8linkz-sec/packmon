CREATE INDEX idx_queue_listing_requested_at ON refresh_queue(requested_at DESC, id DESC);

CREATE INDEX idx_queue_listing_status_requested_at ON refresh_queue(status, requested_at DESC, id DESC);
