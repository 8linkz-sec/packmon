CREATE INDEX IF NOT EXISTS idx_package_check_status_socket_updated_at
    ON package_check_status(updated_at)
    WHERE source = 'socket';
