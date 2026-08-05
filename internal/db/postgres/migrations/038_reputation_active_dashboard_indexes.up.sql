CREATE INDEX IF NOT EXISTS idx_reputation_active_package
    ON package_reputation_cache(ecosystem, name)
    WHERE status IN ('malicious', 'removed', 'risk');

CREATE INDEX IF NOT EXISTS idx_reputation_active_status_severity
    ON package_reputation_cache(status, severity)
    WHERE status IN ('malicious', 'removed', 'risk');
