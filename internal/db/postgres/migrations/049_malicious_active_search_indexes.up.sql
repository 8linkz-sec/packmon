-- packmon:migration no-transaction
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_malicious_active_search_order
    ON malicious_findings (name, ecosystem, source)
    INCLUDE (severity)
    WHERE removed_at IS NULL;

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_malicious_active_severity_search
    ON malicious_findings (severity, name, ecosystem, source)
    WHERE removed_at IS NULL;
