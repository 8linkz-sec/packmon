CREATE INDEX IF NOT EXISTS idx_malicious_active_exact_lookup
    ON malicious_findings(ecosystem, name, updated_at DESC, id DESC)
    WHERE removed_at IS NULL;
