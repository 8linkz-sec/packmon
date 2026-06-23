CREATE INDEX idx_vulnerabilities_recent_published
    ON vulnerabilities(published DESC, id DESC)
    WHERE withdrawn IS NULL;
