-- Partial indexes backing CountUnknownSeverityFindings: the admin feeds page
-- counts active findings with unknown/empty severity on every load. The
-- predicates match the query exactly so the planner can answer from the
-- (nearly empty) indexes instead of scanning the large finding tables.
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_unknown_severity
    ON vulnerabilities (id)
    WHERE withdrawn IS NULL
      AND (TRIM(severity) = '' OR UPPER(TRIM(severity)) = 'UNKNOWN');

CREATE INDEX IF NOT EXISTS idx_malicious_unknown_severity
    ON malicious_findings (id)
    WHERE removed_at IS NULL
      AND (TRIM(severity) = '' OR UPPER(TRIM(severity)) = 'UNKNOWN');

CREATE INDEX IF NOT EXISTS idx_reputation_unknown_severity
    ON package_reputation_cache (id)
    WHERE status IN ('malicious', 'removed', 'risk')
      AND (TRIM(severity) = '' OR UPPER(TRIM(severity)) = 'UNKNOWN');
