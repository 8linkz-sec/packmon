ALTER TABLE package_reputation_cache
    DROP CONSTRAINT IF EXISTS package_reputation_cache_severity_check;

ALTER TABLE malicious_findings
    DROP CONSTRAINT IF EXISTS malicious_findings_severity_check;

ALTER TABLE vulnerabilities
    DROP CONSTRAINT IF EXISTS vulnerabilities_severity_check;
