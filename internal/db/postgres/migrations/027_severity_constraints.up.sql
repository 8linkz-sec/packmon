UPDATE vulnerabilities
SET severity = 'LOW', updated_at = NOW()
WHERE TRIM(severity) = ''
   OR UPPER(TRIM(severity)) = 'UNKNOWN';

UPDATE vulnerabilities
SET severity = UPPER(TRIM(severity)), updated_at = NOW()
WHERE severity IS DISTINCT FROM UPPER(TRIM(severity))
  AND UPPER(TRIM(severity)) IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW');

UPDATE vulnerabilities
SET severity = 'LOW', updated_at = NOW()
WHERE severity NOT IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW');

UPDATE malicious_findings
SET severity = COALESCE(NULLIF(UPPER(TRIM(severity)), ''), 'UNKNOWN'),
    updated_at = NOW()
WHERE severity IS DISTINCT FROM COALESCE(NULLIF(UPPER(TRIM(severity)), ''), 'UNKNOWN')
  AND COALESCE(NULLIF(UPPER(TRIM(severity)), ''), 'UNKNOWN') IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN');

UPDATE malicious_findings
SET severity = 'UNKNOWN', updated_at = NOW()
WHERE severity NOT IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN');

UPDATE package_reputation_cache
SET severity = CASE
        WHEN TRIM(severity) = '' OR UPPER(TRIM(severity)) = 'UNKNOWN' THEN 'CRITICAL'
        ELSE UPPER(TRIM(severity))
    END,
    updated_at = NOW()
WHERE severity IS DISTINCT FROM CASE
        WHEN TRIM(severity) = '' OR UPPER(TRIM(severity)) = 'UNKNOWN' THEN 'CRITICAL'
        ELSE UPPER(TRIM(severity))
    END
  AND CASE
        WHEN TRIM(severity) = '' OR UPPER(TRIM(severity)) = 'UNKNOWN' THEN 'CRITICAL'
        ELSE UPPER(TRIM(severity))
    END IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW');

UPDATE package_reputation_cache
SET severity = 'CRITICAL', updated_at = NOW()
WHERE severity NOT IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW');

ALTER TABLE vulnerabilities
    DROP CONSTRAINT IF EXISTS vulnerabilities_severity_check;

ALTER TABLE malicious_findings
    DROP CONSTRAINT IF EXISTS malicious_findings_severity_check;

ALTER TABLE package_reputation_cache
    DROP CONSTRAINT IF EXISTS package_reputation_cache_severity_check;

ALTER TABLE vulnerabilities
    ADD CONSTRAINT vulnerabilities_severity_check
    CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')) NOT VALID;

ALTER TABLE malicious_findings
    ADD CONSTRAINT malicious_findings_severity_check
    CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN')) NOT VALID;

ALTER TABLE package_reputation_cache
    ADD CONSTRAINT package_reputation_cache_severity_check
    CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')) NOT VALID;

ALTER TABLE vulnerabilities VALIDATE CONSTRAINT vulnerabilities_severity_check;
ALTER TABLE malicious_findings VALIDATE CONSTRAINT malicious_findings_severity_check;
ALTER TABLE package_reputation_cache VALIDATE CONSTRAINT package_reputation_cache_severity_check;
