-- 005_normalize_unknown_severity.down.sql
-- Data normalization is intentionally not reversible: rows moved from
-- vulnerabilities to malicious_findings cannot be reconstructed losslessly.
SELECT 1;
