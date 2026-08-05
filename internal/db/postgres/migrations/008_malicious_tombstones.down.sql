DROP INDEX IF EXISTS idx_malicious_removed_at;

ALTER TABLE malicious_findings
DROP COLUMN IF EXISTS removed_at;
