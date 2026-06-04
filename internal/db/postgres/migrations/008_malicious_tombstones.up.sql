ALTER TABLE malicious_findings
ADD COLUMN removed_at TIMESTAMPTZ;

CREATE INDEX idx_malicious_removed_at ON malicious_findings(removed_at);
