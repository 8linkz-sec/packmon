ALTER TABLE malicious_findings
    ADD COLUMN IF NOT EXISTS version_ranges JSONB;
