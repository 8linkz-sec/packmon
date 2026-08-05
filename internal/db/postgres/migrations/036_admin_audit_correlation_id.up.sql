ALTER TABLE admin_audit_log
    ADD COLUMN IF NOT EXISTS correlation_id TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_admin_audit_correlation_id
    ON admin_audit_log(correlation_id)
    WHERE correlation_id <> '';
