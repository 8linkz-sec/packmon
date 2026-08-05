DROP INDEX IF EXISTS idx_admin_audit_digest;

ALTER TABLE admin_audit_log
  DROP COLUMN IF EXISTS row_digest,
  DROP COLUMN IF EXISTS previous_digest;
