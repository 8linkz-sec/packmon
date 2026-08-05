ALTER TABLE admin_audit_log
  ADD COLUMN previous_digest TEXT NOT NULL DEFAULT '',
  ADD COLUMN row_digest TEXT NOT NULL DEFAULT '';

CREATE INDEX idx_admin_audit_digest ON admin_audit_log(row_digest);
