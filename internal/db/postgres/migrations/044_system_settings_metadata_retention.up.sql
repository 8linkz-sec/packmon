ALTER TABLE system_settings
  ADD COLUMN IF NOT EXISTS scan_log_retention_seconds BIGINT NOT NULL DEFAULT 2592000,
  ADD COLUMN IF NOT EXISTS admin_audit_retention_seconds BIGINT NOT NULL DEFAULT 2592000;

ALTER TABLE system_settings
  ADD CONSTRAINT system_settings_scan_log_retention_nonnegative_check
    CHECK (scan_log_retention_seconds >= 0) NOT VALID,
  ADD CONSTRAINT system_settings_admin_audit_retention_nonnegative_check
    CHECK (admin_audit_retention_seconds >= 0) NOT VALID;

ALTER TABLE system_settings
  VALIDATE CONSTRAINT system_settings_scan_log_retention_nonnegative_check,
  VALIDATE CONSTRAINT system_settings_admin_audit_retention_nonnegative_check;
