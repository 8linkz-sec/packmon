ALTER TABLE system_settings
  DROP CONSTRAINT IF EXISTS system_settings_scan_log_retention_nonnegative_check,
  DROP CONSTRAINT IF EXISTS system_settings_admin_audit_retention_nonnegative_check;

ALTER TABLE system_settings
  DROP COLUMN IF EXISTS scan_log_retention_seconds,
  DROP COLUMN IF EXISTS admin_audit_retention_seconds;
