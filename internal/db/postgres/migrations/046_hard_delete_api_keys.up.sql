-- API key deletion is permanent as of this version. Remove existing
-- soft-deleted tombstone rows; their delete actions remain recorded in
-- admin_audit_log, and scan_log references stay intact with api_key_id
-- cleared through the existing ON DELETE SET NULL constraint.
DELETE FROM api_keys WHERE deleted_at IS NOT NULL;
