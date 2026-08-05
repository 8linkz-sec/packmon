DROP INDEX IF EXISTS idx_admin_audit_digest;
DROP INDEX IF EXISTS idx_api_keys_hash;
DROP INDEX IF EXISTS idx_api_keys_expires_at;
DROP INDEX IF EXISTS idx_api_keys_deleted_at;
DROP INDEX IF EXISTS lifecycle_package_map_lookup_idx;
DROP INDEX IF EXISTS idx_malicious_eco_name;
DROP INDEX IF EXISTS idx_check_status_next;
DROP INDEX IF EXISTS idx_scan_log_scan_id;
DROP INDEX IF EXISTS idx_vuln_aliases_vuln_id;
DROP INDEX IF EXISTS idx_vuln_sources_vuln_id;
DROP INDEX IF EXISTS idx_vuln_refs_vuln_id;
DROP INDEX IF EXISTS idx_affected_eco_name;

CREATE INDEX IF NOT EXISTS idx_malicious_sync_keyset
    ON malicious_findings(ecosystem, name, id);

CREATE INDEX IF NOT EXISTS idx_affected_sync_keyset
    ON affected_packages(ecosystem, name, vulnerability_id);

DROP TABLE IF EXISTS scan_log_totals;

CREATE VIEW scan_log_totals AS
SELECT
    TRUE AS id,
    COALESCE(SUM(packages_count), 0)::BIGINT AS packages_scanned,
    COALESCE(SUM(findings_count), 0)::BIGINT AS findings,
    COALESCE(MAX(scanned_at), NOW()) AS updated_at
FROM scan_log;
