DROP VIEW IF EXISTS scan_log_totals;

CREATE TABLE scan_log_totals (
    id BOOLEAN PRIMARY KEY DEFAULT TRUE,
    packages_scanned BIGINT NOT NULL DEFAULT 0 CHECK (packages_scanned >= 0),
    findings BIGINT NOT NULL DEFAULT 0 CHECK (findings >= 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT scan_log_totals_singleton CHECK (id)
);

INSERT INTO scan_log_totals (id, packages_scanned, findings)
SELECT
    TRUE,
    COALESCE(SUM(packages_count), 0),
    COALESCE(SUM(findings_count), 0)
FROM scan_log;

DROP INDEX IF EXISTS idx_malicious_sync_keyset;
DROP INDEX IF EXISTS idx_affected_sync_keyset;

CREATE INDEX IF NOT EXISTS idx_admin_audit_digest
    ON admin_audit_log(row_digest);

CREATE INDEX IF NOT EXISTS idx_api_keys_hash
    ON api_keys(key_hash);

CREATE INDEX IF NOT EXISTS idx_api_keys_expires_at
    ON api_keys(expires_at)
    WHERE expires_at IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_api_keys_deleted_at
    ON api_keys(deleted_at)
    WHERE deleted_at IS NOT NULL;

CREATE INDEX IF NOT EXISTS lifecycle_package_map_lookup_idx
    ON lifecycle_package_map(ecosystem, name);

CREATE INDEX IF NOT EXISTS idx_malicious_eco_name
    ON malicious_findings(ecosystem, name);

CREATE INDEX IF NOT EXISTS idx_check_status_next
    ON package_check_status(source, next_check_at);

CREATE INDEX IF NOT EXISTS idx_scan_log_scan_id
    ON scan_log(scan_id);

CREATE INDEX IF NOT EXISTS idx_vuln_aliases_vuln_id
    ON vulnerability_aliases(vulnerability_id);

CREATE INDEX IF NOT EXISTS idx_vuln_sources_vuln_id
    ON vulnerability_sources(vulnerability_id);

CREATE INDEX IF NOT EXISTS idx_vuln_refs_vuln_id
    ON vulnerability_references(vulnerability_id);

CREATE INDEX IF NOT EXISTS idx_affected_eco_name
    ON affected_packages(ecosystem, name);
