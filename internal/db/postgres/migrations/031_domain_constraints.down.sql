ALTER TABLE refresh_queue
    DROP CONSTRAINT IF EXISTS refresh_queue_priority_check;

ALTER TABLE refresh_queue
    DROP CONSTRAINT IF EXISTS refresh_queue_status_check;

ALTER TABLE malicious_findings
    DROP CONSTRAINT IF EXISTS malicious_findings_manual_id_check;

ALTER TABLE vulnerability_sources
    DROP CONSTRAINT IF EXISTS vulnerability_sources_manual_id_check;

ALTER TABLE malicious_findings
    DROP CONSTRAINT IF EXISTS malicious_findings_risk_type_check;

ALTER TABLE lifecycle_sync_tombstones
    DROP CONSTRAINT IF EXISTS lifecycle_sync_tombstones_ecosystem_check;

ALTER TABLE lifecycle_package_map
    DROP CONSTRAINT IF EXISTS lifecycle_package_map_ecosystem_check;

ALTER TABLE refresh_queue
    DROP CONSTRAINT IF EXISTS refresh_queue_ecosystem_check;

ALTER TABLE package_check_status
    DROP CONSTRAINT IF EXISTS package_check_status_ecosystem_check;

ALTER TABLE package_reputation_cache
    DROP CONSTRAINT IF EXISTS package_reputation_cache_ecosystem_check;

ALTER TABLE malicious_findings
    DROP CONSTRAINT IF EXISTS malicious_findings_ecosystem_check;

ALTER TABLE affected_packages
    DROP CONSTRAINT IF EXISTS affected_packages_ecosystem_check;
