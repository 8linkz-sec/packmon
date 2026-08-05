-- 005_normalize_unknown_severity.down.sql
-- Restore rows captured by the forward migration before it moved malicious
-- OSV/RustSec records and normalized UNKNOWN vulnerability severities.

DO $$
BEGIN
    IF to_regclass('public.packmon_m005_vulnerabilities_backup') IS NULL
        OR to_regclass('public.packmon_m005_vulnerability_aliases_backup') IS NULL
        OR to_regclass('public.packmon_m005_vulnerability_sources_backup') IS NULL
        OR to_regclass('public.packmon_m005_vulnerability_references_backup') IS NULL
        OR to_regclass('public.packmon_m005_affected_packages_backup') IS NULL
        OR to_regclass('public.packmon_m005_malicious_findings_backup') IS NULL
        OR to_regclass('public.packmon_m005_malicious_vulnerability_ids') IS NULL
        OR to_regclass('public.packmon_m005_malicious_finding_ids') IS NULL THEN
        RAISE EXCEPTION 'migration 005 rollback requires packmon_m005 backup tables created by 005 up; restore a pre-migration database backup for older deployments';
    END IF;
END $$;

DELETE FROM malicious_findings mf
USING packmon_m005_malicious_finding_ids mfi
WHERE mf.id = mfi.id;

INSERT INTO malicious_findings (
    id, ecosystem, name, versions, source, risk_type, severity, summary,
    description, reference_urls, origin_ref, published, created_at, updated_at,
    created_by
)
SELECT
    id, ecosystem, name, versions, source, risk_type, severity, summary,
    description, reference_urls, origin_ref, published, created_at, updated_at,
    created_by
FROM packmon_m005_malicious_findings_backup
ON CONFLICT (id) DO UPDATE SET
    ecosystem = EXCLUDED.ecosystem,
    name = EXCLUDED.name,
    versions = EXCLUDED.versions,
    source = EXCLUDED.source,
    risk_type = EXCLUDED.risk_type,
    severity = EXCLUDED.severity,
    summary = EXCLUDED.summary,
    description = EXCLUDED.description,
    reference_urls = EXCLUDED.reference_urls,
    origin_ref = EXCLUDED.origin_ref,
    published = EXCLUDED.published,
    created_at = EXCLUDED.created_at,
    updated_at = EXCLUDED.updated_at,
    created_by = EXCLUDED.created_by;

INSERT INTO vulnerabilities (
    id, summary, details, severity, cvss_score, epss_score, epss_percentile,
    cisa_kev, exploit_exists, published, modified, withdrawn, created_at,
    updated_at
)
SELECT
    b.id, b.summary, b.details, b.severity, b.cvss_score, b.epss_score,
    b.epss_percentile, b.cisa_kev, b.exploit_exists, b.published, b.modified,
    b.withdrawn, b.created_at, b.updated_at
FROM packmon_m005_vulnerabilities_backup b
INNER JOIN packmon_m005_malicious_vulnerability_ids mv ON mv.id = b.id
ON CONFLICT (id) DO UPDATE SET
    summary = EXCLUDED.summary,
    details = EXCLUDED.details,
    severity = EXCLUDED.severity,
    cvss_score = EXCLUDED.cvss_score,
    epss_score = EXCLUDED.epss_score,
    epss_percentile = EXCLUDED.epss_percentile,
    cisa_kev = EXCLUDED.cisa_kev,
    exploit_exists = EXCLUDED.exploit_exists,
    published = EXCLUDED.published,
    modified = EXCLUDED.modified,
    withdrawn = EXCLUDED.withdrawn,
    created_at = EXCLUDED.created_at,
    updated_at = EXCLUDED.updated_at;

UPDATE vulnerabilities v
SET severity = b.severity,
    updated_at = b.updated_at
FROM packmon_m005_vulnerabilities_backup b
WHERE v.id = b.id
    AND NOT EXISTS (
        SELECT 1
        FROM packmon_m005_malicious_vulnerability_ids mv
        WHERE mv.id = b.id
    );

INSERT INTO vulnerability_aliases (id, vulnerability_id, alias_id)
SELECT id, vulnerability_id, alias_id
FROM packmon_m005_vulnerability_aliases_backup
ON CONFLICT (id) DO UPDATE SET
    vulnerability_id = EXCLUDED.vulnerability_id,
    alias_id = EXCLUDED.alias_id;

INSERT INTO vulnerability_sources (
    id, vulnerability_id, source, source_id, url, raw_json, updated_at
)
SELECT id, vulnerability_id, source, source_id, url, raw_json, updated_at
FROM packmon_m005_vulnerability_sources_backup
ON CONFLICT (id) DO UPDATE SET
    vulnerability_id = EXCLUDED.vulnerability_id,
    source = EXCLUDED.source,
    source_id = EXCLUDED.source_id,
    url = EXCLUDED.url,
    raw_json = EXCLUDED.raw_json,
    updated_at = EXCLUDED.updated_at;

INSERT INTO vulnerability_references (id, vulnerability_id, type, url, source)
SELECT id, vulnerability_id, type, url, source
FROM packmon_m005_vulnerability_references_backup
ON CONFLICT (id) DO UPDATE SET
    vulnerability_id = EXCLUDED.vulnerability_id,
    type = EXCLUDED.type,
    url = EXCLUDED.url,
    source = EXCLUDED.source;

INSERT INTO affected_packages (
    id, vulnerability_id, ecosystem, name, version_ranges, versions_affected
)
SELECT id, vulnerability_id, ecosystem, name, version_ranges, versions_affected
FROM packmon_m005_affected_packages_backup
ON CONFLICT (id) DO UPDATE SET
    vulnerability_id = EXCLUDED.vulnerability_id,
    ecosystem = EXCLUDED.ecosystem,
    name = EXCLUDED.name,
    version_ranges = EXCLUDED.version_ranges,
    versions_affected = EXCLUDED.versions_affected;

SELECT setval(
    pg_get_serial_sequence('vulnerability_aliases', 'id'),
    GREATEST(COALESCE((SELECT MAX(id) FROM vulnerability_aliases), 1), 1),
    (SELECT COUNT(*) > 0 FROM vulnerability_aliases)
);
SELECT setval(
    pg_get_serial_sequence('vulnerability_sources', 'id'),
    GREATEST(COALESCE((SELECT MAX(id) FROM vulnerability_sources), 1), 1),
    (SELECT COUNT(*) > 0 FROM vulnerability_sources)
);
SELECT setval(
    pg_get_serial_sequence('vulnerability_references', 'id'),
    GREATEST(COALESCE((SELECT MAX(id) FROM vulnerability_references), 1), 1),
    (SELECT COUNT(*) > 0 FROM vulnerability_references)
);
SELECT setval(
    pg_get_serial_sequence('affected_packages', 'id'),
    GREATEST(COALESCE((SELECT MAX(id) FROM affected_packages), 1), 1),
    (SELECT COUNT(*) > 0 FROM affected_packages)
);

DROP TABLE IF EXISTS packmon_m005_malicious_finding_ids;
DROP TABLE IF EXISTS packmon_m005_malicious_vulnerability_ids;
DROP TABLE IF EXISTS packmon_m005_malicious_findings_backup;
DROP TABLE IF EXISTS packmon_m005_affected_packages_backup;
DROP TABLE IF EXISTS packmon_m005_vulnerability_references_backup;
DROP TABLE IF EXISTS packmon_m005_vulnerability_sources_backup;
DROP TABLE IF EXISTS packmon_m005_vulnerability_aliases_backup;
DROP TABLE IF EXISTS packmon_m005_vulnerabilities_backup;
