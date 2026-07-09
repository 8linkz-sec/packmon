-- 005_normalize_unknown_severity.up.sql
-- Existing OSV/RustSec records with affected.database_specific.categories
-- containing "malicious" predate the malicious-finding normalization. Move
-- those rows into malicious_findings, then remove remaining user-facing
-- UNKNOWN vulnerability severities by treating unresolved upstream severity as
-- LOW until CVE/NVD enrichment can raise it.

CREATE TABLE IF NOT EXISTS packmon_m005_vulnerabilities_backup (LIKE vulnerabilities);
CREATE TABLE IF NOT EXISTS packmon_m005_vulnerability_aliases_backup (LIKE vulnerability_aliases);
CREATE TABLE IF NOT EXISTS packmon_m005_vulnerability_sources_backup (LIKE vulnerability_sources);
CREATE TABLE IF NOT EXISTS packmon_m005_vulnerability_references_backup (LIKE vulnerability_references);
CREATE TABLE IF NOT EXISTS packmon_m005_affected_packages_backup (LIKE affected_packages);
CREATE TABLE IF NOT EXISTS packmon_m005_malicious_findings_backup (LIKE malicious_findings);

CREATE TABLE IF NOT EXISTS packmon_m005_malicious_vulnerability_ids (
    id TEXT PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS packmon_m005_malicious_finding_ids (
    id TEXT PRIMARY KEY
);

WITH malicious_vulnerabilities AS (
    SELECT DISTINCT v.id
    FROM vulnerabilities v
    INNER JOIN vulnerability_sources vs ON vs.vulnerability_id = v.id
    CROSS JOIN LATERAL jsonb_array_elements(COALESCE(vs.raw_json->'affected', '[]'::jsonb)) AS aff(value)
    WHERE EXISTS (
        SELECT 1
        FROM jsonb_array_elements_text(COALESCE(aff.value->'database_specific'->'categories', '[]'::jsonb)) AS category(value)
        WHERE lower(trim(category.value)) = 'malicious'
    )
)
INSERT INTO packmon_m005_malicious_vulnerability_ids (id)
SELECT id
FROM malicious_vulnerabilities
ON CONFLICT (id) DO NOTHING;

INSERT INTO packmon_m005_vulnerabilities_backup
SELECT v.*
FROM vulnerabilities v
WHERE (
        v.severity = 'UNKNOWN'
        OR EXISTS (
            SELECT 1
            FROM packmon_m005_malicious_vulnerability_ids mv
            WHERE mv.id = v.id
        )
    )
    AND NOT EXISTS (
        SELECT 1
        FROM packmon_m005_vulnerabilities_backup b
        WHERE b.id = v.id
    );

INSERT INTO packmon_m005_vulnerability_aliases_backup
SELECT va.*
FROM vulnerability_aliases va
INNER JOIN packmon_m005_malicious_vulnerability_ids mv ON mv.id = va.vulnerability_id
WHERE NOT EXISTS (
    SELECT 1
    FROM packmon_m005_vulnerability_aliases_backup b
    WHERE b.id = va.id
);

INSERT INTO packmon_m005_vulnerability_sources_backup
SELECT vs.*
FROM vulnerability_sources vs
INNER JOIN packmon_m005_malicious_vulnerability_ids mv ON mv.id = vs.vulnerability_id
WHERE NOT EXISTS (
    SELECT 1
    FROM packmon_m005_vulnerability_sources_backup b
    WHERE b.id = vs.id
);

INSERT INTO packmon_m005_vulnerability_references_backup
SELECT vr.*
FROM vulnerability_references vr
INNER JOIN packmon_m005_malicious_vulnerability_ids mv ON mv.id = vr.vulnerability_id
WHERE NOT EXISTS (
    SELECT 1
    FROM packmon_m005_vulnerability_references_backup b
    WHERE b.id = vr.id
);

INSERT INTO packmon_m005_affected_packages_backup
SELECT ap.*
FROM affected_packages ap
INNER JOIN packmon_m005_malicious_vulnerability_ids mv ON mv.id = ap.vulnerability_id
WHERE NOT EXISTS (
    SELECT 1
    FROM packmon_m005_affected_packages_backup b
    WHERE b.id = ap.id
);

WITH malicious_affected AS (
    SELECT
        v.id AS vulnerability_id,
        v.summary,
        v.details,
        v.published,
        vs.source,
        vs.raw_json,
        aff.value AS affected,
        aff.ordinality
    FROM vulnerabilities v
    INNER JOIN vulnerability_sources vs ON vs.vulnerability_id = v.id
    CROSS JOIN LATERAL jsonb_array_elements(COALESCE(vs.raw_json->'affected', '[]'::jsonb)) WITH ORDINALITY AS aff(value, ordinality)
    WHERE EXISTS (
        SELECT 1
        FROM jsonb_array_elements_text(COALESCE(aff.value->'database_specific'->'categories', '[]'::jsonb)) AS category(value)
        WHERE lower(trim(category.value)) = 'malicious'
    )
),
malicious_rows AS (
    SELECT
        CASE
            WHEN COUNT(*) OVER (PARTITION BY vulnerability_id) = 1 THEN vulnerability_id
            ELSE vulnerability_id || '-' || (ordinality - 1)::text
        END AS id,
        CASE lower(split_part(affected->'package'->>'ecosystem', ':', 1))
            WHEN 'crates.io' THEN 'cargo'
            WHEN 'pypi' THEN 'pypi'
            WHEN 'npm' THEN 'npm'
            WHEN 'go' THEN 'go'
            WHEN 'maven' THEN 'maven'
            WHEN 'packagist' THEN 'composer'
            WHEN 'rubygems' THEN 'gem'
            WHEN 'nuget' THEN 'nuget'
            ELSE lower(split_part(affected->'package'->>'ecosystem', ':', 1))
        END AS ecosystem,
        affected->'package'->>'name' AS name,
        NULLIF(affected->'versions', '[]'::jsonb) AS versions,
        source,
        CASE
            WHEN lower(summary || ' ' || COALESCE(details, '')) LIKE '%typosquat%' THEN 'typosquatting'
            WHEN lower(summary || ' ' || COALESCE(details, '')) LIKE '%supply chain%' THEN 'supply_chain'
            WHEN lower(summary || ' ' || COALESCE(details, '')) LIKE '%supply-chain%' THEN 'supply_chain'
            WHEN lower(summary || ' ' || COALESCE(details, '')) LIKE '%dependency confusion%' THEN 'supply_chain'
            ELSE 'malware'
        END AS risk_type,
        'CRITICAL' AS severity,
        summary,
        details AS description,
        COALESCE(
            (
                SELECT jsonb_agg(ref.value->>'url')
                FROM jsonb_array_elements(COALESCE(raw_json->'references', '[]'::jsonb)) AS ref(value)
                WHERE ref.value->>'url' <> ''
            ),
            '[]'::jsonb
        ) AS reference_urls,
        affected->'database_specific'->>'source' AS origin_ref,
        published,
        'feed-sync' AS created_by
    FROM malicious_affected
    WHERE affected->'package'->>'name' <> ''
)
INSERT INTO packmon_m005_malicious_finding_ids (id)
SELECT id
FROM malicious_rows
WHERE ecosystem <> ''
ON CONFLICT (id) DO NOTHING;

INSERT INTO packmon_m005_malicious_findings_backup
SELECT mf.*
FROM malicious_findings mf
INNER JOIN packmon_m005_malicious_finding_ids mfi ON mfi.id = mf.id
WHERE NOT EXISTS (
    SELECT 1
    FROM packmon_m005_malicious_findings_backup b
    WHERE b.id = mf.id
);

WITH malicious_affected AS (
    SELECT
        v.id AS vulnerability_id,
        v.summary,
        v.details,
        v.published,
        vs.source,
        vs.raw_json,
        aff.value AS affected,
        aff.ordinality
    FROM vulnerabilities v
    INNER JOIN vulnerability_sources vs ON vs.vulnerability_id = v.id
    CROSS JOIN LATERAL jsonb_array_elements(COALESCE(vs.raw_json->'affected', '[]'::jsonb)) WITH ORDINALITY AS aff(value, ordinality)
    INNER JOIN packmon_m005_malicious_vulnerability_ids mv ON mv.id = v.id
),
malicious_rows AS (
    SELECT
        CASE
            WHEN COUNT(*) OVER (PARTITION BY vulnerability_id) = 1 THEN vulnerability_id
            ELSE vulnerability_id || '-' || (ordinality - 1)::text
        END AS id,
        CASE lower(split_part(affected->'package'->>'ecosystem', ':', 1))
            WHEN 'crates.io' THEN 'cargo'
            WHEN 'pypi' THEN 'pypi'
            WHEN 'npm' THEN 'npm'
            WHEN 'go' THEN 'go'
            WHEN 'maven' THEN 'maven'
            WHEN 'packagist' THEN 'composer'
            WHEN 'rubygems' THEN 'gem'
            WHEN 'nuget' THEN 'nuget'
            ELSE lower(split_part(affected->'package'->>'ecosystem', ':', 1))
        END AS ecosystem,
        affected->'package'->>'name' AS name,
        NULLIF(affected->'versions', '[]'::jsonb) AS versions,
        source,
        CASE
            WHEN lower(summary || ' ' || COALESCE(details, '')) LIKE '%typosquat%' THEN 'typosquatting'
            WHEN lower(summary || ' ' || COALESCE(details, '')) LIKE '%supply chain%' THEN 'supply_chain'
            WHEN lower(summary || ' ' || COALESCE(details, '')) LIKE '%supply-chain%' THEN 'supply_chain'
            WHEN lower(summary || ' ' || COALESCE(details, '')) LIKE '%dependency confusion%' THEN 'supply_chain'
            ELSE 'malware'
        END AS risk_type,
        'CRITICAL' AS severity,
        summary,
        details AS description,
        COALESCE(
            (
                SELECT jsonb_agg(ref.value->>'url')
                FROM jsonb_array_elements(COALESCE(raw_json->'references', '[]'::jsonb)) AS ref(value)
                WHERE ref.value->>'url' <> ''
            ),
            '[]'::jsonb
        ) AS reference_urls,
        affected->'database_specific'->>'source' AS origin_ref,
        published,
        'feed-sync' AS created_by
    FROM malicious_affected
    WHERE affected->'package'->>'name' <> ''
)
INSERT INTO malicious_findings (
    id, ecosystem, name, versions, source, risk_type, severity, summary,
    description, reference_urls, origin_ref, published, created_by
)
SELECT
    id, ecosystem, name, versions, source, risk_type, severity, summary,
    description, reference_urls, origin_ref, published, created_by
FROM malicious_rows
WHERE ecosystem <> ''
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
    updated_at = NOW(),
    created_by = EXCLUDED.created_by;

DELETE FROM vulnerabilities v
USING packmon_m005_malicious_vulnerability_ids mv
WHERE v.id = mv.id;

UPDATE vulnerabilities
SET severity = 'LOW', updated_at = NOW()
WHERE severity = 'UNKNOWN';
