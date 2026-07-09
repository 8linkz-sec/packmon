UPDATE affected_packages
SET ecosystem = LOWER(TRIM(ecosystem))
WHERE ecosystem IS DISTINCT FROM LOWER(TRIM(ecosystem))
  AND LOWER(TRIM(ecosystem)) IN (
    'npm', 'pypi', 'go', 'maven', 'cargo', 'nuget', 'composer', 'gem',
    'pub', 'cocoapods', 'swiftpm', 'hex', 'cran', 'actions', 'docker'
  );

UPDATE malicious_findings
SET ecosystem = LOWER(TRIM(ecosystem)), updated_at = NOW()
WHERE ecosystem IS DISTINCT FROM LOWER(TRIM(ecosystem))
  AND LOWER(TRIM(ecosystem)) IN (
    'npm', 'pypi', 'go', 'maven', 'cargo', 'nuget', 'composer', 'gem',
    'pub', 'cocoapods', 'swiftpm', 'hex', 'cran', 'actions', 'docker'
  );

UPDATE package_reputation_cache
SET ecosystem = LOWER(TRIM(ecosystem)), updated_at = NOW()
WHERE ecosystem IS DISTINCT FROM LOWER(TRIM(ecosystem))
  AND LOWER(TRIM(ecosystem)) IN (
    'npm', 'pypi', 'go', 'maven', 'cargo', 'nuget', 'composer', 'gem',
    'pub', 'cocoapods', 'swiftpm', 'hex', 'cran', 'actions', 'docker'
  );

UPDATE package_check_status
SET ecosystem = LOWER(TRIM(ecosystem)), updated_at = NOW()
WHERE ecosystem IS DISTINCT FROM LOWER(TRIM(ecosystem))
  AND LOWER(TRIM(ecosystem)) IN (
    'npm', 'pypi', 'go', 'maven', 'cargo', 'nuget', 'composer', 'gem',
    'pub', 'cocoapods', 'swiftpm', 'hex', 'cran', 'actions', 'docker'
  );

UPDATE refresh_queue
SET ecosystem = LOWER(TRIM(ecosystem))
WHERE ecosystem IS DISTINCT FROM LOWER(TRIM(ecosystem))
  AND LOWER(TRIM(ecosystem)) IN (
    'npm', 'pypi', 'go', 'maven', 'cargo', 'nuget', 'composer', 'gem',
    'pub', 'cocoapods', 'swiftpm', 'hex', 'cran', 'actions', 'docker'
  );

UPDATE lifecycle_package_map
SET ecosystem = LOWER(TRIM(ecosystem)), updated_at = NOW()
WHERE ecosystem IS DISTINCT FROM LOWER(TRIM(ecosystem))
  AND LOWER(TRIM(ecosystem)) IN (
    'npm', 'pypi', 'go', 'maven', 'cargo', 'nuget', 'composer', 'gem',
    'pub', 'cocoapods', 'swiftpm', 'hex', 'cran', 'actions', 'docker'
  );

UPDATE lifecycle_sync_tombstones
SET ecosystem = LOWER(TRIM(ecosystem)), updated_at = NOW()
WHERE ecosystem IS DISTINCT FROM LOWER(TRIM(ecosystem))
  AND LOWER(TRIM(ecosystem)) IN (
    'npm', 'pypi', 'go', 'maven', 'cargo', 'nuget', 'composer', 'gem',
    'pub', 'cocoapods', 'swiftpm', 'hex', 'cran', 'actions', 'docker'
  );

UPDATE malicious_findings
SET risk_type = CASE
        WHEN LOWER(TRIM(risk_type)) IN ('', 'malware') THEN 'malware'
        WHEN LOWER(TRIM(risk_type)) IN ('supply_chain', 'supply-chain', 'supply chain') THEN 'supply_chain'
        WHEN LOWER(TRIM(risk_type)) IN ('typosquatting', 'typosquat', 'typo-squatting') THEN 'typosquatting'
        ELSE 'malware'
    END,
    updated_at = NOW()
WHERE risk_type IS DISTINCT FROM CASE
        WHEN LOWER(TRIM(risk_type)) IN ('', 'malware') THEN 'malware'
        WHEN LOWER(TRIM(risk_type)) IN ('supply_chain', 'supply-chain', 'supply chain') THEN 'supply_chain'
        WHEN LOWER(TRIM(risk_type)) IN ('typosquatting', 'typosquat', 'typo-squatting') THEN 'typosquatting'
        ELSE 'malware'
    END;

UPDATE refresh_queue
SET status = LOWER(TRIM(status))
WHERE LOWER(TRIM(status)) IN ('pending', 'processing', 'paused', 'done', 'error')
  AND status IS DISTINCT FROM LOWER(TRIM(status));

UPDATE refresh_queue
SET status = 'error',
    processed_at = COALESCE(processed_at, NOW()),
    error = COALESCE(NULLIF(error, ''), 'normalized invalid queue status during migration 031')
WHERE status NOT IN ('pending', 'processing', 'paused', 'done', 'error');

UPDATE refresh_queue
SET priority = CASE
        WHEN priority < 0 THEN 0
        WHEN priority > 3 THEN 3
        ELSE priority
    END
WHERE priority < 0 OR priority > 3;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'affected_packages_ecosystem_check') THEN
        ALTER TABLE affected_packages
            ADD CONSTRAINT affected_packages_ecosystem_check
            CHECK (ecosystem IN (
                'npm', 'pypi', 'go', 'maven', 'cargo', 'nuget', 'composer', 'gem',
                'pub', 'cocoapods', 'swiftpm', 'hex', 'cran', 'actions', 'docker'
            )) NOT VALID;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'malicious_findings_ecosystem_check') THEN
        ALTER TABLE malicious_findings
            ADD CONSTRAINT malicious_findings_ecosystem_check
            CHECK (ecosystem IN (
                'npm', 'pypi', 'go', 'maven', 'cargo', 'nuget', 'composer', 'gem',
                'pub', 'cocoapods', 'swiftpm', 'hex', 'cran', 'actions', 'docker'
            )) NOT VALID;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'package_reputation_cache_ecosystem_check') THEN
        ALTER TABLE package_reputation_cache
            ADD CONSTRAINT package_reputation_cache_ecosystem_check
            CHECK (ecosystem IN (
                'npm', 'pypi', 'go', 'maven', 'cargo', 'nuget', 'composer', 'gem',
                'pub', 'cocoapods', 'swiftpm', 'hex', 'cran', 'actions', 'docker'
            )) NOT VALID;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'package_check_status_ecosystem_check') THEN
        ALTER TABLE package_check_status
            ADD CONSTRAINT package_check_status_ecosystem_check
            CHECK (ecosystem IN (
                'npm', 'pypi', 'go', 'maven', 'cargo', 'nuget', 'composer', 'gem',
                'pub', 'cocoapods', 'swiftpm', 'hex', 'cran', 'actions', 'docker'
            )) NOT VALID;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'refresh_queue_ecosystem_check') THEN
        ALTER TABLE refresh_queue
            ADD CONSTRAINT refresh_queue_ecosystem_check
            CHECK (ecosystem IN (
                'npm', 'pypi', 'go', 'maven', 'cargo', 'nuget', 'composer', 'gem',
                'pub', 'cocoapods', 'swiftpm', 'hex', 'cran', 'actions', 'docker'
            )) NOT VALID;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'lifecycle_package_map_ecosystem_check') THEN
        ALTER TABLE lifecycle_package_map
            ADD CONSTRAINT lifecycle_package_map_ecosystem_check
            CHECK (ecosystem IN (
                'npm', 'pypi', 'go', 'maven', 'cargo', 'nuget', 'composer', 'gem',
                'pub', 'cocoapods', 'swiftpm', 'hex', 'cran', 'actions', 'docker'
            )) NOT VALID;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'lifecycle_sync_tombstones_ecosystem_check') THEN
        ALTER TABLE lifecycle_sync_tombstones
            ADD CONSTRAINT lifecycle_sync_tombstones_ecosystem_check
            CHECK (ecosystem IN (
                'npm', 'pypi', 'go', 'maven', 'cargo', 'nuget', 'composer', 'gem',
                'pub', 'cocoapods', 'swiftpm', 'hex', 'cran', 'actions', 'docker'
            )) NOT VALID;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'malicious_findings_risk_type_check') THEN
        ALTER TABLE malicious_findings
            ADD CONSTRAINT malicious_findings_risk_type_check
            CHECK (risk_type IN ('malware', 'supply_chain', 'typosquatting')) NOT VALID;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'vulnerability_sources_manual_id_check') THEN
        ALTER TABLE vulnerability_sources
            ADD CONSTRAINT vulnerability_sources_manual_id_check
            CHECK (source <> 'manual' OR (vulnerability_id LIKE 'manual:%' AND source_id LIKE 'manual:%')) NOT VALID;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'malicious_findings_manual_id_check') THEN
        ALTER TABLE malicious_findings
            ADD CONSTRAINT malicious_findings_manual_id_check
            CHECK (source <> 'manual' OR id LIKE 'manual:%') NOT VALID;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'refresh_queue_status_check') THEN
        ALTER TABLE refresh_queue
            ADD CONSTRAINT refresh_queue_status_check
            CHECK (status IN ('pending', 'processing', 'paused', 'done', 'error')) NOT VALID;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'refresh_queue_priority_check') THEN
        ALTER TABLE refresh_queue
            ADD CONSTRAINT refresh_queue_priority_check
            CHECK (priority BETWEEN 0 AND 3) NOT VALID;
    END IF;
END $$;

ALTER TABLE affected_packages VALIDATE CONSTRAINT affected_packages_ecosystem_check;
ALTER TABLE malicious_findings VALIDATE CONSTRAINT malicious_findings_ecosystem_check;
ALTER TABLE package_reputation_cache VALIDATE CONSTRAINT package_reputation_cache_ecosystem_check;
ALTER TABLE package_check_status VALIDATE CONSTRAINT package_check_status_ecosystem_check;
ALTER TABLE refresh_queue VALIDATE CONSTRAINT refresh_queue_ecosystem_check;
ALTER TABLE lifecycle_package_map VALIDATE CONSTRAINT lifecycle_package_map_ecosystem_check;
ALTER TABLE lifecycle_sync_tombstones VALIDATE CONSTRAINT lifecycle_sync_tombstones_ecosystem_check;
ALTER TABLE malicious_findings VALIDATE CONSTRAINT malicious_findings_risk_type_check;
ALTER TABLE vulnerability_sources VALIDATE CONSTRAINT vulnerability_sources_manual_id_check;
ALTER TABLE malicious_findings VALIDATE CONSTRAINT malicious_findings_manual_id_check;
ALTER TABLE refresh_queue VALIDATE CONSTRAINT refresh_queue_status_check;
ALTER TABLE refresh_queue VALIDATE CONSTRAINT refresh_queue_priority_check;
