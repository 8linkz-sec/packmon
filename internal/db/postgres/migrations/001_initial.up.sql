-- 001_initial.up.sql
-- Packmon consolidated schema. All tables use TIMESTAMPTZ for timestamps.
-- Database must be created with ENCODING 'UTF8' (DE-14).

CREATE OR REPLACE FUNCTION packmon_jsonb_string_array_valid(value JSONB)
RETURNS BOOLEAN
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
    item JSONB;
BEGIN
    IF value IS NULL OR jsonb_typeof(value) <> 'array' THEN
        RETURN FALSE;
    END IF;

    FOR item IN SELECT jsonb_array_elements(value)
    LOOP
        IF jsonb_typeof(item) <> 'string' THEN
            RETURN FALSE;
        END IF;
    END LOOP;

    RETURN TRUE;
END;
$$;

CREATE OR REPLACE FUNCTION packmon_jsonb_version_ranges_valid(value JSONB)
RETURNS BOOLEAN
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
    range_item JSONB;
    event_item JSONB;
BEGIN
    IF value IS NULL OR jsonb_typeof(value) <> 'array' THEN
        RETURN FALSE;
    END IF;

    FOR range_item IN SELECT jsonb_array_elements(value)
    LOOP
        IF jsonb_typeof(range_item) <> 'object'
           OR jsonb_typeof(range_item->'events') <> 'array'
           OR jsonb_array_length(range_item->'events') = 0 THEN
            RETURN FALSE;
        END IF;

        FOR event_item IN SELECT jsonb_array_elements(range_item->'events')
        LOOP
            IF jsonb_typeof(event_item) <> 'object'
               OR NOT (
                    event_item ? 'introduced'
                    OR event_item ? 'fixed'
                    OR event_item ? 'last_affected'
                    OR event_item ? 'limit'
               ) THEN
                RETURN FALSE;
            END IF;
        END LOOP;
    END LOOP;

    RETURN TRUE;
END;
$$;

-- =============================================================================
-- 1. vulnerabilities -- Core vulnerability facts (DE-7)
-- =============================================================================
CREATE TABLE vulnerabilities (
    id              TEXT        PRIMARY KEY,
    summary         TEXT        NOT NULL,
    details         TEXT,
    severity        TEXT        NOT NULL DEFAULT 'LOW',
    cvss_score      REAL,
    epss_score      REAL,
    epss_percentile REAL,
    cisa_kev        BOOLEAN     NOT NULL DEFAULT FALSE,
    exploit_exists  BOOLEAN     NOT NULL DEFAULT FALSE,
    published       TIMESTAMPTZ NOT NULL,
    modified        TIMESTAMPTZ NOT NULL,
    withdrawn       TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT vulnerabilities_severity_check
        CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')),
    CONSTRAINT vulnerabilities_cvss_score_range_check
        CHECK (cvss_score IS NULL OR (cvss_score >= 0 AND cvss_score <= 10)),
    CONSTRAINT vulnerabilities_epss_score_range_check
        CHECK (epss_score IS NULL OR (epss_score >= 0 AND epss_score <= 1)),
    CONSTRAINT vulnerabilities_epss_percentile_range_check
        CHECK (epss_percentile IS NULL OR (epss_percentile >= 0 AND epss_percentile <= 1))
);

CREATE INDEX idx_vulnerabilities_nvd_candidate ON vulnerabilities(id)
    WHERE severity = 'UNKNOWN' OR (severity = 'LOW' AND cvss_score IS NULL);
CREATE INDEX idx_vulnerabilities_cisa_kev ON vulnerabilities(id)
    WHERE cisa_kev = TRUE;

-- =============================================================================
-- 2. vulnerability_aliases -- All IDs for a vulnerability (DE-7)
--    Many-to-many: same alias can link to multiple vulnerabilities.
-- =============================================================================
CREATE TABLE vulnerability_aliases (
    id               SERIAL      PRIMARY KEY,
    vulnerability_id TEXT        NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    alias_id         TEXT        NOT NULL,
    UNIQUE(vulnerability_id, alias_id)
);

CREATE INDEX idx_vuln_aliases_vuln_id ON vulnerability_aliases(vulnerability_id);
CREATE INDEX idx_vuln_aliases_alias_id ON vulnerability_aliases(alias_id);
CREATE INDEX idx_vuln_aliases_cve_alias ON vulnerability_aliases(alias_id text_pattern_ops, vulnerability_id)
    WHERE alias_id LIKE 'CVE-%';

-- =============================================================================
-- 2a. nvd_cvss_negative_cache -- Negative NVD CVSS lookup cache per CVE alias
-- =============================================================================
CREATE TABLE nvd_cvss_negative_cache (
    cve_id                   TEXT        PRIMARY KEY,
    checked_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    vulnerability_updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_nvd_cvss_negative_cache_checked_at
    ON nvd_cvss_negative_cache(checked_at);

-- =============================================================================
-- 3. vulnerability_sources -- Provenance and freshness per feed (DE-7)
-- =============================================================================
CREATE TABLE vulnerability_sources (
    id               SERIAL      PRIMARY KEY,
    vulnerability_id TEXT        NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    source           TEXT        NOT NULL,
    source_id        TEXT        NOT NULL,
    url              TEXT,
    raw_json         JSONB,
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT vulnerability_sources_manual_id_check
        CHECK (source <> 'manual' OR (vulnerability_id LIKE 'manual:%' AND source_id LIKE 'manual:%')),
    UNIQUE(vulnerability_id, source)
);

CREATE INDEX idx_vuln_sources_vuln_id ON vulnerability_sources(vulnerability_id);
CREATE INDEX idx_vuln_sources_source_vuln_id ON vulnerability_sources(source, vulnerability_id) WHERE raw_json IS NOT NULL;

-- =============================================================================
-- 4. vulnerability_references -- Read links (DE-7)
-- =============================================================================
CREATE TABLE vulnerability_references (
    id               SERIAL      PRIMARY KEY,
    vulnerability_id TEXT        NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    type             TEXT,
    url              TEXT        NOT NULL,
    source           TEXT        NOT NULL DEFAULT '',
    UNIQUE(vulnerability_id, source, url)
);

CREATE INDEX idx_vuln_refs_vuln_id ON vulnerability_references(vulnerability_id);

-- =============================================================================
-- 5. affected_packages -- Affected packages per vulnerability (1:N)
-- =============================================================================
CREATE TABLE affected_packages (
    id                SERIAL      PRIMARY KEY,
    vulnerability_id  TEXT        NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    ecosystem         TEXT        NOT NULL,
    name              TEXT        NOT NULL,
    version_ranges    JSONB       NOT NULL DEFAULT '[]',
    versions_affected JSONB       NOT NULL DEFAULT '[]',
    CONSTRAINT affected_packages_version_ranges_array_check
        CHECK (packmon_jsonb_version_ranges_valid(version_ranges)),
    CONSTRAINT affected_packages_versions_affected_array_check
        CHECK (packmon_jsonb_string_array_valid(versions_affected)),
    CONSTRAINT affected_packages_ecosystem_check
        CHECK (ecosystem IN (
            'npm', 'pypi', 'go', 'maven', 'cargo', 'nuget', 'composer', 'gem',
            'pub', 'cocoapods', 'swiftpm', 'hex', 'cran', 'actions', 'docker'
        )),
    UNIQUE(vulnerability_id, ecosystem, name)
);

CREATE INDEX idx_affected_eco_name ON affected_packages(ecosystem, name);

-- =============================================================================
-- 6. malicious_findings -- Malicious package findings (DE-14)
-- =============================================================================
CREATE TABLE malicious_findings (
    id             TEXT        PRIMARY KEY,
    ecosystem      TEXT        NOT NULL,
    name           TEXT        NOT NULL,
    version_ranges JSONB,
    versions       JSONB,
    source         TEXT        NOT NULL,
    risk_type      TEXT        NOT NULL,
    severity       TEXT        NOT NULL DEFAULT 'CRITICAL',
    summary        TEXT        NOT NULL,
    description    TEXT,
    reference_urls JSONB       NOT NULL DEFAULT '[]',
    origin_ref     TEXT,
    published      TIMESTAMPTZ,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by     TEXT,
    CONSTRAINT malicious_findings_version_ranges_array_check
        CHECK (version_ranges IS NULL OR packmon_jsonb_version_ranges_valid(version_ranges)),
    CONSTRAINT malicious_findings_versions_array_check
        CHECK (versions IS NULL OR packmon_jsonb_string_array_valid(versions)),
    CONSTRAINT malicious_findings_ecosystem_check
        CHECK (ecosystem IN (
            'npm', 'pypi', 'go', 'maven', 'cargo', 'nuget', 'composer', 'gem',
            'pub', 'cocoapods', 'swiftpm', 'hex', 'cran', 'actions', 'docker'
        )),
    CONSTRAINT malicious_findings_risk_type_check
        CHECK (risk_type IN ('malware', 'supply_chain', 'typosquatting')),
    CONSTRAINT malicious_findings_severity_check
        CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN')),
    CONSTRAINT malicious_findings_manual_id_check
        CHECK (source <> 'manual' OR id LIKE 'manual:%')
);

CREATE INDEX idx_malicious_eco_name ON malicious_findings(ecosystem, name);
CREATE INDEX idx_malicious_source ON malicious_findings(source);

-- =============================================================================
-- 7. package_check_status -- Per-package check status for async feeds (DE-15)
-- =============================================================================
CREATE TABLE package_check_status (
    id              SERIAL      PRIMARY KEY,
    ecosystem       TEXT        NOT NULL,
    name            TEXT        NOT NULL,
    source          TEXT        NOT NULL,
    last_checked_at TIMESTAMPTZ,
    next_check_at   TIMESTAMPTZ,
    check_count     INTEGER     NOT NULL DEFAULT 0,
    last_result     JSONB,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT package_check_status_ecosystem_check
        CHECK (ecosystem IN (
            'npm', 'pypi', 'go', 'maven', 'cargo', 'nuget', 'composer', 'gem',
            'pub', 'cocoapods', 'swiftpm', 'hex', 'cran', 'actions', 'docker'
        )),
    UNIQUE(ecosystem, name, source)
);

CREATE INDEX idx_check_status_next ON package_check_status(source, next_check_at);
CREATE INDEX idx_package_check_status_socket_updated_at ON package_check_status(updated_at)
    WHERE source = 'socket';

-- =============================================================================
-- 8. feed_sync_status -- Sync state per feed
-- =============================================================================
CREATE TABLE feed_sync_status (
    feed_name          TEXT        PRIMARY KEY,
    last_sync_at       TIMESTAMPTZ,
    last_sync_duration INTERVAL,
    last_sync_status   TEXT        NOT NULL DEFAULT 'pending',
    last_error         TEXT,
    entries_synced     INTEGER     NOT NULL DEFAULT 0,
    entries_total      INTEGER     NOT NULL DEFAULT 0,
    last_etag          TEXT,
    last_commit_hash   TEXT,
    metadata           JSONB       NOT NULL DEFAULT '{}',
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT feed_sync_status_status_check
        CHECK (last_sync_status IN (
            'pending', 'running', 'success', 'error', 'skipped',
            'disabled', 'external', 'rejected', 'permanent_error'
        )),
    CONSTRAINT feed_sync_status_entries_nonnegative_check
        CHECK (entries_synced >= 0 AND entries_total >= 0),
    CONSTRAINT feed_sync_status_entries_order_check
        CHECK (entries_total <= 0 OR entries_synced <= entries_total),
    CONSTRAINT feed_sync_status_duration_nonnegative_check
        CHECK (last_sync_duration IS NULL OR last_sync_duration >= INTERVAL '0')
);

-- =============================================================================
-- 9. refresh_queue -- Priority queue for async feed checks (DE-15, DE-16)
-- =============================================================================
CREATE TABLE refresh_queue (
    id           SERIAL      PRIMARY KEY,
    ecosystem    TEXT        NOT NULL,
    name         TEXT        NOT NULL,
    source       TEXT        NOT NULL,
    priority     INTEGER     NOT NULL DEFAULT 3,
    status       TEXT        NOT NULL DEFAULT 'pending',
    requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    processed_at TIMESTAMPTZ,
    error        TEXT,
    CONSTRAINT refresh_queue_ecosystem_check
        CHECK (ecosystem IN (
            'npm', 'pypi', 'go', 'maven', 'cargo', 'nuget', 'composer', 'gem',
            'pub', 'cocoapods', 'swiftpm', 'hex', 'cran', 'actions', 'docker'
        )),
    CONSTRAINT refresh_queue_status_check
        CHECK (status IN ('pending', 'processing', 'paused', 'done', 'error')),
    CONSTRAINT refresh_queue_priority_check
        CHECK (priority BETWEEN 0 AND 3)
);

CREATE INDEX idx_queue_priority ON refresh_queue(source, status, priority, requested_at);

CREATE UNIQUE INDEX idx_queue_dedup
    ON refresh_queue(ecosystem, name, source)
    WHERE status IN ('pending', 'processing');

-- =============================================================================
-- 10. scan_log -- Scan audit log (DE-25)
-- =============================================================================
CREATE TABLE scan_log (
    id              SERIAL      PRIMARY KEY,
    scan_id         TEXT        NOT NULL,
    repo_name       TEXT,
    scanned_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    packages_count  INTEGER     NOT NULL,
    findings_count  INTEGER     NOT NULL,
    duration_ms     INTEGER     NOT NULL,
    client_ip       INET,
    client_version  TEXT,
    api_key_id      INTEGER,
    api_key_name    TEXT,
    CONSTRAINT scan_log_packages_count_nonnegative_check
        CHECK (packages_count >= 0),
    CONSTRAINT scan_log_findings_count_nonnegative_check
        CHECK (findings_count >= 0),
    CONSTRAINT scan_log_duration_ms_nonnegative_check
        CHECK (duration_ms >= 0)
);

CREATE INDEX idx_scan_log_time ON scan_log(scanned_at);
CREATE INDEX idx_scan_log_scan_id ON scan_log(scan_id);

-- =============================================================================
-- 11. admin_auth -- Single-row shared admin login
-- =============================================================================
CREATE TABLE admin_auth (
    id                    SMALLINT    PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    username              TEXT        NOT NULL UNIQUE DEFAULT 'admin' CHECK (username = 'admin'),
    password_hash         TEXT        NOT NULL,
    password_is_bootstrap BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    password_changed_at   TIMESTAMPTZ,
    last_login_at         TIMESTAMPTZ
);

-- =============================================================================
-- 12. admin_audit_log -- Admin action audit trail
-- =============================================================================
CREATE TABLE admin_audit_log (
    id         SERIAL      PRIMARY KEY,
    action     TEXT        NOT NULL,
    details    JSONB,
    ip         INET,
    correlation_id TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_admin_audit_time ON admin_audit_log(created_at);
CREATE INDEX idx_admin_audit_correlation_id ON admin_audit_log(correlation_id) WHERE correlation_id <> '';

-- =============================================================================
-- 13. api_keys -- API key management (DE-12)
-- =============================================================================
CREATE TABLE api_keys (
    id           SERIAL      PRIMARY KEY,
    name         TEXT        NOT NULL,
    key_hash     TEXT        NOT NULL UNIQUE,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at   TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    CONSTRAINT api_keys_revoked_not_before_created_check
        CHECK (revoked_at IS NULL OR revoked_at >= created_at),
    CONSTRAINT api_keys_last_used_not_before_created_check
        CHECK (last_used_at IS NULL OR last_used_at >= created_at)
);

CREATE INDEX idx_api_keys_hash ON api_keys(key_hash);

ALTER TABLE scan_log
    ADD CONSTRAINT scan_log_api_key_id_fkey
        FOREIGN KEY (api_key_id) REFERENCES api_keys(id) ON DELETE SET NULL;

-- =============================================================================
-- 14. feed_configs -- Per-feed runtime configuration
-- =============================================================================
CREATE TABLE feed_configs (
    feed_name     TEXT        PRIMARY KEY,
    enabled       BOOLEAN     NOT NULL,
    mode          TEXT        NOT NULL CHECK (mode IN ('self', 'external')),
    sync_interval INTERVAL,
    api_key       TEXT,
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT feed_configs_sync_interval_minimum_check
        CHECK (sync_interval IS NULL OR sync_interval >= INTERVAL '15 minutes')
);
