-- 001_initial.up.sql
-- Packmon consolidated schema. All tables use TIMESTAMPTZ for timestamps.
-- Database must be created with ENCODING 'UTF8' (DE-14).

-- =============================================================================
-- 1. vulnerabilities -- Core vulnerability facts (DE-7)
-- =============================================================================
CREATE TABLE vulnerabilities (
    id              TEXT        PRIMARY KEY,
    summary         TEXT        NOT NULL,
    details         TEXT,
    severity        TEXT        NOT NULL DEFAULT 'UNKNOWN',
    cvss_score      REAL,
    epss_score      REAL,
    epss_percentile REAL,
    cisa_kev        BOOLEAN     NOT NULL DEFAULT FALSE,
    exploit_exists  BOOLEAN     NOT NULL DEFAULT FALSE,
    published       TIMESTAMPTZ NOT NULL,
    modified        TIMESTAMPTZ NOT NULL,
    withdrawn       TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

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
    UNIQUE(vulnerability_id, source)
);

CREATE INDEX idx_vuln_sources_vuln_id ON vulnerability_sources(vulnerability_id);

-- =============================================================================
-- 4. vulnerability_references -- Read links (DE-7)
-- =============================================================================
CREATE TABLE vulnerability_references (
    id               SERIAL      PRIMARY KEY,
    vulnerability_id TEXT        NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    type             TEXT,
    url              TEXT        NOT NULL,
    source           TEXT,
    UNIQUE(vulnerability_id, url)
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
    created_by     TEXT
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
    UNIQUE(ecosystem, name, source)
);

CREATE INDEX idx_check_status_next ON package_check_status(source, next_check_at);

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
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
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
    error        TEXT
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
    branch          TEXT,
    commit          TEXT,
    scanned_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    packages_count  INTEGER     NOT NULL,
    findings_count  INTEGER     NOT NULL,
    duration_ms     INTEGER     NOT NULL,
    client_ip       INET,
    user_agent      TEXT
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
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_admin_audit_time ON admin_audit_log(created_at);

-- =============================================================================
-- 13. api_keys -- API key management (DE-12)
-- =============================================================================
CREATE TABLE api_keys (
    id           SERIAL      PRIMARY KEY,
    name         TEXT        NOT NULL,
    key_hash     TEXT        NOT NULL UNIQUE,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at   TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ
);

CREATE INDEX idx_api_keys_hash ON api_keys(key_hash);

-- =============================================================================
-- 14. feed_configs -- Per-feed runtime configuration
-- =============================================================================
CREATE TABLE feed_configs (
    feed_name     TEXT        PRIMARY KEY,
    enabled       BOOLEAN     NOT NULL,
    mode          TEXT        NOT NULL CHECK (mode IN ('self', 'external')),
    sync_interval INTERVAL,
    api_key       TEXT,
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
