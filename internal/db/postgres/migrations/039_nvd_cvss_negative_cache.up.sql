CREATE TABLE IF NOT EXISTS nvd_cvss_negative_cache (
    cve_id                   TEXT        PRIMARY KEY,
    checked_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    vulnerability_updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_nvd_cvss_negative_cache_checked_at
    ON nvd_cvss_negative_cache(checked_at);
