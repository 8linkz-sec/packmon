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
