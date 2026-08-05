-- packmon:migration no-transaction
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_vulnerabilities_updated_at ON vulnerabilities(updated_at);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_malicious_findings_updated_at ON malicious_findings(updated_at);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_package_reputation_cache_updated_at ON package_reputation_cache(updated_at);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_lifecycle_products_updated_at ON lifecycle_products(updated_at);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_lifecycle_releases_updated_at ON lifecycle_releases(updated_at);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_lifecycle_package_map_updated_at ON lifecycle_package_map(updated_at);

CREATE TABLE IF NOT EXISTS lifecycle_sync_tombstones (
    id           TEXT        PRIMARY KEY,
    ecosystem    TEXT        NOT NULL,
    name         TEXT        NOT NULL,
    product_slug TEXT        NOT NULL,
    cycle        TEXT        NOT NULL,
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_lifecycle_sync_tombstones_updated_at
    ON lifecycle_sync_tombstones(updated_at);
