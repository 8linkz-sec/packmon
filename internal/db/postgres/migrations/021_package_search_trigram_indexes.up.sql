CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE INDEX IF NOT EXISTS idx_affected_packages_name_trgm
    ON affected_packages USING gin (name gin_trgm_ops);

CREATE INDEX IF NOT EXISTS idx_malicious_findings_name_trgm
    ON malicious_findings USING gin (name gin_trgm_ops)
    WHERE removed_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_package_reputation_cache_name_trgm
    ON package_reputation_cache USING gin (name gin_trgm_ops);

CREATE INDEX IF NOT EXISTS idx_lifecycle_package_map_name_trgm
    ON lifecycle_package_map USING gin (name gin_trgm_ops);
