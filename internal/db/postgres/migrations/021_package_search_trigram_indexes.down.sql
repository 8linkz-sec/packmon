-- packmon:migration no-transaction
DROP INDEX CONCURRENTLY IF EXISTS idx_lifecycle_package_map_name_trgm;

DROP INDEX CONCURRENTLY IF EXISTS idx_package_reputation_cache_name_trgm;

DROP INDEX CONCURRENTLY IF EXISTS idx_malicious_findings_name_trgm;

DROP INDEX CONCURRENTLY IF EXISTS idx_affected_packages_name_trgm;
