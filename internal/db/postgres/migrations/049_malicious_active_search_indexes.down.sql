-- packmon:migration no-transaction
DROP INDEX CONCURRENTLY IF EXISTS idx_malicious_active_severity_search;
DROP INDEX CONCURRENTLY IF EXISTS idx_malicious_active_search_order;
