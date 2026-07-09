-- packmon:migration no-transaction
DROP INDEX CONCURRENTLY IF EXISTS idx_affected_packages_updated_at;

ALTER TABLE affected_packages
    DROP COLUMN IF EXISTS updated_at;
