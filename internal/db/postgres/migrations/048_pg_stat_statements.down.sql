-- pg_stat_statements may be owned and shared by the database operator. A
-- Packmon rollback must not remove that cluster-wide observability facility.
SELECT 1;
