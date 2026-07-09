-- packmon:migration no-transaction
ALTER TABLE affected_packages
    ADD COLUMN updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_affected_packages_updated_at ON affected_packages(updated_at);
