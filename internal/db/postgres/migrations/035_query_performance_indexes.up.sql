CREATE INDEX IF NOT EXISTS idx_lifecycle_releases_eol_status_date
    ON lifecycle_releases(product_slug, eol_from)
    WHERE is_eol OR eol_from IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_lifecycle_releases_eoas_status_date
    ON lifecycle_releases(product_slug, eoas_from)
    WHERE is_eoas OR eoas_from IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_malicious_active_source_updated_at
    ON malicious_findings(source, updated_at DESC, created_at DESC, id DESC)
    WHERE removed_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_malicious_active_updated_at
    ON malicious_findings(updated_at DESC, created_at DESC, id DESC)
    WHERE removed_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_queue_oldest_active_source_requested_at
    ON refresh_queue(source, requested_at)
    WHERE source <> '' AND status IN ('pending', 'processing');

CREATE INDEX IF NOT EXISTS idx_reputation_prune_source_updated_at
    ON package_reputation_cache(source, updated_at)
    WHERE status IN ('clean', 'not_found', 'unsupported', 'error');
