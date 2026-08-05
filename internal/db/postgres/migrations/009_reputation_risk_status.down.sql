-- 009_reputation_risk_status.down.sql

WITH rollback_rows AS (
    SELECT
        id,
        evidence->'packmon_migration_009' AS marker
    FROM package_reputation_cache
    WHERE status = 'risk'
      AND evidence ? 'packmon_migration_009'
      AND evidence->'packmon_migration_009'->>'previous_status' IN (
          'pending', 'malicious', 'removed', 'clean', 'not_found', 'unsupported', 'error'
      )
)
UPDATE package_reputation_cache AS cache
SET status = rollback_rows.marker->>'previous_status',
    severity = COALESCE(NULLIF(rollback_rows.marker->>'previous_severity', ''), cache.severity),
    summary = COALESCE(rollback_rows.marker->>'previous_summary', cache.summary),
    description = COALESCE(rollback_rows.marker->>'previous_description', cache.description),
    evidence = CASE
        WHEN rollback_rows.marker ? 'previous_assessment'
             AND jsonb_typeof(rollback_rows.marker->'previous_assessment') <> 'null'
            THEN jsonb_set(
                COALESCE(cache.evidence, '{}'::jsonb) - 'packmon_migration_009',
                '{assessment}',
                rollback_rows.marker->'previous_assessment',
                true
            )
        ELSE COALESCE(cache.evidence, '{}'::jsonb) - 'packmon_migration_009' - 'assessment'
    END,
    updated_at = NOW()
FROM rollback_rows
WHERE cache.id = rollback_rows.id;

ALTER TABLE package_reputation_cache
    DROP CONSTRAINT IF EXISTS package_reputation_cache_status_check;

-- Preserve legitimate risk rows inserted after 009; this rollback only reverses
-- rows marked as converted by the 009 up migration.
ALTER TABLE package_reputation_cache
    ADD CONSTRAINT package_reputation_cache_status_check
    CHECK (status IN ('pending', 'malicious', 'removed', 'risk', 'clean', 'not_found', 'unsupported', 'error'));

DROP INDEX IF EXISTS idx_reputation_due;

CREATE INDEX idx_reputation_due
    ON package_reputation_cache(source, ecosystem, name, next_check_at)
    WHERE status IN ('pending', 'error', 'malicious', 'removed', 'clean', 'not_found');
