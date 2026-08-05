-- 009_reputation_risk_status.up.sql

ALTER TABLE package_reputation_cache
    DROP CONSTRAINT IF EXISTS package_reputation_cache_status_check;

ALTER TABLE package_reputation_cache
    ADD CONSTRAINT package_reputation_cache_status_check
    CHECK (status IN ('pending', 'malicious', 'removed', 'risk', 'clean', 'not_found', 'unsupported', 'error'));

UPDATE package_reputation_cache
SET status = 'risk',
    severity = 'HIGH',
    summary = 'ReversingLabs: malware incident history',
    evidence = jsonb_set(
        COALESCE(evidence, '{}'::jsonb) ||
        jsonb_build_object(
            'packmon_migration_009',
            jsonb_build_object(
                'previous_status', status,
                'previous_severity', severity,
                'previous_summary', summary,
                'previous_description', description,
                'previous_assessment', COALESCE(evidence->'assessment', 'null'::jsonb)
            )
        ),
        '{assessment}',
        '"risk"'::jsonb,
        true
    ),
    updated_at = NOW()
WHERE source = 'reversinglabs'
  AND status = 'malicious'
  AND jsonb_typeof(evidence->'signals') = 'array'
  AND evidence->'signals' ? 'incidents.type.malware'
  AND NOT (
      evidence->'signals' ?| ARRAY[
          'package.all_malicious',
          'assessments.malware.status',
          'classifications.status',
          'dependencies.classification.status'
      ]
  );

DROP INDEX IF EXISTS idx_reputation_due;

CREATE INDEX idx_reputation_due
    ON package_reputation_cache(source, ecosystem, name, next_check_at)
    WHERE status IN ('pending', 'error', 'malicious', 'removed', 'risk', 'clean', 'not_found');
