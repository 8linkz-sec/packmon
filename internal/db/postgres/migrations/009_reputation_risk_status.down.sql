-- 009_reputation_risk_status.down.sql

UPDATE package_reputation_cache
SET status = 'clean',
    severity = 'CRITICAL',
    summary = 'ReversingLabs: no malicious signals',
    description = '',
    evidence = jsonb_set(COALESCE(evidence, '{}'::jsonb), '{assessment}', '"clean"'::jsonb, true),
    updated_at = NOW()
WHERE status = 'risk';

ALTER TABLE package_reputation_cache
    DROP CONSTRAINT IF EXISTS package_reputation_cache_status_check;

ALTER TABLE package_reputation_cache
    ADD CONSTRAINT package_reputation_cache_status_check
    CHECK (status IN ('pending', 'malicious', 'removed', 'clean', 'not_found', 'unsupported', 'error'));

DROP INDEX IF EXISTS idx_reputation_due;

CREATE INDEX idx_reputation_due
    ON package_reputation_cache(source, ecosystem, name, next_check_at)
    WHERE status IN ('pending', 'error', 'malicious', 'removed', 'clean', 'not_found');
