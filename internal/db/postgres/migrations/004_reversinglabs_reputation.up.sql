-- 004_reversinglabs_reputation.up.sql

CREATE TABLE package_reputation_cache (
    id              SERIAL      PRIMARY KEY,
    ecosystem       TEXT        NOT NULL,
    name            TEXT        NOT NULL,
    version         TEXT        NOT NULL,
    source          TEXT        NOT NULL,
    status          TEXT        NOT NULL CHECK (status IN ('pending', 'malicious', 'removed', 'clean', 'not_found', 'unsupported', 'error')),
    severity        TEXT        NOT NULL DEFAULT 'CRITICAL',
    summary         TEXT        NOT NULL DEFAULT '',
    description     TEXT        NOT NULL DEFAULT '',
    reference_urls  JSONB       NOT NULL DEFAULT '[]',
    evidence        JSONB       NOT NULL DEFAULT '{}',
    last_checked_at TIMESTAMPTZ,
    next_check_at   TIMESTAMPTZ,
    last_error      TEXT        NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(ecosystem, name, version, source)
);

CREATE INDEX idx_reputation_due
    ON package_reputation_cache(source, ecosystem, name, next_check_at)
    WHERE status IN ('pending', 'error', 'malicious', 'removed', 'clean', 'not_found');
