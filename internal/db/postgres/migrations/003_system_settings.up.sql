-- 003_system_settings.up.sql
-- Persist admin-managed server-level settings.

CREATE TABLE system_settings (
    id                    SMALLINT    PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    block_threshold       TEXT        NOT NULL DEFAULT 'CRITICAL'
        CHECK (block_threshold IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE')),
    rate_limit_per_minute INTEGER     NOT NULL DEFAULT 60 CHECK (rate_limit_per_minute > 0),
    rate_limit_burst      INTEGER     NOT NULL DEFAULT 60 CHECK (rate_limit_burst > 0),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
