-- 003_alias_many_to_many.up.sql
-- Fix ARCH-H3: Allow the same alias_id to be linked to multiple
-- vulnerabilities. The previous UNIQUE(alias_id) constraint caused
-- ON CONFLICT ... DO UPDATE to silently move aliases between
-- vulnerabilities, potentially orphaning the original.
--
-- New constraint: UNIQUE(vulnerability_id, alias_id) -- composite key.
-- This means a given (vuln, alias) pair is unique but the same alias
-- can appear under different vulnerability IDs.

-- Drop the old unique constraint on alias_id alone.
ALTER TABLE vulnerability_aliases
    DROP CONSTRAINT IF EXISTS vulnerability_aliases_alias_id_key;

-- Add the new composite unique constraint.
ALTER TABLE vulnerability_aliases
    ADD CONSTRAINT vulnerability_aliases_vuln_alias_unique
    UNIQUE (vulnerability_id, alias_id);

-- Add an index on alias_id for lookup queries (no longer unique).
CREATE INDEX IF NOT EXISTS idx_vuln_aliases_alias_id
    ON vulnerability_aliases(alias_id);
