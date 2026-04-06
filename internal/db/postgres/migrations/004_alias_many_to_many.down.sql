-- 003_alias_many_to_many.down.sql
-- Revert to UNIQUE(alias_id) -- single-vulnerability-per-alias model.
-- WARNING: If duplicate alias_ids exist (same alias linked to multiple
-- vulnerabilities), this migration will fail. Clean duplicates first.

DROP INDEX IF EXISTS idx_vuln_aliases_alias_id;

ALTER TABLE vulnerability_aliases
    DROP CONSTRAINT IF EXISTS vulnerability_aliases_vuln_alias_unique;

-- Re-add the original unique constraint on alias_id alone.
-- This will fail if there are duplicate alias_id values.
ALTER TABLE vulnerability_aliases
    ADD CONSTRAINT vulnerability_aliases_alias_id_key
    UNIQUE (alias_id);
