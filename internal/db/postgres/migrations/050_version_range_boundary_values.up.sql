-- 050_version_range_boundary_values.up.sql
-- Tighten packmon_jsonb_version_ranges_valid to what the store validates
-- before every write (validateStoredVersionRangesJSON). The earlier function
-- (001, 032) only tested that a boundary key exists, so it accepted a range
-- without an events key ([{}]: the NULL type check skipped the test and the
-- empty loop returned TRUE) and events whose boundaries were null, numeric or
-- blank. Now every range must be an object with a nonempty events array, every
-- event must be an object, introduced/fixed/last_affected/limit must be a
-- string or null when present, and at least one of them must be a nonblank
-- string. [] and other keys (type, repo, database_specific) stay accepted.
--
-- Existing rows the stricter check rejects are repaired the same way 032 did:
-- affected_packages.version_ranges falls back to [] (fail-safe: every version
-- is treated as affected until the next feed sync rewrites the row) and
-- malicious_findings.version_ranges to NULL. The repair is one-way; the down
-- migration restores only the previous function.

CREATE OR REPLACE FUNCTION packmon_jsonb_version_ranges_valid(value JSONB)
RETURNS BOOLEAN
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
    range_item JSONB;
    event_item JSONB;
    boundary_key TEXT;
    boundary_value JSONB;
    has_boundary BOOLEAN;
BEGIN
    IF value IS NULL OR jsonb_typeof(value) <> 'array' THEN
        RETURN FALSE;
    END IF;

    FOR range_item IN SELECT jsonb_array_elements(value)
    LOOP
        -- Separate checks: SQL does not guarantee the evaluation order of OR
        -- (jsonb_array_length raises on a non-array), and a missing key yields
        -- SQL NULL, which must reject instead of skipping the test.
        IF jsonb_typeof(range_item) IS DISTINCT FROM 'object' THEN
            RETURN FALSE;
        END IF;
        IF jsonb_typeof(range_item->'events') IS DISTINCT FROM 'array' THEN
            RETURN FALSE;
        END IF;
        IF jsonb_array_length(range_item->'events') = 0 THEN
            RETURN FALSE;
        END IF;

        FOR event_item IN SELECT jsonb_array_elements(range_item->'events')
        LOOP
            IF jsonb_typeof(event_item) IS DISTINCT FROM 'object' THEN
                RETURN FALSE;
            END IF;

            has_boundary := FALSE;
            FOREACH boundary_key IN ARRAY ARRAY['introduced', 'fixed', 'last_affected', 'limit']
            LOOP
                boundary_value := event_item->boundary_key;
                CONTINUE WHEN boundary_value IS NULL OR jsonb_typeof(boundary_value) = 'null';
                IF jsonb_typeof(boundary_value) <> 'string' THEN
                    RETURN FALSE;
                END IF;
                IF btrim(boundary_value #>> '{}', E' \t\n\r\f\x0B') <> '' THEN
                    has_boundary := TRUE;
                END IF;
            END LOOP;

            IF NOT has_boundary THEN
                RETURN FALSE;
            END IF;
        END LOOP;
    END LOOP;

    RETURN TRUE;
END;
$$;

UPDATE affected_packages
SET version_ranges = '[]'::jsonb,
    updated_at = NOW()
WHERE NOT packmon_jsonb_version_ranges_valid(version_ranges);

UPDATE malicious_findings
SET version_ranges = NULL,
    updated_at = NOW()
WHERE version_ranges IS NOT NULL
  AND NOT packmon_jsonb_version_ranges_valid(version_ranges);

-- Replacing a function does not re-check rows, so re-add both constraints and
-- validate them against the stricter function.
ALTER TABLE affected_packages
    DROP CONSTRAINT IF EXISTS affected_packages_version_ranges_array_check;

ALTER TABLE malicious_findings
    DROP CONSTRAINT IF EXISTS malicious_findings_version_ranges_array_check;

ALTER TABLE affected_packages
    ADD CONSTRAINT affected_packages_version_ranges_array_check
    CHECK (packmon_jsonb_version_ranges_valid(version_ranges)) NOT VALID;

ALTER TABLE malicious_findings
    ADD CONSTRAINT malicious_findings_version_ranges_array_check
    CHECK (version_ranges IS NULL OR packmon_jsonb_version_ranges_valid(version_ranges)) NOT VALID;

ALTER TABLE affected_packages VALIDATE CONSTRAINT affected_packages_version_ranges_array_check;
ALTER TABLE malicious_findings VALIDATE CONSTRAINT malicious_findings_version_ranges_array_check;
