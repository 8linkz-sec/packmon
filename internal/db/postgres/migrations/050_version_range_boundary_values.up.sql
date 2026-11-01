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
-- Existing rows the stricter check rejects are repaired before the
-- constraints are re-validated, and every repaired row is recorded in
-- packmon_m050_version_range_repairs (original value included) so operators
-- can list them and the down migration can restore them:
-- - affected_packages.version_ranges falls back to [] (as in 032; fail-safe,
--   every version is treated as affected until the next feed sync rewrites
--   the row);
-- - malicious_findings with nonempty exact versions get version_ranges NULL,
--   so only those exact versions keep matching;
-- - active malicious_findings without exact versions are quarantined with the
--   normal tombstone (removed_at, updated_at), because NULL ranges plus NULL
--   versions would turn them into all-version blocking findings. Delta sync
--   exports the tombstone, so local clients drop them too; the next feed
--   import that contains the finding resurrects it, manual advisories must be
--   re-entered.
-- The per-table counts are emitted as a NOTICE.

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

CREATE TABLE packmon_m050_version_range_repairs (
    table_name              TEXT        NOT NULL,
    row_id                  TEXT        NOT NULL,
    action                  TEXT        NOT NULL,
    original_version_ranges JSONB       NOT NULL,
    original_removed_at     TIMESTAMPTZ,
    repaired_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (table_name, row_id),
    CONSTRAINT packmon_m050_version_range_repairs_action_check CHECK (
        (table_name = 'affected_packages' AND action = 'ranges_reset')
        OR (table_name = 'malicious_findings' AND action IN ('ranges_cleared', 'quarantined'))
    )
);

DO $$
DECLARE
    ranges_reset   BIGINT;
    ranges_cleared BIGINT;
    quarantined    BIGINT;
BEGIN
    INSERT INTO packmon_m050_version_range_repairs (table_name, row_id, action, original_version_ranges)
    SELECT 'affected_packages', id::text, 'ranges_reset', version_ranges
    FROM affected_packages
    WHERE NOT packmon_jsonb_version_ranges_valid(version_ranges);

    UPDATE affected_packages ap
    SET version_ranges = '[]'::jsonb,
        updated_at = NOW()
    FROM packmon_m050_version_range_repairs r
    WHERE r.table_name = 'affected_packages'
      AND r.row_id = ap.id::text;
    GET DIAGNOSTICS ranges_reset = ROW_COUNT;

    -- Nested CASE instead of AND: jsonb_array_length raises on a non-array,
    -- and SQL does not guarantee the evaluation order of AND.
    INSERT INTO packmon_m050_version_range_repairs (table_name, row_id, action, original_version_ranges, original_removed_at)
    SELECT
        'malicious_findings',
        id,
        CASE
            WHEN removed_at IS NULL
             AND NOT CASE WHEN jsonb_typeof(versions) = 'array' THEN jsonb_array_length(versions) > 0 ELSE FALSE END
            THEN 'quarantined'
            ELSE 'ranges_cleared'
        END,
        version_ranges,
        removed_at
    FROM malicious_findings
    WHERE version_ranges IS NOT NULL
      AND NOT packmon_jsonb_version_ranges_valid(version_ranges);

    UPDATE malicious_findings mf
    SET version_ranges = NULL,
        removed_at = NOW(),
        updated_at = NOW()
    FROM packmon_m050_version_range_repairs r
    WHERE r.table_name = 'malicious_findings'
      AND r.action = 'quarantined'
      AND r.row_id = mf.id;
    GET DIAGNOSTICS quarantined = ROW_COUNT;

    UPDATE malicious_findings mf
    SET version_ranges = NULL,
        updated_at = NOW()
    FROM packmon_m050_version_range_repairs r
    WHERE r.table_name = 'malicious_findings'
      AND r.action = 'ranges_cleared'
      AND r.row_id = mf.id;
    GET DIAGNOSTICS ranges_cleared = ROW_COUNT;

    RAISE NOTICE 'migration 050: affected_packages version_ranges reset to []: %; malicious_findings version_ranges cleared (exact versions apply): %; malicious_findings quarantined (removed_at set): %; details in packmon_m050_version_range_repairs',
        ranges_reset, ranges_cleared, quarantined;
END $$;

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
