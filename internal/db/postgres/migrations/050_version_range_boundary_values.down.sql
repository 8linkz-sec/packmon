-- 050_version_range_boundary_values.down.sql
-- Restore the packmon_jsonb_version_ranges_valid definition from 032 first
-- (the original values below only pass the older, more lenient check), then
-- put back the rows recorded in packmon_m050_version_range_repairs that are
-- unchanged since the repair. 050 up sets updated_at = NOW() on every repaired
-- row in the same transaction in which repaired_at defaults to NOW(), and no
-- trigger touches updated_at, so updated_at = repaired_at means "not written
-- since". Any later write (a feed import, a re-tombstone, an admin delete or
-- re-entry) moves updated_at, and such a row keeps its current state even when
-- its value happens to look repaired ([] ranges, NULL ranges, tombstoned).

CREATE OR REPLACE FUNCTION packmon_jsonb_version_ranges_valid(value JSONB)
RETURNS BOOLEAN
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
    range_item JSONB;
    event_item JSONB;
BEGIN
    IF value IS NULL OR jsonb_typeof(value) <> 'array' THEN
        RETURN FALSE;
    END IF;

    FOR range_item IN SELECT jsonb_array_elements(value)
    LOOP
        IF jsonb_typeof(range_item) <> 'object'
           OR jsonb_typeof(range_item->'events') <> 'array'
           OR jsonb_array_length(range_item->'events') = 0 THEN
            RETURN FALSE;
        END IF;

        FOR event_item IN SELECT jsonb_array_elements(range_item->'events')
        LOOP
            IF jsonb_typeof(event_item) <> 'object'
               OR NOT (
                    event_item ? 'introduced'
                    OR event_item ? 'fixed'
                    OR event_item ? 'last_affected'
                    OR event_item ? 'limit'
               ) THEN
                RETURN FALSE;
            END IF;
        END LOOP;
    END LOOP;

    RETURN TRUE;
END;
$$;

DO $$
BEGIN
    IF to_regclass('public.packmon_m050_version_range_repairs') IS NULL THEN
        RETURN;
    END IF;

    UPDATE affected_packages ap
    SET version_ranges = r.original_version_ranges,
        updated_at = NOW()
    FROM packmon_m050_version_range_repairs r
    WHERE r.table_name = 'affected_packages'
      AND r.row_id = ap.id::text
      AND ap.updated_at = r.repaired_at
      AND ap.version_ranges = '[]'::jsonb;

    UPDATE malicious_findings mf
    SET version_ranges = r.original_version_ranges,
        removed_at = CASE WHEN r.action = 'quarantined' THEN r.original_removed_at ELSE mf.removed_at END,
        updated_at = NOW()
    FROM packmon_m050_version_range_repairs r
    WHERE r.table_name = 'malicious_findings'
      AND r.row_id = mf.id
      AND mf.updated_at = r.repaired_at
      AND mf.version_ranges IS NULL
      AND (r.action <> 'quarantined' OR mf.removed_at IS NOT NULL);
END $$;

DROP TABLE IF EXISTS packmon_m050_version_range_repairs;
