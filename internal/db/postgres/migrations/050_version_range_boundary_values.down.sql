-- 050_version_range_boundary_values.down.sql
-- Restore the packmon_jsonb_version_ranges_valid definition from 032 first
-- (the original values below only pass the older, more lenient check), then
-- put back the rows recorded in packmon_m050_version_range_repairs that still
-- hold their repaired value. A row a feed import rewrote after 050 keeps the
-- newer value, and a quarantined finding is reactivated only while it is still
-- tombstoned with NULL ranges.

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
      AND ap.version_ranges = '[]'::jsonb;

    UPDATE malicious_findings mf
    SET version_ranges = r.original_version_ranges,
        removed_at = CASE WHEN r.action = 'quarantined' THEN r.original_removed_at ELSE mf.removed_at END,
        updated_at = NOW()
    FROM packmon_m050_version_range_repairs r
    WHERE r.table_name = 'malicious_findings'
      AND r.row_id = mf.id
      AND mf.version_ranges IS NULL
      AND (r.action <> 'quarantined' OR mf.removed_at IS NOT NULL);
END $$;

DROP TABLE IF EXISTS packmon_m050_version_range_repairs;
