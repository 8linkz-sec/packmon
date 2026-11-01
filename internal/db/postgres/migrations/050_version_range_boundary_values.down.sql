-- 050_version_range_boundary_values.down.sql
-- Restore the packmon_jsonb_version_ranges_valid definition from 032. The
-- constraints keep using the function, which is more lenient again, so they
-- stay valid. Rows the up migration repaired keep their repaired value.

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
