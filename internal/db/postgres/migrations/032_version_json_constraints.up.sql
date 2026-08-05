CREATE OR REPLACE FUNCTION packmon_jsonb_string_array_valid(value JSONB)
RETURNS BOOLEAN
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
    item JSONB;
BEGIN
    IF value IS NULL OR jsonb_typeof(value) <> 'array' THEN
        RETURN FALSE;
    END IF;

    FOR item IN SELECT jsonb_array_elements(value)
    LOOP
        IF jsonb_typeof(item) <> 'string' THEN
            RETURN FALSE;
        END IF;
    END LOOP;

    RETURN TRUE;
END;
$$;

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

UPDATE affected_packages
SET version_ranges = '[]'::jsonb,
    updated_at = NOW()
WHERE NOT packmon_jsonb_version_ranges_valid(version_ranges);

UPDATE affected_packages
SET versions_affected = '[]'::jsonb,
    updated_at = NOW()
WHERE NOT packmon_jsonb_string_array_valid(versions_affected);

UPDATE malicious_findings
SET version_ranges = NULL,
    updated_at = NOW()
WHERE version_ranges IS NOT NULL
  AND NOT packmon_jsonb_version_ranges_valid(version_ranges);

UPDATE malicious_findings
SET versions = NULL,
    updated_at = NOW()
WHERE versions IS NOT NULL
  AND NOT packmon_jsonb_string_array_valid(versions);

ALTER TABLE affected_packages
    DROP CONSTRAINT IF EXISTS affected_packages_version_ranges_array_check;

ALTER TABLE affected_packages
    DROP CONSTRAINT IF EXISTS affected_packages_versions_affected_array_check;

ALTER TABLE malicious_findings
    DROP CONSTRAINT IF EXISTS malicious_findings_version_ranges_array_check;

ALTER TABLE malicious_findings
    DROP CONSTRAINT IF EXISTS malicious_findings_versions_array_check;

ALTER TABLE affected_packages
    ADD CONSTRAINT affected_packages_version_ranges_array_check
    CHECK (packmon_jsonb_version_ranges_valid(version_ranges)) NOT VALID;

ALTER TABLE affected_packages
    ADD CONSTRAINT affected_packages_versions_affected_array_check
    CHECK (packmon_jsonb_string_array_valid(versions_affected)) NOT VALID;

ALTER TABLE malicious_findings
    ADD CONSTRAINT malicious_findings_version_ranges_array_check
    CHECK (version_ranges IS NULL OR packmon_jsonb_version_ranges_valid(version_ranges)) NOT VALID;

ALTER TABLE malicious_findings
    ADD CONSTRAINT malicious_findings_versions_array_check
    CHECK (versions IS NULL OR packmon_jsonb_string_array_valid(versions)) NOT VALID;

ALTER TABLE affected_packages VALIDATE CONSTRAINT affected_packages_version_ranges_array_check;
ALTER TABLE affected_packages VALIDATE CONSTRAINT affected_packages_versions_affected_array_check;
ALTER TABLE malicious_findings VALIDATE CONSTRAINT malicious_findings_version_ranges_array_check;
ALTER TABLE malicious_findings VALIDATE CONSTRAINT malicious_findings_versions_array_check;
