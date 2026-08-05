ALTER TABLE malicious_findings
    DROP CONSTRAINT IF EXISTS malicious_findings_versions_array_check;

ALTER TABLE malicious_findings
    DROP CONSTRAINT IF EXISTS malicious_findings_version_ranges_array_check;

ALTER TABLE affected_packages
    DROP CONSTRAINT IF EXISTS affected_packages_versions_affected_array_check;

ALTER TABLE affected_packages
    DROP CONSTRAINT IF EXISTS affected_packages_version_ranges_array_check;

DROP FUNCTION IF EXISTS packmon_jsonb_version_ranges_valid(JSONB);
DROP FUNCTION IF EXISTS packmon_jsonb_string_array_valid(JSONB);
