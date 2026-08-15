-- Restore the pre-047 ecosystem CHECK constraints (without the chocolatey
-- ecosystem). Rows carrying that value cannot survive the rollback: the
-- ecosystem is inventory-only and never persisted by the scan path, so none
-- are expected, but any that exist (for example from a feed import) are
-- removed first so the restored constraints VALIDATE cleanly.

DELETE FROM affected_packages WHERE ecosystem = 'chocolatey';
DELETE FROM malicious_findings WHERE ecosystem = 'chocolatey';
DELETE FROM package_reputation_cache WHERE ecosystem = 'chocolatey';
DELETE FROM package_check_status WHERE ecosystem = 'chocolatey';
DELETE FROM refresh_queue WHERE ecosystem = 'chocolatey';
DELETE FROM lifecycle_package_map WHERE ecosystem = 'chocolatey';
DELETE FROM lifecycle_sync_tombstones WHERE ecosystem = 'chocolatey';

ALTER TABLE affected_packages
    DROP CONSTRAINT IF EXISTS affected_packages_ecosystem_check;
ALTER TABLE affected_packages
    ADD CONSTRAINT affected_packages_ecosystem_check
    CHECK (ecosystem IN (
                'npm', 'pypi', 'go', 'maven', 'cargo', 'nuget', 'composer', 'gem',
                'pub', 'cocoapods', 'swiftpm', 'hex', 'cran', 'actions', 'docker'
            )) NOT VALID;

ALTER TABLE malicious_findings
    DROP CONSTRAINT IF EXISTS malicious_findings_ecosystem_check;
ALTER TABLE malicious_findings
    ADD CONSTRAINT malicious_findings_ecosystem_check
    CHECK (ecosystem IN (
                'npm', 'pypi', 'go', 'maven', 'cargo', 'nuget', 'composer', 'gem',
                'pub', 'cocoapods', 'swiftpm', 'hex', 'cran', 'actions', 'docker'
            )) NOT VALID;

ALTER TABLE package_reputation_cache
    DROP CONSTRAINT IF EXISTS package_reputation_cache_ecosystem_check;
ALTER TABLE package_reputation_cache
    ADD CONSTRAINT package_reputation_cache_ecosystem_check
    CHECK (ecosystem IN (
                'npm', 'pypi', 'go', 'maven', 'cargo', 'nuget', 'composer', 'gem',
                'pub', 'cocoapods', 'swiftpm', 'hex', 'cran', 'actions', 'docker'
            )) NOT VALID;

ALTER TABLE package_check_status
    DROP CONSTRAINT IF EXISTS package_check_status_ecosystem_check;
ALTER TABLE package_check_status
    ADD CONSTRAINT package_check_status_ecosystem_check
    CHECK (ecosystem IN (
                'npm', 'pypi', 'go', 'maven', 'cargo', 'nuget', 'composer', 'gem',
                'pub', 'cocoapods', 'swiftpm', 'hex', 'cran', 'actions', 'docker'
            )) NOT VALID;

ALTER TABLE refresh_queue
    DROP CONSTRAINT IF EXISTS refresh_queue_ecosystem_check;
ALTER TABLE refresh_queue
    ADD CONSTRAINT refresh_queue_ecosystem_check
    CHECK (ecosystem IN (
                'npm', 'pypi', 'go', 'maven', 'cargo', 'nuget', 'composer', 'gem',
                'pub', 'cocoapods', 'swiftpm', 'hex', 'cran', 'actions', 'docker'
            )) NOT VALID;

ALTER TABLE lifecycle_package_map
    DROP CONSTRAINT IF EXISTS lifecycle_package_map_ecosystem_check;
ALTER TABLE lifecycle_package_map
    ADD CONSTRAINT lifecycle_package_map_ecosystem_check
    CHECK (ecosystem IN (
                'npm', 'pypi', 'go', 'maven', 'cargo', 'nuget', 'composer', 'gem',
                'pub', 'cocoapods', 'swiftpm', 'hex', 'cran', 'actions', 'docker'
            )) NOT VALID;

ALTER TABLE lifecycle_sync_tombstones
    DROP CONSTRAINT IF EXISTS lifecycle_sync_tombstones_ecosystem_check;
ALTER TABLE lifecycle_sync_tombstones
    ADD CONSTRAINT lifecycle_sync_tombstones_ecosystem_check
    CHECK (ecosystem IN (
                'npm', 'pypi', 'go', 'maven', 'cargo', 'nuget', 'composer', 'gem',
                'pub', 'cocoapods', 'swiftpm', 'hex', 'cran', 'actions', 'docker'
            )) NOT VALID;

ALTER TABLE affected_packages VALIDATE CONSTRAINT affected_packages_ecosystem_check;
ALTER TABLE malicious_findings VALIDATE CONSTRAINT malicious_findings_ecosystem_check;
ALTER TABLE package_reputation_cache VALIDATE CONSTRAINT package_reputation_cache_ecosystem_check;
ALTER TABLE package_check_status VALIDATE CONSTRAINT package_check_status_ecosystem_check;
ALTER TABLE refresh_queue VALIDATE CONSTRAINT refresh_queue_ecosystem_check;
ALTER TABLE lifecycle_package_map VALIDATE CONSTRAINT lifecycle_package_map_ecosystem_check;
ALTER TABLE lifecycle_sync_tombstones VALIDATE CONSTRAINT lifecycle_sync_tombstones_ecosystem_check;
