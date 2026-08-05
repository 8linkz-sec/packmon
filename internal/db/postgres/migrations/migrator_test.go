package migrations

import (
	"context"
	"database/sql"
	"fmt"
	iofs "io/fs"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func TestExpectedVersionMatchesHighestEmbeddedMigration(t *testing.T) {
	t.Parallel()

	highest := 0
	seenUp := map[int]bool{}
	seenDown := map[int]bool{}
	err := iofs.WalkDir(fs, ".", func(path string, d iofs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || filepath.Ext(path) != ".sql" {
			return nil
		}
		base := filepath.Base(path)
		if len(base) < 3 {
			return fmt.Errorf("migration filename %q is too short", base)
		}
		version, err := strconv.Atoi(base[:3])
		if err != nil {
			return fmt.Errorf("migration filename %q does not start with a numeric version: %w", base, err)
		}
		if version > highest {
			highest = version
		}
		switch {
		case strings.HasSuffix(base, ".up.sql"):
			seenUp[version] = true
		case strings.HasSuffix(base, ".down.sql"):
			seenDown[version] = true
		default:
			return fmt.Errorf("migration filename %q must end with .up.sql or .down.sql", base)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk embedded migrations: %v", err)
	}

	if highest != ExpectedVersion {
		t.Fatalf("highest embedded migration = %d, ExpectedVersion = %d", highest, ExpectedVersion)
	}
	for version := 1; version <= highest; version++ {
		if !seenUp[version] || !seenDown[version] {
			t.Fatalf("migration %03d has up=%v down=%v, want both", version, seenUp[version], seenDown[version])
		}
	}
}

func TestPostInitialDownMigrationsDoNotDropBaselineSchemaObjects(t *testing.T) {
	t.Parallel()

	initial, err := fs.ReadFile("001_initial.up.sql")
	if err != nil {
		t.Fatalf("read initial schema: %v", err)
	}
	initialSQL := string(initial)
	baselineIndexes := migrationCreateIndexNames(initialSQL)
	baselineTables := migrationCreateTableNames(initialSQL)
	baselineColumns := migrationTableColumns(initialSQL)

	downs, err := EmbeddedMigrations(MigrationDirectionDown)
	if err != nil {
		t.Fatalf("read embedded down migrations: %v", err)
	}
	var conflicts []string
	for _, migration := range downs {
		if migration.Version == 1 {
			continue
		}
		up, err := ReadEmbeddedMigration(migration.Version, MigrationDirectionUp)
		if err != nil {
			t.Fatalf("read matching up migration for %s: %v", migration.Name, err)
		}
		idempotentIndexes := migrationCreateIndexIfNotExistsNames(up.SQL)
		idempotentTables := migrationCreateTableIfNotExistsNames(up.SQL)
		idempotentColumns := migrationAddColumnIfNotExists(up.SQL)
		for _, indexName := range migrationDropIndexNames(migration.SQL) {
			if baselineIndexes[indexName] && idempotentIndexes[indexName] {
				conflicts = append(conflicts, fmt.Sprintf("%s drops baseline-owned index %s", migration.Name, indexName))
			}
		}
		for _, tableName := range migrationDropTableNames(migration.SQL) {
			if baselineTables[tableName] && idempotentTables[tableName] {
				conflicts = append(conflicts, fmt.Sprintf("%s drops baseline-owned table %s", migration.Name, tableName))
			}
		}
		for tableName, columnNames := range migrationDropColumns(migration.SQL) {
			for columnName := range columnNames {
				if baselineColumns[tableName][columnName] && idempotentColumns[tableName][columnName] {
					conflicts = append(conflicts, fmt.Sprintf("%s drops baseline-owned column %s.%s", migration.Name, tableName, columnName))
				}
			}
		}
	}
	if len(conflicts) > 0 {
		t.Fatalf("post-initial down migrations must not drop baseline schema objects:\n%s", strings.Join(conflicts, "\n"))
	}
}

func TestSystemSettingsRetentionMigrationDefinesAdminConfigurableMetadataRetention(t *testing.T) {
	t.Parallel()

	up, err := fs.ReadFile("044_system_settings_metadata_retention.up.sql")
	if err != nil {
		t.Fatalf("read metadata retention migration: %v", err)
	}
	upSQL := string(up)
	for _, want := range []string{
		"ALTER TABLE system_settings",
		"ADD COLUMN IF NOT EXISTS scan_log_retention_seconds BIGINT NOT NULL DEFAULT 2592000",
		"ADD COLUMN IF NOT EXISTS admin_audit_retention_seconds BIGINT NOT NULL DEFAULT 2592000",
		"system_settings_scan_log_retention_nonnegative_check",
		"system_settings_admin_audit_retention_nonnegative_check",
	} {
		if !strings.Contains(upSQL, want) {
			t.Fatalf("metadata retention migration missing %q:\n%s", want, upSQL)
		}
	}

	down, err := fs.ReadFile("044_system_settings_metadata_retention.down.sql")
	if err != nil {
		t.Fatalf("read metadata retention rollback: %v", err)
	}
	downSQL := string(down)
	for _, want := range []string{
		"DROP CONSTRAINT IF EXISTS system_settings_scan_log_retention_nonnegative_check",
		"DROP CONSTRAINT IF EXISTS system_settings_admin_audit_retention_nonnegative_check",
		"DROP COLUMN IF EXISTS scan_log_retention_seconds",
		"DROP COLUMN IF EXISTS admin_audit_retention_seconds",
	} {
		if !strings.Contains(downSQL, want) {
			t.Fatalf("metadata retention rollback missing %q:\n%s", want, downSQL)
		}
	}
}

func TestScanLogAPIKeyIdentityMigrationFilesExist(t *testing.T) {
	t.Parallel()

	for _, name := range []string{
		"012_scan_log_api_key_identity.up.sql",
		"012_scan_log_api_key_identity.down.sql",
	} {
		data, err := fs.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if strings.TrimSpace(string(data)) == "" {
			t.Fatalf("%s is empty", name)
		}
	}
}

func TestAdminAuditCorrelationIDMigrationDefinesColumn(t *testing.T) {
	t.Parallel()

	up, err := fs.ReadFile("036_admin_audit_correlation_id.up.sql")
	if err != nil {
		t.Fatalf("read up migration: %v", err)
	}
	upSQL := string(up)
	for _, want := range []string{
		"ALTER TABLE admin_audit_log",
		"ADD COLUMN IF NOT EXISTS correlation_id TEXT NOT NULL DEFAULT '';",
		"CREATE INDEX IF NOT EXISTS idx_admin_audit_correlation_id",
		"ON admin_audit_log(correlation_id)",
		"WHERE correlation_id <> '';",
	} {
		if !strings.Contains(upSQL, want) {
			t.Fatalf("admin audit correlation up migration missing %q:\n%s", want, upSQL)
		}
	}

	down, err := fs.ReadFile("036_admin_audit_correlation_id.down.sql")
	if err != nil {
		t.Fatalf("read down migration: %v", err)
	}
	downSQL := string(down)
	for _, forbidden := range []string{
		"DROP INDEX IF EXISTS idx_admin_audit_correlation_id;",
		"ALTER TABLE admin_audit_log",
		"DROP COLUMN IF EXISTS correlation_id;",
	} {
		if strings.Contains(downSQL, forbidden) {
			t.Fatalf("admin audit correlation down migration drops baseline-owned object %q:\n%s", forbidden, downSQL)
		}
	}

	initial, err := fs.ReadFile("001_initial.up.sql")
	if err != nil {
		t.Fatalf("read initial schema: %v", err)
	}
	initialSQL := string(initial)
	for _, want := range []string{
		"correlation_id TEXT NOT NULL DEFAULT ''",
		"CREATE INDEX idx_admin_audit_correlation_id",
		"ON admin_audit_log(correlation_id)",
		"WHERE correlation_id <> '';",
	} {
		if !strings.Contains(initialSQL, want) {
			t.Fatalf("initial schema missing admin audit correlation marker %q", want)
		}
	}
}

func TestQueuePausedDedupMigrationReconcilesExistingDuplicates(t *testing.T) {
	t.Parallel()

	up, err := fs.ReadFile("002_queue_paused_dedup.up.sql")
	if err != nil {
		t.Fatalf("read up migration: %v", err)
	}
	upSQL := string(up)
	for _, want := range []string{
		"ROW_NUMBER() OVER",
		"PARTITION BY ecosystem, name, source",
		"WHEN 'processing' THEN 0",
		"WHEN 'pending' THEN 1",
		"WHEN 'paused' THEN 2",
		"DELETE FROM refresh_queue q",
		"ranked.duplicate_rank > 1",
		"WHERE status IN ('pending', 'processing', 'paused')",
		"CREATE UNIQUE INDEX idx_queue_dedup",
	} {
		if !strings.Contains(upSQL, want) {
			t.Fatalf("queue paused dedup migration missing %q:\n%s", want, upSQL)
		}
	}
}

func TestRefreshQueueListingIndexMigrationDefinesExpectedIndexes(t *testing.T) {
	t.Parallel()

	up, err := fs.ReadFile("017_refresh_queue_listing_indexes.up.sql")
	if err != nil {
		t.Fatalf("read up migration: %v", err)
	}
	upSQL := string(up)
	for _, want := range []string{
		"CREATE INDEX idx_queue_listing_requested_at ON refresh_queue(requested_at DESC, id DESC);",
		"CREATE INDEX idx_queue_listing_status_requested_at ON refresh_queue(status, requested_at DESC, id DESC);",
	} {
		if !strings.Contains(upSQL, want) {
			t.Fatalf("up migration missing %q:\n%s", want, upSQL)
		}
	}

	down, err := fs.ReadFile("017_refresh_queue_listing_indexes.down.sql")
	if err != nil {
		t.Fatalf("read down migration: %v", err)
	}
	downSQL := string(down)
	for _, want := range []string{
		"DROP INDEX IF EXISTS idx_queue_listing_status_requested_at;",
		"DROP INDEX IF EXISTS idx_queue_listing_requested_at;",
	} {
		if !strings.Contains(downSQL, want) {
			t.Fatalf("down migration missing %q:\n%s", want, downSQL)
		}
	}
}

func TestRefreshQueueTerminalRetentionIndexMigrationDefinesExpectedIndex(t *testing.T) {
	t.Parallel()

	up, err := fs.ReadFile("022_refresh_queue_terminal_retention_index.up.sql")
	if err != nil {
		t.Fatalf("read up migration: %v", err)
	}
	upSQL := string(up)
	for _, want := range []string{
		"CREATE INDEX idx_queue_terminal_processed_at",
		"ON refresh_queue(COALESCE(processed_at, requested_at))",
		"WHERE status IN ('done', 'error');",
	} {
		if !strings.Contains(upSQL, want) {
			t.Fatalf("up migration missing %q:\n%s", want, upSQL)
		}
	}

	down, err := fs.ReadFile("022_refresh_queue_terminal_retention_index.down.sql")
	if err != nil {
		t.Fatalf("read down migration: %v", err)
	}
	if !strings.Contains(string(down), "DROP INDEX IF EXISTS idx_queue_terminal_processed_at;") {
		t.Fatalf("down migration missing terminal retention index drop:\n%s", down)
	}
}

func TestPackageCheckStatusRetentionIndexMigrationDefinesExpectedIndex(t *testing.T) {
	t.Parallel()

	up, err := fs.ReadFile("028_package_check_status_retention_index.up.sql")
	if err != nil {
		t.Fatalf("read up migration: %v", err)
	}
	upSQL := string(up)
	for _, want := range []string{
		"CREATE INDEX IF NOT EXISTS idx_package_check_status_socket_updated_at",
		"ON package_check_status(updated_at)",
		"WHERE source = 'socket';",
	} {
		if !strings.Contains(upSQL, want) {
			t.Fatalf("up migration missing %q:\n%s", want, upSQL)
		}
	}

	down, err := fs.ReadFile("028_package_check_status_retention_index.down.sql")
	if err != nil {
		t.Fatalf("read down migration: %v", err)
	}
	if strings.Contains(string(down), "DROP INDEX IF EXISTS idx_package_check_status_socket_updated_at;") {
		t.Fatalf("down migration drops baseline-owned package check status retention index:\n%s", down)
	}

	initial, err := fs.ReadFile("001_initial.up.sql")
	if err != nil {
		t.Fatalf("read initial schema: %v", err)
	}
	initialSQL := string(initial)
	for _, want := range []string{
		"CREATE INDEX idx_package_check_status_socket_updated_at",
		"ON package_check_status(updated_at)",
		"WHERE source = 'socket';",
	} {
		if !strings.Contains(initialSQL, want) {
			t.Fatalf("initial schema missing package check status retention index marker %q", want)
		}
	}
}

func TestRecentVulnerabilitiesPublishedIndexMigrationDefinesExpectedIndex(t *testing.T) {
	t.Parallel()

	up, err := fs.ReadFile("023_recent_vulnerabilities_published_index.up.sql")
	if err != nil {
		t.Fatalf("read up migration: %v", err)
	}
	upSQL := string(up)
	for _, want := range []string{
		"CREATE INDEX idx_vulnerabilities_recent_published",
		"ON vulnerabilities(published DESC, id DESC)",
		"WHERE withdrawn IS NULL;",
	} {
		if !strings.Contains(upSQL, want) {
			t.Fatalf("up migration missing %q:\n%s", want, upSQL)
		}
	}

	down, err := fs.ReadFile("023_recent_vulnerabilities_published_index.down.sql")
	if err != nil {
		t.Fatalf("read down migration: %v", err)
	}
	if !strings.Contains(string(down), "DROP INDEX IF EXISTS idx_vulnerabilities_recent_published;") {
		t.Fatalf("down migration missing recent vulnerabilities index drop:\n%s", down)
	}
}

func TestAPIKeyDeletedAtMigrationDefinesSoftDeleteColumn(t *testing.T) {
	t.Parallel()

	up, err := fs.ReadFile("025_api_key_deleted_at.up.sql")
	if err != nil {
		t.Fatalf("read up migration: %v", err)
	}
	upSQL := string(up)
	for _, want := range []string{
		"ALTER TABLE api_keys",
		"ADD COLUMN deleted_at TIMESTAMPTZ;",
		"CREATE INDEX idx_api_keys_deleted_at",
		"WHERE deleted_at IS NOT NULL;",
	} {
		if !strings.Contains(upSQL, want) {
			t.Fatalf("up migration missing API key soft-delete marker %q:\n%s", want, upSQL)
		}
	}

	down, err := fs.ReadFile("025_api_key_deleted_at.down.sql")
	if err != nil {
		t.Fatalf("read down migration: %v", err)
	}
	downSQL := string(down)
	for _, want := range []string{
		"DROP INDEX IF EXISTS idx_api_keys_deleted_at;",
		"DROP COLUMN IF EXISTS deleted_at;",
	} {
		if !strings.Contains(downSQL, want) {
			t.Fatalf("down migration missing API key soft-delete marker %q:\n%s", want, downSQL)
		}
	}
}

func TestScanLogIdempotencyMigrationDefinesRetryKey(t *testing.T) {
	t.Parallel()

	up, err := fs.ReadFile("026_scan_log_idempotency.up.sql")
	if err != nil {
		t.Fatalf("read up migration: %v", err)
	}
	upSQL := string(up)
	for _, want := range []string{
		"ADD COLUMN IF NOT EXISTS idempotency_key TEXT",
		"ADD COLUMN IF NOT EXISTS request_digest TEXT NOT NULL DEFAULT ''",
		"CREATE UNIQUE INDEX IF NOT EXISTS idx_scan_log_idempotency_key",
		"ON scan_log(idempotency_key)",
		"WHERE idempotency_key IS NOT NULL;",
	} {
		if !strings.Contains(upSQL, want) {
			t.Fatalf("up migration missing scan-log idempotency marker %q:\n%s", want, upSQL)
		}
	}

	down, err := fs.ReadFile("026_scan_log_idempotency.down.sql")
	if err != nil {
		t.Fatalf("read down migration: %v", err)
	}
	downSQL := string(down)
	for _, want := range []string{
		"DROP INDEX IF EXISTS idx_scan_log_idempotency_key;",
		"DROP COLUMN IF EXISTS request_digest",
		"DROP COLUMN IF EXISTS idempotency_key",
	} {
		if !strings.Contains(downSQL, want) {
			t.Fatalf("down migration missing scan-log idempotency marker %q:\n%s", want, downSQL)
		}
	}
}

func TestVulnerabilityEnrichmentIndexMigrationDefinesExpectedIndexes(t *testing.T) {
	t.Parallel()

	up, err := fs.ReadFile("024_vulnerability_enrichment_indexes.up.sql")
	if err != nil {
		t.Fatalf("read up migration: %v", err)
	}
	upSQL := string(up)
	for _, want := range []string{
		"CREATE INDEX IF NOT EXISTS idx_vulnerabilities_nvd_candidate",
		"ON vulnerabilities(id)",
		"WHERE severity = 'UNKNOWN' OR (severity = 'LOW' AND cvss_score IS NULL);",
		"CREATE INDEX IF NOT EXISTS idx_vuln_aliases_cve_alias",
		"ON vulnerability_aliases(alias_id text_pattern_ops, vulnerability_id)",
		"WHERE alias_id LIKE 'CVE-%';",
		"CREATE INDEX IF NOT EXISTS idx_vulnerabilities_cisa_kev",
		"ON vulnerabilities(id)",
		"WHERE cisa_kev = TRUE;",
	} {
		if !strings.Contains(upSQL, want) {
			t.Fatalf("up migration missing vulnerability enrichment index marker %q:\n%s", want, upSQL)
		}
	}

	down, err := fs.ReadFile("024_vulnerability_enrichment_indexes.down.sql")
	if err != nil {
		t.Fatalf("read down migration: %v", err)
	}
	downSQL := string(down)
	for _, forbidden := range []string{
		"DROP INDEX IF EXISTS idx_vulnerabilities_cisa_kev;",
		"DROP INDEX IF EXISTS idx_vuln_aliases_cve_alias;",
		"DROP INDEX IF EXISTS idx_vulnerabilities_nvd_candidate;",
	} {
		if strings.Contains(downSQL, forbidden) {
			t.Fatalf("down migration drops baseline-owned vulnerability enrichment index %q:\n%s", forbidden, downSQL)
		}
	}

	initial, err := fs.ReadFile("001_initial.up.sql")
	if err != nil {
		t.Fatalf("read initial schema: %v", err)
	}
	initialSQL := string(initial)
	for _, want := range []string{
		"CREATE INDEX idx_vulnerabilities_nvd_candidate",
		"WHERE severity = 'UNKNOWN' OR (severity = 'LOW' AND cvss_score IS NULL);",
		"CREATE INDEX idx_vuln_aliases_cve_alias",
		"WHERE alias_id LIKE 'CVE-%';",
		"CREATE INDEX idx_vulnerabilities_cisa_kev",
		"WHERE cisa_kev = TRUE;",
	} {
		if !strings.Contains(initialSQL, want) {
			t.Fatalf("initial schema missing vulnerability enrichment index marker %q", want)
		}
	}
}

func TestSeverityConstraintMigrationDefinesStoredSeverityChecks(t *testing.T) {
	t.Parallel()

	up, err := fs.ReadFile("027_severity_constraints.up.sql")
	if err != nil {
		t.Fatalf("read up migration: %v", err)
	}
	upSQL := string(up)
	for _, want := range []string{
		"CONSTRAINT vulnerabilities_severity_check",
		"CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW'))",
		"CONSTRAINT malicious_findings_severity_check",
		"CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'))",
		"CONSTRAINT package_reputation_cache_severity_check",
	} {
		if !strings.Contains(upSQL, want) {
			t.Fatalf("severity migration missing %q:\n%s", want, upSQL)
		}
	}

	initial, err := fs.ReadFile("001_initial.up.sql")
	if err != nil {
		t.Fatalf("read initial schema: %v", err)
	}
	initialSQL := string(initial)
	for _, want := range []string{
		"CONSTRAINT vulnerabilities_severity_check",
		"CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW'))",
		"CONSTRAINT malicious_findings_severity_check",
		"CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'))",
	} {
		if !strings.Contains(initialSQL, want) {
			t.Fatalf("initial schema missing severity marker %q", want)
		}
	}
}

func TestVulnerabilityScoreConstraintMigrationDefinesCVSSAndEPSSRanges(t *testing.T) {
	t.Parallel()

	up, err := fs.ReadFile("041_vulnerability_score_constraints.up.sql")
	if err != nil {
		t.Fatalf("read up migration: %v", err)
	}
	upSQL := strings.Join(strings.Fields(string(up)), " ")
	for _, want := range []string{
		"ALTER TABLE vulnerabilities",
		"DROP CONSTRAINT IF EXISTS vulnerabilities_cvss_score_range_check",
		"DROP CONSTRAINT IF EXISTS vulnerabilities_epss_score_range_check",
		"DROP CONSTRAINT IF EXISTS vulnerabilities_epss_percentile_range_check",
		"ADD CONSTRAINT vulnerabilities_cvss_score_range_check",
		"CHECK (cvss_score IS NULL OR (cvss_score >= 0 AND cvss_score <= 10)) NOT VALID",
		"ADD CONSTRAINT vulnerabilities_epss_score_range_check",
		"CHECK (epss_score IS NULL OR (epss_score >= 0 AND epss_score <= 1)) NOT VALID",
		"ADD CONSTRAINT vulnerabilities_epss_percentile_range_check",
		"CHECK (epss_percentile IS NULL OR (epss_percentile >= 0 AND epss_percentile <= 1)) NOT VALID",
		"VALIDATE CONSTRAINT vulnerabilities_cvss_score_range_check;",
		"VALIDATE CONSTRAINT vulnerabilities_epss_score_range_check;",
		"VALIDATE CONSTRAINT vulnerabilities_epss_percentile_range_check;",
	} {
		if !strings.Contains(upSQL, want) {
			t.Fatalf("score constraint up migration missing %q:\n%s", want, upSQL)
		}
	}
	if strings.Contains(upSQL, "UPDATE vulnerabilities") {
		t.Fatalf("score constraint up migration must not rewrite existing vulnerability scores:\n%s", upSQL)
	}

	down, err := fs.ReadFile("041_vulnerability_score_constraints.down.sql")
	if err != nil {
		t.Fatalf("read down migration: %v", err)
	}
	downSQL := strings.Join(strings.Fields(string(down)), " ")
	for _, want := range []string{
		"DROP CONSTRAINT IF EXISTS vulnerabilities_epss_percentile_range_check;",
		"DROP CONSTRAINT IF EXISTS vulnerabilities_epss_score_range_check;",
		"DROP CONSTRAINT IF EXISTS vulnerabilities_cvss_score_range_check;",
	} {
		if !strings.Contains(downSQL, want) {
			t.Fatalf("score constraint down migration missing %q:\n%s", want, downSQL)
		}
	}

	initial, err := fs.ReadFile("001_initial.up.sql")
	if err != nil {
		t.Fatalf("read initial schema: %v", err)
	}
	initialSQL := strings.Join(strings.Fields(string(initial)), " ")
	for _, want := range []string{
		"CONSTRAINT vulnerabilities_cvss_score_range_check CHECK (cvss_score IS NULL OR (cvss_score >= 0 AND cvss_score <= 10))",
		"CONSTRAINT vulnerabilities_epss_score_range_check CHECK (epss_score IS NULL OR (epss_score >= 0 AND epss_score <= 1))",
		"CONSTRAINT vulnerabilities_epss_percentile_range_check CHECK (epss_percentile IS NULL OR (epss_percentile >= 0 AND epss_percentile <= 1))",
	} {
		if !strings.Contains(initialSQL, want) {
			t.Fatalf("initial schema missing score constraint marker %q", want)
		}
	}
}

func TestSchemaConstraintBatchMigrationDefinesOpenTodoChecks(t *testing.T) {
	t.Parallel()

	up, err := fs.ReadFile("042_schema_constraint_batch.up.sql")
	if err != nil {
		t.Fatalf("read up migration: %v", err)
	}
	upSQL := strings.Join(strings.Fields(string(up)), " ")
	for _, want := range []string{
		"UPDATE scan_log SET api_key_id = NULL WHERE api_key_id IS NOT NULL AND NOT EXISTS",
		"ADD CONSTRAINT feed_sync_status_status_check",
		"last_sync_status IN (",
		"'permanent_error'",
		"ADD CONSTRAINT feed_sync_status_entries_nonnegative_check CHECK (entries_synced >= 0 AND entries_total >= 0) NOT VALID",
		"ADD CONSTRAINT feed_sync_status_entries_order_check CHECK (entries_total <= 0 OR entries_synced <= entries_total) NOT VALID",
		"ADD CONSTRAINT feed_sync_status_duration_nonnegative_check CHECK (last_sync_duration IS NULL OR last_sync_duration >= INTERVAL '0') NOT VALID",
		"ADD CONSTRAINT refresh_queue_status_check CHECK (status IN ('pending', 'processing', 'paused', 'done', 'error')) NOT VALID",
		"ADD CONSTRAINT refresh_queue_priority_check CHECK (priority BETWEEN 0 AND 3) NOT VALID",
		"ADD CONSTRAINT scan_log_api_key_id_fkey FOREIGN KEY (api_key_id) REFERENCES api_keys(id) ON DELETE SET NULL NOT VALID",
		"ADD CONSTRAINT scan_log_packages_count_nonnegative_check CHECK (packages_count >= 0) NOT VALID",
		"ADD CONSTRAINT scan_log_findings_count_nonnegative_check CHECK (findings_count >= 0) NOT VALID",
		"ADD CONSTRAINT scan_log_duration_ms_nonnegative_check CHECK (duration_ms >= 0) NOT VALID",
		"ADD CONSTRAINT scan_log_manual_advisories_count_nonnegative_check CHECK (manual_advisories_count >= 0) NOT VALID",
		"ADD CONSTRAINT scan_log_block_threshold_check CHECK (block_threshold IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE')) NOT VALID",
		"ADD CONSTRAINT scan_log_feed_status_check CHECK (feed_status IN ('healthy', 'degraded', 'error')) NOT VALID",
		"ADD CONSTRAINT scan_log_feed_versions_object_check CHECK (feed_versions IS NULL OR jsonb_typeof(feed_versions) = 'object') NOT VALID",
		"ADD CONSTRAINT scan_log_finding_ids_array_check CHECK (finding_ids IS NULL OR jsonb_typeof(finding_ids) = 'array') NOT VALID",
		"ADD CONSTRAINT scan_log_finding_severities_array_check CHECK (finding_severities IS NULL OR jsonb_typeof(finding_severities) = 'array') NOT VALID",
		"ADD CONSTRAINT api_keys_deleted_requires_revoked_check CHECK (deleted_at IS NULL OR revoked_at IS NOT NULL) NOT VALID",
		"ADD CONSTRAINT api_keys_revoked_not_before_created_check CHECK (revoked_at IS NULL OR revoked_at >= created_at) NOT VALID",
		"ADD CONSTRAINT api_keys_deleted_not_before_created_check CHECK (deleted_at IS NULL OR deleted_at >= created_at) NOT VALID",
		"ADD CONSTRAINT api_keys_last_used_not_before_created_check CHECK (last_used_at IS NULL OR last_used_at >= created_at) NOT VALID",
		"ADD CONSTRAINT api_keys_deleted_not_before_revoked_check CHECK (deleted_at IS NULL OR revoked_at IS NULL OR deleted_at >= revoked_at) NOT VALID",
		"ADD CONSTRAINT feed_configs_sync_interval_minimum_check CHECK (sync_interval IS NULL OR sync_interval >= INTERVAL '15 minutes') NOT VALID",
		"VALIDATE CONSTRAINT feed_configs_sync_interval_minimum_check;",
	} {
		if !strings.Contains(upSQL, want) {
			t.Fatalf("schema constraint batch up migration missing %q:\n%s", want, upSQL)
		}
	}

	down, err := fs.ReadFile("042_schema_constraint_batch.down.sql")
	if err != nil {
		t.Fatalf("read down migration: %v", err)
	}
	downSQL := strings.Join(strings.Fields(string(down)), " ")
	for _, want := range []string{
		"DROP CONSTRAINT IF EXISTS feed_configs_sync_interval_minimum_check;",
		"DROP CONSTRAINT IF EXISTS api_keys_deleted_not_before_revoked_check",
		"DROP CONSTRAINT IF EXISTS api_keys_last_used_not_before_created_check",
		"DROP CONSTRAINT IF EXISTS scan_log_api_key_id_fkey;",
		"DROP CONSTRAINT IF EXISTS scan_log_feed_versions_object_check",
		"DROP CONSTRAINT IF EXISTS refresh_queue_priority_check;",
		"DROP CONSTRAINT IF EXISTS feed_sync_status_entries_order_check;",
		"ADD CONSTRAINT feed_sync_status_entries_order_check CHECK (entries_synced <= entries_total) NOT VALID",
	} {
		if !strings.Contains(downSQL, want) {
			t.Fatalf("schema constraint batch down migration missing %q:\n%s", want, downSQL)
		}
	}
}

func TestInitialSchemaDefinesCurrentSchemaConstraintBatch(t *testing.T) {
	t.Parallel()

	initial, err := fs.ReadFile("001_initial.up.sql")
	if err != nil {
		t.Fatalf("read initial schema: %v", err)
	}
	initialSQL := strings.Join(strings.Fields(string(initial)), " ")
	for _, want := range []string{
		"CONSTRAINT feed_sync_status_entries_order_check CHECK (entries_total <= 0 OR entries_synced <= entries_total)",
		"CONSTRAINT refresh_queue_status_check CHECK (status IN ('pending', 'processing', 'paused', 'done', 'error'))",
		"CONSTRAINT scan_log_packages_count_nonnegative_check CHECK (packages_count >= 0)",
		"CONSTRAINT scan_log_findings_count_nonnegative_check CHECK (findings_count >= 0)",
		"CONSTRAINT scan_log_duration_ms_nonnegative_check CHECK (duration_ms >= 0)",
		"ALTER TABLE scan_log ADD CONSTRAINT scan_log_api_key_id_fkey FOREIGN KEY (api_key_id) REFERENCES api_keys(id) ON DELETE SET NULL;",
		"CONSTRAINT api_keys_revoked_not_before_created_check CHECK (revoked_at IS NULL OR revoked_at >= created_at)",
		"CONSTRAINT api_keys_last_used_not_before_created_check CHECK (last_used_at IS NULL OR last_used_at >= created_at)",
		"CONSTRAINT feed_configs_sync_interval_minimum_check CHECK (sync_interval IS NULL OR sync_interval >= INTERVAL '15 minutes')",
	} {
		if !strings.Contains(initialSQL, want) {
			t.Fatalf("initial schema missing schema constraint batch marker %q", want)
		}
	}
}

func TestDomainConstraintMigrationDefinesExpectedChecks(t *testing.T) {
	t.Parallel()

	up, err := fs.ReadFile("031_domain_constraints.up.sql")
	if err != nil {
		t.Fatalf("read up migration: %v", err)
	}
	upSQL := string(up)
	for _, want := range []string{
		"CONSTRAINT affected_packages_ecosystem_check",
		"CONSTRAINT malicious_findings_ecosystem_check",
		"CONSTRAINT package_reputation_cache_ecosystem_check",
		"CONSTRAINT malicious_findings_risk_type_check",
		"CONSTRAINT vulnerability_sources_manual_id_check",
		"CONSTRAINT malicious_findings_manual_id_check",
		"CONSTRAINT refresh_queue_status_check",
		"CONSTRAINT refresh_queue_priority_check",
		"CHECK (priority BETWEEN 0 AND 3)",
	} {
		if !strings.Contains(upSQL, want) {
			t.Fatalf("domain constraint migration missing %q:\n%s", want, upSQL)
		}
	}

	down, err := fs.ReadFile("031_domain_constraints.down.sql")
	if err != nil {
		t.Fatalf("read down migration: %v", err)
	}
	downSQL := string(down)
	for _, want := range []string{
		"DROP CONSTRAINT IF EXISTS affected_packages_ecosystem_check",
		"DROP CONSTRAINT IF EXISTS malicious_findings_ecosystem_check",
		"DROP CONSTRAINT IF EXISTS package_reputation_cache_ecosystem_check",
		"DROP CONSTRAINT IF EXISTS malicious_findings_risk_type_check",
		"DROP CONSTRAINT IF EXISTS vulnerability_sources_manual_id_check",
		"DROP CONSTRAINT IF EXISTS malicious_findings_manual_id_check",
		"DROP CONSTRAINT IF EXISTS refresh_queue_status_check",
		"DROP CONSTRAINT IF EXISTS refresh_queue_priority_check",
	} {
		if !strings.Contains(downSQL, want) {
			t.Fatalf("domain constraint down migration missing %q:\n%s", want, downSQL)
		}
	}

	initial, err := fs.ReadFile("001_initial.up.sql")
	if err != nil {
		t.Fatalf("read initial schema: %v", err)
	}
	initialSQL := string(initial)
	for _, want := range []string{
		"CONSTRAINT affected_packages_ecosystem_check",
		"CONSTRAINT malicious_findings_ecosystem_check",
		"CONSTRAINT malicious_findings_risk_type_check",
		"CONSTRAINT refresh_queue_status_check",
		"CONSTRAINT refresh_queue_priority_check",
	} {
		if !strings.Contains(initialSQL, want) {
			t.Fatalf("initial schema missing domain constraint marker %q", want)
		}
	}
}

func TestFeedStatusAndSyncIndexMigrationDefinesExpectedChecks(t *testing.T) {
	t.Parallel()

	up, err := fs.ReadFile("034_feed_status_and_sync_indexes.up.sql")
	if err != nil {
		t.Fatalf("read up migration: %v", err)
	}
	upSQL := string(up)
	for _, want := range []string{
		"CONSTRAINT feed_sync_status_status_check",
		"CONSTRAINT feed_sync_status_entries_nonnegative_check",
		"CONSTRAINT feed_sync_status_entries_order_check",
		"CONSTRAINT feed_sync_status_duration_nonnegative_check",
		"CREATE INDEX IF NOT EXISTS idx_reputation_reportable_sync",
		"ON package_reputation_cache(source, ecosystem, name, version)",
		"WHERE status IN ('malicious', 'removed', 'risk');",
	} {
		if !strings.Contains(upSQL, want) {
			t.Fatalf("feed status/index migration missing %q:\n%s", want, upSQL)
		}
	}

	down, err := fs.ReadFile("034_feed_status_and_sync_indexes.down.sql")
	if err != nil {
		t.Fatalf("read down migration: %v", err)
	}
	downSQL := string(down)
	for _, want := range []string{
		"DROP INDEX IF EXISTS idx_reputation_reportable_sync",
		"DROP CONSTRAINT IF EXISTS feed_sync_status_status_check",
		"DROP CONSTRAINT IF EXISTS feed_sync_status_entries_nonnegative_check",
		"DROP CONSTRAINT IF EXISTS feed_sync_status_entries_order_check",
		"DROP CONSTRAINT IF EXISTS feed_sync_status_duration_nonnegative_check",
	} {
		if !strings.Contains(downSQL, want) {
			t.Fatalf("feed status/index down migration missing %q:\n%s", want, downSQL)
		}
	}

	initial, err := fs.ReadFile("001_initial.up.sql")
	if err != nil {
		t.Fatalf("read initial schema: %v", err)
	}
	initialSQL := string(initial)
	for _, want := range []string{
		"CONSTRAINT feed_sync_status_status_check",
		"CONSTRAINT feed_sync_status_entries_nonnegative_check",
		"CONSTRAINT feed_sync_status_entries_order_check",
		"CONSTRAINT feed_sync_status_duration_nonnegative_check",
	} {
		if !strings.Contains(initialSQL, want) {
			t.Fatalf("initial schema missing feed status constraint marker %q", want)
		}
	}
}

func TestQueryPerformanceIndexMigrationDefinesExpectedIndexes(t *testing.T) {
	t.Parallel()

	up, err := fs.ReadFile("035_query_performance_indexes.up.sql")
	if err != nil {
		t.Fatalf("read up migration: %v", err)
	}
	upSQL := string(up)
	for _, want := range []string{
		"CREATE INDEX IF NOT EXISTS idx_lifecycle_releases_eol_status_date",
		"ON lifecycle_releases(product_slug, eol_from)",
		"WHERE is_eol OR eol_from IS NOT NULL;",
		"CREATE INDEX IF NOT EXISTS idx_lifecycle_releases_eoas_status_date",
		"ON lifecycle_releases(product_slug, eoas_from)",
		"WHERE is_eoas OR eoas_from IS NOT NULL;",
		"CREATE INDEX IF NOT EXISTS idx_malicious_active_source_updated_at",
		"ON malicious_findings(source, updated_at DESC, created_at DESC, id DESC)",
		"WHERE removed_at IS NULL;",
		"CREATE INDEX IF NOT EXISTS idx_malicious_active_updated_at",
		"ON malicious_findings(updated_at DESC, created_at DESC, id DESC)",
		"WHERE removed_at IS NULL;",
		"CREATE INDEX IF NOT EXISTS idx_queue_oldest_active_source_requested_at",
		"ON refresh_queue(source, requested_at)",
		"WHERE source <> '' AND status IN ('pending', 'processing');",
		"CREATE INDEX IF NOT EXISTS idx_reputation_prune_source_updated_at",
		"ON package_reputation_cache(source, updated_at)",
		"WHERE status IN ('clean', 'not_found', 'unsupported', 'error');",
	} {
		if !strings.Contains(upSQL, want) {
			t.Fatalf("query performance migration missing %q:\n%s", want, upSQL)
		}
	}

	down, err := fs.ReadFile("035_query_performance_indexes.down.sql")
	if err != nil {
		t.Fatalf("read down migration: %v", err)
	}
	downSQL := string(down)
	for _, want := range []string{
		"DROP INDEX IF EXISTS idx_reputation_prune_source_updated_at;",
		"DROP INDEX IF EXISTS idx_queue_oldest_active_source_requested_at;",
		"DROP INDEX IF EXISTS idx_malicious_active_updated_at;",
		"DROP INDEX IF EXISTS idx_malicious_active_source_updated_at;",
		"DROP INDEX IF EXISTS idx_lifecycle_releases_eoas_status_date;",
		"DROP INDEX IF EXISTS idx_lifecycle_releases_eol_status_date;",
	} {
		if !strings.Contains(downSQL, want) {
			t.Fatalf("query performance down migration missing %q:\n%s", want, downSQL)
		}
	}
}

func TestVersionJSONConstraintMigrationDefinesExpectedChecks(t *testing.T) {
	t.Parallel()

	up, err := fs.ReadFile("032_version_json_constraints.up.sql")
	if err != nil {
		t.Fatalf("read up migration: %v", err)
	}
	upSQL := string(up)
	for _, want := range []string{
		"CREATE OR REPLACE FUNCTION packmon_jsonb_string_array_valid",
		"CREATE OR REPLACE FUNCTION packmon_jsonb_version_ranges_valid",
		"CONSTRAINT affected_packages_version_ranges_array_check",
		"CHECK (packmon_jsonb_version_ranges_valid(version_ranges))",
		"CONSTRAINT affected_packages_versions_affected_array_check",
		"CHECK (packmon_jsonb_string_array_valid(versions_affected))",
		"CONSTRAINT malicious_findings_version_ranges_array_check",
		"CHECK (version_ranges IS NULL OR packmon_jsonb_version_ranges_valid(version_ranges))",
		"CONSTRAINT malicious_findings_versions_array_check",
		"CHECK (versions IS NULL OR packmon_jsonb_string_array_valid(versions))",
	} {
		if !strings.Contains(upSQL, want) {
			t.Fatalf("version JSON constraint migration missing %q:\n%s", want, upSQL)
		}
	}

	down, err := fs.ReadFile("032_version_json_constraints.down.sql")
	if err != nil {
		t.Fatalf("read down migration: %v", err)
	}
	downSQL := string(down)
	for _, want := range []string{
		"DROP CONSTRAINT IF EXISTS affected_packages_version_ranges_array_check",
		"DROP CONSTRAINT IF EXISTS affected_packages_versions_affected_array_check",
		"DROP CONSTRAINT IF EXISTS malicious_findings_version_ranges_array_check",
		"DROP CONSTRAINT IF EXISTS malicious_findings_versions_array_check",
		"DROP FUNCTION IF EXISTS packmon_jsonb_version_ranges_valid(JSONB)",
		"DROP FUNCTION IF EXISTS packmon_jsonb_string_array_valid(JSONB)",
	} {
		if !strings.Contains(downSQL, want) {
			t.Fatalf("version JSON constraint down migration missing %q:\n%s", want, downSQL)
		}
	}

	initial, err := fs.ReadFile("001_initial.up.sql")
	if err != nil {
		t.Fatalf("read initial schema: %v", err)
	}
	initialSQL := string(initial)
	for _, want := range []string{
		"CONSTRAINT affected_packages_version_ranges_array_check",
		"CONSTRAINT affected_packages_versions_affected_array_check",
		"CONSTRAINT malicious_findings_version_ranges_array_check",
		"CONSTRAINT malicious_findings_versions_array_check",
		"CREATE OR REPLACE FUNCTION packmon_jsonb_string_array_valid",
		"CREATE OR REPLACE FUNCTION packmon_jsonb_version_ranges_valid",
	} {
		if !strings.Contains(initialSQL, want) {
			t.Fatalf("initial schema missing version JSON constraint marker %q", want)
		}
	}
}

func TestScanLogTotalsMigrationDefinesRollup(t *testing.T) {
	t.Parallel()

	up, err := fs.ReadFile("018_scan_log_totals.up.sql")
	if err != nil {
		t.Fatalf("read up migration: %v", err)
	}
	upSQL := string(up)
	for _, want := range []string{
		"CREATE TABLE scan_log_totals",
		"packages_scanned BIGINT NOT NULL DEFAULT 0",
		"findings BIGINT NOT NULL DEFAULT 0",
		"SUM(packages_count)",
		"SUM(findings_count)",
	} {
		if !strings.Contains(upSQL, want) {
			t.Fatalf("up migration missing %q:\n%s", want, upSQL)
		}
	}

	down, err := fs.ReadFile("018_scan_log_totals.down.sql")
	if err != nil {
		t.Fatalf("read down migration: %v", err)
	}
	if downSQL := string(down); !strings.Contains(downSQL, "DROP TABLE IF EXISTS scan_log_totals;") {
		t.Fatalf("down migration missing scan_log_totals drop:\n%s", downSQL)
	}
}

func TestVulnerabilitySourcesSourceIndexMigrationDefinesExpectedIndex(t *testing.T) {
	t.Parallel()

	const initialIndexSQL = "CREATE INDEX idx_vuln_sources_source_vuln_id ON vulnerability_sources(source, vulnerability_id) WHERE raw_json IS NOT NULL;"
	const migrationIndexSQL = "CREATE INDEX IF NOT EXISTS idx_vuln_sources_source_vuln_id ON vulnerability_sources(source, vulnerability_id) WHERE raw_json IS NOT NULL;"

	up, err := fs.ReadFile("019_vulnerability_sources_source_index.up.sql")
	if err != nil {
		t.Fatalf("read up migration: %v", err)
	}
	if upSQL := string(up); !strings.Contains(upSQL, migrationIndexSQL) {
		t.Fatalf("up migration missing source-leading vulnerability_sources index:\n%s", upSQL)
	}

	down, err := fs.ReadFile("019_vulnerability_sources_source_index.down.sql")
	if err != nil {
		t.Fatalf("read down migration: %v", err)
	}
	if downSQL := string(down); strings.Contains(downSQL, "DROP INDEX IF EXISTS idx_vuln_sources_source_vuln_id;") {
		t.Fatalf("down migration drops baseline-owned source-leading index:\n%s", downSQL)
	}

	initial, err := fs.ReadFile("001_initial.up.sql")
	if err != nil {
		t.Fatalf("read initial schema: %v", err)
	}
	if initialSQL := string(initial); !strings.Contains(initialSQL, initialIndexSQL) {
		t.Fatalf("initial schema missing source-leading vulnerability_sources index")
	}
}

func TestLifecyclePackageMapProductSlugIndexMigrationDefinesExpectedIndex(t *testing.T) {
	t.Parallel()

	const migrationIndexSQL = "CREATE INDEX IF NOT EXISTS idx_lifecycle_package_map_product_slug ON lifecycle_package_map(product_slug);"

	up, err := fs.ReadFile("020_lifecycle_package_map_product_slug_index.up.sql")
	if err != nil {
		t.Fatalf("read up migration: %v", err)
	}
	if upSQL := string(up); !strings.Contains(upSQL, migrationIndexSQL) {
		t.Fatalf("up migration missing lifecycle package-map product_slug index:\n%s", upSQL)
	}

	down, err := fs.ReadFile("020_lifecycle_package_map_product_slug_index.down.sql")
	if err != nil {
		t.Fatalf("read down migration: %v", err)
	}
	if downSQL := string(down); strings.Contains(downSQL, "DROP INDEX IF EXISTS idx_lifecycle_package_map_product_slug;") {
		t.Fatalf("down migration drops baseline-owned lifecycle product_slug index:\n%s", downSQL)
	}

	lifecycleSchema, err := fs.ReadFile("007_lifecycle.up.sql")
	if err != nil {
		t.Fatalf("read lifecycle schema: %v", err)
	}
	lifecycleSQL := string(lifecycleSchema)
	for _, want := range []string{
		"CREATE INDEX idx_lifecycle_package_map_product_slug",
		"ON lifecycle_package_map(product_slug);",
	} {
		if !strings.Contains(lifecycleSQL, want) {
			t.Fatalf("lifecycle schema missing package-map product_slug index marker %q", want)
		}
	}
}

func TestPackageSearchTrigramIndexMigrationDefinesExpectedIndexes(t *testing.T) {
	t.Parallel()

	up, err := fs.ReadFile("021_package_search_trigram_indexes.up.sql")
	if err != nil {
		t.Fatalf("read up migration: %v", err)
	}
	upSQL := string(up)
	for _, want := range []string{
		"CREATE EXTENSION IF NOT EXISTS pg_trgm;",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_affected_packages_name_trgm",
		"ON affected_packages USING gin (name gin_trgm_ops);",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_malicious_findings_name_trgm",
		"ON malicious_findings USING gin (name gin_trgm_ops)",
		"WHERE removed_at IS NULL;",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_package_reputation_cache_name_trgm",
		"ON package_reputation_cache USING gin (name gin_trgm_ops);",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_lifecycle_package_map_name_trgm",
		"ON lifecycle_package_map USING gin (name gin_trgm_ops);",
	} {
		if !strings.Contains(upSQL, want) {
			t.Fatalf("up migration missing package-search trigram marker %q:\n%s", want, upSQL)
		}
	}

	down, err := fs.ReadFile("021_package_search_trigram_indexes.down.sql")
	if err != nil {
		t.Fatalf("read down migration: %v", err)
	}
	downSQL := string(down)
	for _, want := range []string{
		"DROP INDEX CONCURRENTLY IF EXISTS idx_lifecycle_package_map_name_trgm;",
		"DROP INDEX CONCURRENTLY IF EXISTS idx_package_reputation_cache_name_trgm;",
		"DROP INDEX CONCURRENTLY IF EXISTS idx_malicious_findings_name_trgm;",
		"DROP INDEX CONCURRENTLY IF EXISTS idx_affected_packages_name_trgm;",
	} {
		if !strings.Contains(downSQL, want) {
			t.Fatalf("down migration missing package-search trigram marker %q:\n%s", want, downSQL)
		}
	}
}

func TestBlockingIndexMigrationsRunOutsideTransaction(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		version int
		name    string
		wants   []string
	}{
		{
			version: 10,
			name:    "010_affected_packages_updated_at.up.sql",
			wants: []string{
				"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_affected_packages_updated_at ON affected_packages(updated_at);",
			},
		},
		{
			version: 11,
			name:    "011_sync_keyset_and_lifecycle_tombstones.up.sql",
			wants: []string{
				"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_vulnerabilities_updated_at ON vulnerabilities(updated_at);",
				"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_malicious_findings_updated_at ON malicious_findings(updated_at);",
				"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_package_reputation_cache_updated_at ON package_reputation_cache(updated_at);",
				"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_lifecycle_products_updated_at ON lifecycle_products(updated_at);",
				"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_lifecycle_releases_updated_at ON lifecycle_releases(updated_at);",
				"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_lifecycle_package_map_updated_at ON lifecycle_package_map(updated_at);",
				"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_lifecycle_sync_tombstones_updated_at",
			},
		},
		{
			version: 21,
			name:    "021_package_search_trigram_indexes.up.sql",
			wants: []string{
				"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_affected_packages_name_trgm",
				"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_malicious_findings_name_trgm",
				"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_package_reputation_cache_name_trgm",
				"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_lifecycle_package_map_name_trgm",
			},
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			migration, err := ReadEmbeddedMigration(tc.version, MigrationDirectionUp)
			if err != nil {
				t.Fatalf("ReadEmbeddedMigration(%d, up): %v", tc.version, err)
			}
			if migrationRunsInTransaction(migrationFile{
				version:   migration.Version,
				name:      migration.Name,
				direction: migration.Direction,
				sql:       migration.SQL,
			}) {
				t.Fatalf("%s should opt out of transaction-wrapped execution", tc.name)
			}
			for _, want := range tc.wants {
				if !strings.Contains(migration.SQL, want) {
					t.Fatalf("%s missing concurrent index creation %q:\n%s", tc.name, want, migration.SQL)
				}
			}
		})
	}
}

func TestBlockingIndexDownMigrationsUseConcurrentDrops(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		version int
		name    string
		wants   []string
	}{
		{
			version: 10,
			name:    "010_affected_packages_updated_at.down.sql",
			wants: []string{
				"DROP INDEX CONCURRENTLY IF EXISTS idx_affected_packages_updated_at;",
			},
		},
		{
			version: 11,
			name:    "011_sync_keyset_and_lifecycle_tombstones.down.sql",
			wants: []string{
				"DROP INDEX CONCURRENTLY IF EXISTS idx_lifecycle_sync_tombstones_updated_at;",
				"DROP INDEX CONCURRENTLY IF EXISTS idx_lifecycle_package_map_updated_at;",
				"DROP INDEX CONCURRENTLY IF EXISTS idx_lifecycle_releases_updated_at;",
				"DROP INDEX CONCURRENTLY IF EXISTS idx_lifecycle_products_updated_at;",
				"DROP INDEX CONCURRENTLY IF EXISTS idx_package_reputation_cache_updated_at;",
				"DROP INDEX CONCURRENTLY IF EXISTS idx_malicious_findings_updated_at;",
				"DROP INDEX CONCURRENTLY IF EXISTS idx_vulnerabilities_updated_at;",
			},
		},
		{
			version: 21,
			name:    "021_package_search_trigram_indexes.down.sql",
			wants: []string{
				"DROP INDEX CONCURRENTLY IF EXISTS idx_lifecycle_package_map_name_trgm;",
				"DROP INDEX CONCURRENTLY IF EXISTS idx_package_reputation_cache_name_trgm;",
				"DROP INDEX CONCURRENTLY IF EXISTS idx_malicious_findings_name_trgm;",
				"DROP INDEX CONCURRENTLY IF EXISTS idx_affected_packages_name_trgm;",
			},
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			migration, err := ReadEmbeddedMigration(tc.version, MigrationDirectionDown)
			if err != nil {
				t.Fatalf("ReadEmbeddedMigration(%d, down): %v", tc.version, err)
			}
			if migrationRunsInTransaction(migrationFile{
				version:   migration.Version,
				name:      migration.Name,
				direction: migration.Direction,
				sql:       migration.SQL,
			}) {
				t.Fatalf("%s should opt out of transaction-wrapped execution", tc.name)
			}
			for _, want := range tc.wants {
				if !strings.Contains(migration.SQL, want) {
					t.Fatalf("%s missing concurrent index drop %q:\n%s", tc.name, want, migration.SQL)
				}
			}
		})
	}
}

func TestApplyMigrationWithoutTransactionExecutesStatementsSeparately(t *testing.T) {
	t.Parallel()

	recorder := &recordingSQLExecutor{}
	migration := migrationFile{
		name: "077_no_transaction.up.sql",
		sql: `-- packmon:migration no-transaction
ALTER TABLE affected_packages
    ADD COLUMN updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_affected_packages_updated_at
    ON affected_packages(updated_at);`,
	}

	if err := applyMigrationWithoutTransaction(context.Background(), recorder, migration); err != nil {
		t.Fatalf("applyMigrationWithoutTransaction() error = %v", err)
	}

	want := []string{
		"-- packmon:migration no-transaction\nALTER TABLE affected_packages\n    ADD COLUMN updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_affected_packages_updated_at\n    ON affected_packages(updated_at)",
	}
	if len(recorder.statements) != len(want) {
		t.Fatalf("executed %d statements, want %d: %#v", len(recorder.statements), len(want), recorder.statements)
	}
	for i := range want {
		if recorder.statements[i] != want[i] {
			t.Fatalf("statement %d = %q, want %q", i, recorder.statements[i], want[i])
		}
	}
}

func TestSplitSQLStatementsHandlesQuotedSemicolons(t *testing.T) {
	t.Parallel()

	statements, err := splitSQLStatements(`
CREATE FUNCTION example() RETURNS trigger AS $$
BEGIN
    RAISE NOTICE 'not a split; still function body';
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_example ON affected_packages(name);
`)
	if err != nil {
		t.Fatalf("splitSQLStatements() error = %v", err)
	}
	if len(statements) != 2 {
		t.Fatalf("splitSQLStatements() returned %d statements, want 2: %#v", len(statements), statements)
	}
	if !strings.Contains(statements[0], "RAISE NOTICE 'not a split; still function body';") {
		t.Fatalf("first statement lost dollar-quoted function body:\n%s", statements[0])
	}
	if !strings.HasPrefix(statements[1], "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_example") {
		t.Fatalf("second statement = %q", statements[1])
	}
}

func TestHistoricalBlockingIndexMigrationChecksumsRemainAccepted(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name        string
		oldChecksum string
	}{
		{name: "010_affected_packages_updated_at.up.sql", oldChecksum: "db8f58df8d5022eb21bad847c61bcaf7453c4f96ba1cafe12d719498b0974f30"},
		{name: "011_sync_keyset_and_lifecycle_tombstones.up.sql", oldChecksum: "58a98c9d3ce3813e770acc5739522e76822fa34d7621b13f3d41a788277a8f22"},
		{name: "021_package_search_trigram_indexes.up.sql", oldChecksum: "f5f140894c5bd39ea76bf2a57f0fec96b933f19e3a7eb7c36f7043bab24a38e1"},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			data, err := fs.ReadFile(tc.name)
			if err != nil {
				t.Fatalf("read %s: %v", tc.name, err)
			}
			migration := migrationFile{name: tc.name, sql: string(data)}
			if migrationChecksum(migration.sql) == tc.oldChecksum {
				t.Fatalf("%s checksum was expected to change after concurrent index migration update", tc.name)
			}
			if !migrationChecksumMatches(migration, tc.oldChecksum) {
				t.Fatalf("%s old checksum %s was not accepted", tc.name, tc.oldChecksum)
			}
		})
	}
}

type recordingSQLExecutor struct {
	statements []string
}

func (r *recordingSQLExecutor) ExecContext(_ context.Context, query string, _ ...any) (sql.Result, error) {
	r.statements = append(r.statements, strings.TrimSpace(query))
	return nil, nil
}

func TestMaliciousActiveExactLookupIndexMigrationDefinesExpectedIndex(t *testing.T) {
	t.Parallel()

	up, err := fs.ReadFile("037_malicious_active_exact_lookup_index.up.sql")
	if err != nil {
		t.Fatalf("read up migration: %v", err)
	}
	upSQL := string(up)
	for _, want := range []string{
		"CREATE INDEX IF NOT EXISTS idx_malicious_active_exact_lookup",
		"ON malicious_findings(ecosystem, name, updated_at DESC, id DESC)",
		"WHERE removed_at IS NULL;",
	} {
		if !strings.Contains(upSQL, want) {
			t.Fatalf("up migration missing active malicious exact-lookup marker %q:\n%s", want, upSQL)
		}
	}

	down, err := fs.ReadFile("037_malicious_active_exact_lookup_index.down.sql")
	if err != nil {
		t.Fatalf("read down migration: %v", err)
	}
	if downSQL := string(down); !strings.Contains(downSQL, "DROP INDEX IF EXISTS idx_malicious_active_exact_lookup;") {
		t.Fatalf("down migration missing active malicious exact-lookup index drop:\n%s", downSQL)
	}
}

func TestReputationActiveDashboardIndexMigrationDefinesExpectedIndexes(t *testing.T) {
	t.Parallel()

	up, err := fs.ReadFile("038_reputation_active_dashboard_indexes.up.sql")
	if err != nil {
		t.Fatalf("read up migration: %v", err)
	}
	upSQL := string(up)
	for _, want := range []string{
		"CREATE INDEX IF NOT EXISTS idx_reputation_active_package",
		"ON package_reputation_cache(ecosystem, name)",
		"WHERE status IN ('malicious', 'removed', 'risk');",
		"CREATE INDEX IF NOT EXISTS idx_reputation_active_status_severity",
		"ON package_reputation_cache(status, severity)",
		"WHERE status IN ('malicious', 'removed', 'risk');",
	} {
		if !strings.Contains(upSQL, want) {
			t.Fatalf("up migration missing active reputation dashboard marker %q:\n%s", want, upSQL)
		}
	}

	down, err := fs.ReadFile("038_reputation_active_dashboard_indexes.down.sql")
	if err != nil {
		t.Fatalf("read down migration: %v", err)
	}
	downSQL := string(down)
	for _, want := range []string{
		"DROP INDEX IF EXISTS idx_reputation_active_status_severity;",
		"DROP INDEX IF EXISTS idx_reputation_active_package;",
	} {
		if !strings.Contains(downSQL, want) {
			t.Fatalf("down migration missing active reputation dashboard index drop %q:\n%s", want, downSQL)
		}
	}
}

func TestPostgresIndexBatchMigrationDefinesExpectedChanges(t *testing.T) {
	t.Parallel()

	up, err := fs.ReadFile("043_postgres_index_batch.up.sql")
	if err != nil {
		t.Fatalf("read up migration: %v", err)
	}
	upSQL := strings.Join(strings.Fields(string(up)), " ")
	for _, want := range []string{
		"DROP INDEX IF EXISTS idx_admin_audit_digest;",
		"DROP INDEX IF EXISTS idx_api_keys_hash;",
		"DROP INDEX IF EXISTS idx_api_keys_expires_at;",
		"DROP INDEX IF EXISTS idx_api_keys_deleted_at;",
		"DROP INDEX IF EXISTS lifecycle_package_map_lookup_idx;",
		"DROP INDEX IF EXISTS idx_malicious_eco_name;",
		"DROP INDEX IF EXISTS idx_check_status_next;",
		"DROP INDEX IF EXISTS idx_scan_log_scan_id;",
		"DROP INDEX IF EXISTS idx_vuln_aliases_vuln_id;",
		"DROP INDEX IF EXISTS idx_vuln_sources_vuln_id;",
		"DROP INDEX IF EXISTS idx_vuln_refs_vuln_id;",
		"DROP INDEX IF EXISTS idx_affected_eco_name;",
		"CREATE INDEX IF NOT EXISTS idx_malicious_sync_keyset ON malicious_findings(ecosystem, name, id);",
		"CREATE INDEX IF NOT EXISTS idx_affected_sync_keyset ON affected_packages(ecosystem, name, vulnerability_id);",
		"DROP TABLE IF EXISTS scan_log_totals;",
		"CREATE VIEW scan_log_totals AS",
		"COALESCE(SUM(packages_count), 0)::BIGINT AS packages_scanned",
		"COALESCE(SUM(findings_count), 0)::BIGINT AS findings",
		"FROM scan_log;",
	} {
		if !strings.Contains(upSQL, want) {
			t.Fatalf("up migration missing index-batch marker %q:\n%s", want, upSQL)
		}
	}

	down, err := fs.ReadFile("043_postgres_index_batch.down.sql")
	if err != nil {
		t.Fatalf("read down migration: %v", err)
	}
	downSQL := strings.Join(strings.Fields(string(down)), " ")
	for _, want := range []string{
		"DROP VIEW IF EXISTS scan_log_totals;",
		"CREATE TABLE scan_log_totals",
		"CONSTRAINT scan_log_totals_singleton CHECK (id)",
		"INSERT INTO scan_log_totals (id, packages_scanned, findings)",
		"DROP INDEX IF EXISTS idx_malicious_sync_keyset;",
		"DROP INDEX IF EXISTS idx_affected_sync_keyset;",
		"CREATE INDEX IF NOT EXISTS idx_admin_audit_digest ON admin_audit_log(row_digest);",
		"CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);",
		"CREATE INDEX IF NOT EXISTS idx_api_keys_expires_at ON api_keys(expires_at) WHERE expires_at IS NOT NULL;",
		"CREATE INDEX IF NOT EXISTS idx_api_keys_deleted_at ON api_keys(deleted_at) WHERE deleted_at IS NOT NULL;",
		"CREATE INDEX IF NOT EXISTS lifecycle_package_map_lookup_idx ON lifecycle_package_map(ecosystem, name);",
		"CREATE INDEX IF NOT EXISTS idx_malicious_eco_name ON malicious_findings(ecosystem, name);",
		"CREATE INDEX IF NOT EXISTS idx_check_status_next ON package_check_status(source, next_check_at);",
		"CREATE INDEX IF NOT EXISTS idx_scan_log_scan_id ON scan_log(scan_id);",
		"CREATE INDEX IF NOT EXISTS idx_vuln_aliases_vuln_id ON vulnerability_aliases(vulnerability_id);",
		"CREATE INDEX IF NOT EXISTS idx_vuln_sources_vuln_id ON vulnerability_sources(vulnerability_id);",
		"CREATE INDEX IF NOT EXISTS idx_vuln_refs_vuln_id ON vulnerability_references(vulnerability_id);",
		"CREATE INDEX IF NOT EXISTS idx_affected_eco_name ON affected_packages(ecosystem, name);",
	} {
		if !strings.Contains(downSQL, want) {
			t.Fatalf("down migration missing index-batch marker %q:\n%s", want, downSQL)
		}
	}
}

func TestEmbeddedUpMigrationsAreSortedAndComplete(t *testing.T) {
	t.Parallel()

	migrations, err := embeddedUpMigrations()
	if err != nil {
		t.Fatalf("embeddedUpMigrations: %v", err)
	}
	if len(migrations) != ExpectedVersion {
		t.Fatalf("embedded up migration count = %d, want %d", len(migrations), ExpectedVersion)
	}
	for i, migration := range migrations {
		wantVersion := i + 1
		if migration.version != wantVersion {
			t.Fatalf("migration[%d].version = %d, want %d", i, migration.version, wantVersion)
		}
		if migration.name == "" || !strings.HasSuffix(migration.name, ".up.sql") {
			t.Fatalf("migration[%d].name = %q", i, migration.name)
		}
		if strings.TrimSpace(migration.sql) == "" {
			t.Fatalf("migration[%d].sql is empty", i)
		}
	}
}

func TestEmbeddedDownMigrationsAreReachableInRollbackOrder(t *testing.T) {
	t.Parallel()

	migrations, err := EmbeddedMigrations(MigrationDirectionDown)
	if err != nil {
		t.Fatalf("EmbeddedMigrations(down): %v", err)
	}
	if len(migrations) != ExpectedVersion {
		t.Fatalf("embedded down migration count = %d, want %d", len(migrations), ExpectedVersion)
	}
	for i, migration := range migrations {
		wantVersion := ExpectedVersion - i
		if migration.Version != wantVersion {
			t.Fatalf("migration[%d].Version = %d, want %d", i, migration.Version, wantVersion)
		}
		if migration.Direction != MigrationDirectionDown {
			t.Fatalf("migration[%d].Direction = %q, want %q", i, migration.Direction, MigrationDirectionDown)
		}
		if migration.Name == "" || !strings.HasSuffix(migration.Name, ".down.sql") {
			t.Fatalf("migration[%d].Name = %q", i, migration.Name)
		}
		if strings.TrimSpace(migration.SQL) == "" {
			t.Fatalf("migration[%d].SQL is empty", i)
		}
	}
}

func TestReadEmbeddedMigrationReadsSpecificDownMigration(t *testing.T) {
	t.Parallel()

	migration, err := ReadEmbeddedMigration(ExpectedVersion, MigrationDirectionDown)
	if err != nil {
		t.Fatalf("ReadEmbeddedMigration(%d, down): %v", ExpectedVersion, err)
	}
	if migration.Version != ExpectedVersion {
		t.Fatalf("Version = %d, want %d", migration.Version, ExpectedVersion)
	}
	if migration.Direction != MigrationDirectionDown {
		t.Fatalf("Direction = %q, want %q", migration.Direction, MigrationDirectionDown)
	}
	if !strings.HasPrefix(migration.Name, fmt.Sprintf("%03d_", ExpectedVersion)) ||
		!strings.HasSuffix(migration.Name, ".down.sql") {
		t.Fatalf("Name = %q, want current down migration", migration.Name)
	}
	if !strings.Contains(migration.SQL, "tombstone rows cannot be restored") {
		t.Fatalf("current down migration SQL does not include expected rollback marker:\n%s", migration.SQL)
	}
}

func TestDropScanLogClientMetadataMigrationDefinesRollback(t *testing.T) {
	t.Parallel()

	up, err := fs.ReadFile("040_drop_scan_log_client_metadata.up.sql")
	if err != nil {
		t.Fatalf("read up migration: %v", err)
	}
	upSQL := strings.Join(strings.Fields(string(up)), " ")
	for _, want := range []string{
		"DROP COLUMN IF EXISTS branch",
		"DROP COLUMN IF EXISTS commit",
		"DROP COLUMN IF EXISTS user_agent",
	} {
		if !strings.Contains(upSQL, want) {
			t.Fatalf("up migration missing %q:\n%s", want, upSQL)
		}
	}

	down, err := fs.ReadFile("040_drop_scan_log_client_metadata.down.sql")
	if err != nil {
		t.Fatalf("read down migration: %v", err)
	}
	downSQL := strings.Join(strings.Fields(string(down)), " ")
	for _, want := range []string{
		"ADD COLUMN IF NOT EXISTS branch TEXT",
		"ADD COLUMN IF NOT EXISTS commit TEXT",
		"ADD COLUMN IF NOT EXISTS user_agent TEXT",
	} {
		if !strings.Contains(downSQL, want) {
			t.Fatalf("down migration missing %q:\n%s", want, downSQL)
		}
	}
}

func TestNVDCVSSNegativeCacheMigrationDefinesTable(t *testing.T) {
	t.Parallel()

	up, err := fs.ReadFile("039_nvd_cvss_negative_cache.up.sql")
	if err != nil {
		t.Fatalf("read up migration: %v", err)
	}
	upSQL := strings.Join(strings.Fields(string(up)), " ")
	for _, want := range []string{
		"CREATE TABLE IF NOT EXISTS nvd_cvss_negative_cache",
		"cve_id TEXT PRIMARY KEY",
		"checked_at TIMESTAMPTZ NOT NULL DEFAULT NOW()",
		"vulnerability_updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()",
		"CREATE INDEX IF NOT EXISTS idx_nvd_cvss_negative_cache_checked_at",
		"ON nvd_cvss_negative_cache(checked_at)",
	} {
		if !strings.Contains(upSQL, want) {
			t.Fatalf("up migration missing NVD negative cache marker %q:\n%s", want, upSQL)
		}
	}

	down, err := fs.ReadFile("039_nvd_cvss_negative_cache.down.sql")
	if err != nil {
		t.Fatalf("read down migration: %v", err)
	}
	downSQL := strings.Join(strings.Fields(string(down)), " ")
	for _, forbidden := range []string{
		"DROP INDEX IF EXISTS idx_nvd_cvss_negative_cache_checked_at;",
		"DROP TABLE IF EXISTS nvd_cvss_negative_cache;",
	} {
		if strings.Contains(downSQL, forbidden) {
			t.Fatalf("down migration drops baseline-owned NVD negative cache object %q:\n%s", forbidden, downSQL)
		}
	}

	initial, err := fs.ReadFile("001_initial.up.sql")
	if err != nil {
		t.Fatalf("read initial schema: %v", err)
	}
	initialSQL := strings.Join(strings.Fields(string(initial)), " ")
	for _, want := range []string{
		"CREATE TABLE nvd_cvss_negative_cache",
		"CREATE INDEX idx_nvd_cvss_negative_cache_checked_at",
		"ON nvd_cvss_negative_cache(checked_at)",
	} {
		if !strings.Contains(initialSQL, want) {
			t.Fatalf("initial schema missing NVD negative cache marker %q", want)
		}
	}

	initialDown, err := fs.ReadFile("001_initial.down.sql")
	if err != nil {
		t.Fatalf("read initial down schema: %v", err)
	}
	if !strings.Contains(strings.Join(strings.Fields(string(initialDown)), " "), "DROP TABLE IF EXISTS nvd_cvss_negative_cache;") {
		t.Fatal("initial down schema missing NVD negative cache drop")
	}
}

func TestEmbeddedMigrationHelpersRejectInvalidInputs(t *testing.T) {
	t.Parallel()

	if _, err := EmbeddedMigrations(MigrationDirection("sideways")); err == nil {
		t.Fatal("EmbeddedMigrations(invalid direction) error = nil")
	}
	if _, err := ReadEmbeddedMigration(0, MigrationDirectionDown); err == nil {
		t.Fatal("ReadEmbeddedMigration(version 0) error = nil")
	}
	if _, err := ReadEmbeddedMigration(ExpectedVersion+1, MigrationDirectionDown); err == nil {
		t.Fatal("ReadEmbeddedMigration(missing version) error = nil")
	}
}

func TestVersionContextHonorsCanceledContext(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, _, err := VersionContext(ctx, "postgres://packmon:packmon@127.0.0.1:1/packmon?sslmode=disable")
	if err == nil || !strings.Contains(err.Error(), "context canceled") {
		t.Fatalf("VersionContext(canceled) error = %v, want context canceled", err)
	}
}

func TestRunContextHonorsCanceledContext(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := RunContext(ctx, "postgres://packmon:packmon@127.0.0.1:1/packmon?sslmode=disable")
	if err == nil || !strings.Contains(err.Error(), "context canceled") {
		t.Fatalf("RunContext(canceled) error = %v, want context canceled", err)
	}
}

func TestParseMigrationVersionRejectsInvalidFilenames(t *testing.T) {
	t.Parallel()

	if version, err := parseMigrationVersion("006_api_key_expiration.up.sql"); err != nil || version != 6 {
		t.Fatalf("parseMigrationVersion(valid) = %d, %v", version, err)
	}
	for _, name := range []string{"1.sql", "abc_name.up.sql"} {
		if _, err := parseMigrationVersion(name); err == nil {
			t.Fatalf("parseMigrationVersion(%q) error = nil", name)
		}
	}
}

func migrationCreateIndexNames(sql string) map[string]bool {
	names := map[string]bool{}
	re := regexp.MustCompile(`(?is)\bCREATE\s+(?:UNIQUE\s+)?INDEX\s+(?:IF\s+NOT\s+EXISTS\s+)?([a-zA-Z_][a-zA-Z0-9_]*)\b`)
	for _, match := range re.FindAllStringSubmatch(sql, -1) {
		names[strings.ToLower(match[1])] = true
	}
	return names
}

func migrationCreateIndexIfNotExistsNames(sql string) map[string]bool {
	names := map[string]bool{}
	re := regexp.MustCompile(`(?is)\bCREATE\s+(?:UNIQUE\s+)?INDEX\s+IF\s+NOT\s+EXISTS\s+([a-zA-Z_][a-zA-Z0-9_]*)\b`)
	for _, match := range re.FindAllStringSubmatch(sql, -1) {
		names[strings.ToLower(match[1])] = true
	}
	return names
}

func migrationCreateTableNames(sql string) map[string]bool {
	names := map[string]bool{}
	re := regexp.MustCompile(`(?is)\bCREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([a-zA-Z_][a-zA-Z0-9_]*)\b`)
	for _, match := range re.FindAllStringSubmatch(sql, -1) {
		names[strings.ToLower(match[1])] = true
	}
	return names
}

func migrationCreateTableIfNotExistsNames(sql string) map[string]bool {
	names := map[string]bool{}
	re := regexp.MustCompile(`(?is)\bCREATE\s+TABLE\s+IF\s+NOT\s+EXISTS\s+([a-zA-Z_][a-zA-Z0-9_]*)\b`)
	for _, match := range re.FindAllStringSubmatch(sql, -1) {
		names[strings.ToLower(match[1])] = true
	}
	return names
}

func migrationTableColumns(sql string) map[string]map[string]bool {
	columns := map[string]map[string]bool{}
	createTableRe := regexp.MustCompile(`(?is)\bCREATE\s+TABLE\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\((.*?)\);`)
	columnRe := regexp.MustCompile(`(?im)^\s*([a-zA-Z_][a-zA-Z0-9_]*)\s+`)
	for _, match := range createTableRe.FindAllStringSubmatch(sql, -1) {
		tableName := strings.ToLower(match[1])
		for _, line := range strings.Split(match[2], "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "--") {
				continue
			}
			columnMatch := columnRe.FindStringSubmatch(line)
			if len(columnMatch) == 0 {
				continue
			}
			columnName := strings.ToLower(columnMatch[1])
			switch columnName {
			case "constraint", "primary", "unique", "foreign", "check":
				continue
			}
			if columns[tableName] == nil {
				columns[tableName] = map[string]bool{}
			}
			columns[tableName][columnName] = true
		}
	}
	return columns
}

func migrationAddColumnIfNotExists(sql string) map[string]map[string]bool {
	columns := map[string]map[string]bool{}
	alterTableRe := regexp.MustCompile(`(?is)\bALTER\s+TABLE\s+([a-zA-Z_][a-zA-Z0-9_]*)\s+(.*?);`)
	addColumnRe := regexp.MustCompile(`(?is)\bADD\s+COLUMN\s+IF\s+NOT\s+EXISTS\s+([a-zA-Z_][a-zA-Z0-9_]*)\b`)
	for _, alterMatch := range alterTableRe.FindAllStringSubmatch(sql, -1) {
		tableName := strings.ToLower(alterMatch[1])
		for _, columnMatch := range addColumnRe.FindAllStringSubmatch(alterMatch[2], -1) {
			if columns[tableName] == nil {
				columns[tableName] = map[string]bool{}
			}
			columns[tableName][strings.ToLower(columnMatch[1])] = true
		}
	}
	return columns
}

func migrationDropIndexNames(sql string) []string {
	re := regexp.MustCompile(`(?is)\bDROP\s+INDEX\s+(?:IF\s+EXISTS\s+)?([a-zA-Z_][a-zA-Z0-9_]*)\b`)
	matches := re.FindAllStringSubmatch(sql, -1)
	names := make([]string, 0, len(matches))
	for _, match := range matches {
		names = append(names, strings.ToLower(match[1]))
	}
	return names
}

func migrationDropTableNames(sql string) []string {
	re := regexp.MustCompile(`(?is)\bDROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?([a-zA-Z_][a-zA-Z0-9_]*)\b`)
	matches := re.FindAllStringSubmatch(sql, -1)
	names := make([]string, 0, len(matches))
	for _, match := range matches {
		names = append(names, strings.ToLower(match[1]))
	}
	return names
}

func migrationDropColumns(sql string) map[string]map[string]bool {
	drops := map[string]map[string]bool{}
	alterTableRe := regexp.MustCompile(`(?is)\bALTER\s+TABLE\s+([a-zA-Z_][a-zA-Z0-9_]*)\s+(.*?);`)
	dropColumnRe := regexp.MustCompile(`(?is)\bDROP\s+COLUMN\s+(?:IF\s+EXISTS\s+)?([a-zA-Z_][a-zA-Z0-9_]*)\b`)
	for _, alterMatch := range alterTableRe.FindAllStringSubmatch(sql, -1) {
		tableName := strings.ToLower(alterMatch[1])
		for _, dropMatch := range dropColumnRe.FindAllStringSubmatch(alterMatch[2], -1) {
			if drops[tableName] == nil {
				drops[tableName] = map[string]bool{}
			}
			drops[tableName][strings.ToLower(dropMatch[1])] = true
		}
	}
	return drops
}
