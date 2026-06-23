package migrations

import (
	"context"
	"fmt"
	iofs "io/fs"
	"path/filepath"
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
	for _, want := range []string{
		"DROP INDEX IF EXISTS idx_vulnerabilities_cisa_kev;",
		"DROP INDEX IF EXISTS idx_vuln_aliases_cve_alias;",
		"DROP INDEX IF EXISTS idx_vulnerabilities_nvd_candidate;",
	} {
		if !strings.Contains(downSQL, want) {
			t.Fatalf("down migration missing vulnerability enrichment index marker %q:\n%s", want, downSQL)
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
	if downSQL := string(down); !strings.Contains(downSQL, "DROP INDEX IF EXISTS idx_vuln_sources_source_vuln_id;") {
		t.Fatalf("down migration missing source-leading index drop:\n%s", downSQL)
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
	if downSQL := string(down); !strings.Contains(downSQL, "DROP INDEX IF EXISTS idx_lifecycle_package_map_product_slug;") {
		t.Fatalf("down migration missing lifecycle product_slug index drop:\n%s", downSQL)
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
		"CREATE INDEX IF NOT EXISTS idx_affected_packages_name_trgm",
		"ON affected_packages USING gin (name gin_trgm_ops);",
		"CREATE INDEX IF NOT EXISTS idx_malicious_findings_name_trgm",
		"ON malicious_findings USING gin (name gin_trgm_ops)",
		"WHERE removed_at IS NULL;",
		"CREATE INDEX IF NOT EXISTS idx_package_reputation_cache_name_trgm",
		"ON package_reputation_cache USING gin (name gin_trgm_ops);",
		"CREATE INDEX IF NOT EXISTS idx_lifecycle_package_map_name_trgm",
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
		"DROP INDEX IF EXISTS idx_lifecycle_package_map_name_trgm;",
		"DROP INDEX IF EXISTS idx_package_reputation_cache_name_trgm;",
		"DROP INDEX IF EXISTS idx_malicious_findings_name_trgm;",
		"DROP INDEX IF EXISTS idx_affected_packages_name_trgm;",
	} {
		if !strings.Contains(downSQL, want) {
			t.Fatalf("down migration missing package-search trigram marker %q:\n%s", want, downSQL)
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

func TestVersionContextHonorsCanceledContext(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, _, err := VersionContext(ctx, "postgres://packmon:packmon@127.0.0.1:1/packmon?sslmode=disable")
	if err == nil || !strings.Contains(err.Error(), "context canceled") {
		t.Fatalf("VersionContext(canceled) error = %v, want context canceled", err)
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
