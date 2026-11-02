package migrations

import (
	"strings"
	"testing"
)

func TestMigration011And012StatementContracts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		version       int
		direction     MigrationDirection
		transactional bool
		want          []string
	}{
		{
			name:          "011_up_exact_order",
			version:       11,
			direction:     MigrationDirectionUp,
			transactional: false,
			want: []string{
				"-- packmon:migration no-transaction\nCREATE INDEX CONCURRENTLY IF NOT EXISTS idx_vulnerabilities_updated_at ON vulnerabilities(updated_at)",
				"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_malicious_findings_updated_at ON malicious_findings(updated_at)",
				"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_package_reputation_cache_updated_at ON package_reputation_cache(updated_at)",
				"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_lifecycle_products_updated_at ON lifecycle_products(updated_at)",
				"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_lifecycle_releases_updated_at ON lifecycle_releases(updated_at)",
				"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_lifecycle_package_map_updated_at ON lifecycle_package_map(updated_at)",
				"CREATE TABLE IF NOT EXISTS lifecycle_sync_tombstones (\n    id           TEXT        PRIMARY KEY,\n    ecosystem    TEXT        NOT NULL,\n    name         TEXT        NOT NULL,\n    product_slug TEXT        NOT NULL,\n    cycle        TEXT        NOT NULL,\n    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()\n)",
				"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_lifecycle_sync_tombstones_updated_at\n    ON lifecycle_sync_tombstones(updated_at)",
			},
		},
		{
			name:          "011_down_exact_order",
			version:       11,
			direction:     MigrationDirectionDown,
			transactional: false,
			want: []string{
				"-- packmon:migration no-transaction\nDROP INDEX CONCURRENTLY IF EXISTS idx_lifecycle_sync_tombstones_updated_at",
				"DROP TABLE IF EXISTS lifecycle_sync_tombstones",
				"DROP INDEX CONCURRENTLY IF EXISTS idx_lifecycle_package_map_updated_at",
				"DROP INDEX CONCURRENTLY IF EXISTS idx_lifecycle_releases_updated_at",
				"DROP INDEX CONCURRENTLY IF EXISTS idx_lifecycle_products_updated_at",
				"DROP INDEX CONCURRENTLY IF EXISTS idx_package_reputation_cache_updated_at",
				"DROP INDEX CONCURRENTLY IF EXISTS idx_malicious_findings_updated_at",
				"DROP INDEX CONCURRENTLY IF EXISTS idx_vulnerabilities_updated_at",
			},
		},
		{
			name:          "012_up_exact_order",
			version:       12,
			direction:     MigrationDirectionUp,
			transactional: true,
			want: []string{
				"ALTER TABLE scan_log\n    ADD COLUMN IF NOT EXISTS api_key_id INTEGER,\n    ADD COLUMN IF NOT EXISTS api_key_name TEXT",
			},
		},
		{
			name:          "012_down_exact_order",
			version:       12,
			direction:     MigrationDirectionDown,
			transactional: true,
			want:          []string{"-- No-op: scan_log.api_key_id and scan_log.api_key_name are owned by 001_initial.\nSELECT 1"},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			embedded, err := ReadEmbeddedMigration(tt.version, tt.direction)
			if err != nil {
				t.Fatalf("ReadEmbeddedMigration(%d, %s): %v", tt.version, tt.direction, err)
			}
			migration := migrationFile{
				version:   embedded.Version,
				name:      embedded.Name,
				direction: embedded.Direction,
				sql:       embedded.SQL,
			}
			statements, err := splitSQLStatements(migration.sql)
			if err != nil {
				t.Fatalf("splitSQLStatements(%s): %v", migration.name, err)
			}
			if len(statements) != len(tt.want) {
				t.Fatalf("%s statement count = %d, want %d: %#v", migration.name, len(statements), len(tt.want), statements)
			}
			for i := range tt.want {
				got := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(statements[i]), ";"))
				if got != tt.want[i] {
					t.Fatalf("%s statement %d = %q, want %q", migration.name, i+1, got, tt.want[i])
				}
			}
			if got := migrationRunsInTransaction(migration); got != tt.transactional {
				t.Fatalf("migrationRunsInTransaction(%s) = %t, want %t", migration.name, got, tt.transactional)
			}
		})
	}
}
