package migrations

import (
	"reflect"
	"strings"
	"testing"
)

func TestF149F152EmbeddedSQLContracts(t *testing.T) {
	tests := []struct {
		name          string
		version       int
		direction     MigrationDirection
		transactional bool
		want          []string
	}{
		{
			name:          "021_up",
			version:       21,
			direction:     MigrationDirectionUp,
			transactional: false,
			want: []string{
				"CREATE EXTENSION IF NOT EXISTS pg_trgm",
				"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_affected_packages_name_trgm ON affected_packages USING gin (name gin_trgm_ops)",
				"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_malicious_findings_name_trgm ON malicious_findings USING gin (name gin_trgm_ops) WHERE removed_at IS NULL",
				"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_package_reputation_cache_name_trgm ON package_reputation_cache USING gin (name gin_trgm_ops)",
				"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_lifecycle_package_map_name_trgm ON lifecycle_package_map USING gin (name gin_trgm_ops)",
			},
		},
		{
			name:          "021_down",
			version:       21,
			direction:     MigrationDirectionDown,
			transactional: false,
			want: []string{
				"DROP INDEX CONCURRENTLY IF EXISTS idx_lifecycle_package_map_name_trgm",
				"DROP INDEX CONCURRENTLY IF EXISTS idx_package_reputation_cache_name_trgm",
				"DROP INDEX CONCURRENTLY IF EXISTS idx_malicious_findings_name_trgm",
				"DROP INDEX CONCURRENTLY IF EXISTS idx_affected_packages_name_trgm",
			},
		},
		{
			name:          "022_up",
			version:       22,
			direction:     MigrationDirectionUp,
			transactional: true,
			want: []string{
				"CREATE INDEX idx_queue_terminal_processed_at ON refresh_queue(COALESCE(processed_at, requested_at)) WHERE status IN ('done', 'error')",
			},
		},
		{
			name:          "022_down",
			version:       22,
			direction:     MigrationDirectionDown,
			transactional: true,
			want: []string{
				"DROP INDEX IF EXISTS idx_queue_terminal_processed_at",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			embedded, err := ReadEmbeddedMigration(tt.version, tt.direction)
			if err != nil {
				t.Fatalf("ReadEmbeddedMigration(%03d, %s) error = %v", tt.version, tt.direction, err)
			}
			migration := migrationFile{
				version:   embedded.Version,
				name:      embedded.Name,
				direction: embedded.Direction,
				sql:       embedded.SQL,
			}
			statements, err := splitSQLStatements(migration.sql)
			if err != nil {
				t.Fatalf("splitSQLStatements(%s) error = %v", migration.name, err)
			}
			got := make([]string, len(statements))
			for i, statement := range statements {
				got[i] = f149F152NormalizeSQLStatement(statement)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("%s statements = %#v, want exact ordered %#v", migration.name, got, tt.want)
			}
			if gotTransactional := migrationRunsInTransaction(migration); gotTransactional != tt.transactional {
				t.Fatalf("migrationRunsInTransaction(%s) = %t, want %t", migration.name, gotTransactional, tt.transactional)
			}
		})
	}
}

func f149F152NormalizeSQLStatement(statement string) string {
	lines := strings.Split(strings.TrimSuffix(statement, ";"), "\n")
	kept := lines[:0]
	for _, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "--") {
			continue
		}
		kept = append(kept, line)
	}
	return strings.Join(strings.Fields(strings.Join(kept, "\n")), " ")
}
