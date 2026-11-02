package migrations

import (
	"reflect"
	"strings"
	"testing"
)

func TestMigration018Through020StatementContracts(t *testing.T) {
	tests := []struct {
		name      string
		version   int
		direction MigrationDirection
		want      []string
	}{
		{
			name:      "018_up",
			version:   18,
			direction: MigrationDirectionUp,
			want: []string{
				"CREATE TABLE scan_log_totals ( id BOOLEAN PRIMARY KEY DEFAULT TRUE, packages_scanned BIGINT NOT NULL DEFAULT 0 CHECK (packages_scanned >= 0), findings BIGINT NOT NULL DEFAULT 0 CHECK (findings >= 0), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), CONSTRAINT scan_log_totals_singleton CHECK (id) )",
				"INSERT INTO scan_log_totals (id, packages_scanned, findings) SELECT TRUE, COALESCE(SUM(packages_count), 0), COALESCE(SUM(findings_count), 0) FROM scan_log",
			},
		},
		{
			name:      "018_down",
			version:   18,
			direction: MigrationDirectionDown,
			want:      []string{"DROP TABLE IF EXISTS scan_log_totals"},
		},
		{
			name:      "019_up",
			version:   19,
			direction: MigrationDirectionUp,
			want:      []string{"CREATE INDEX IF NOT EXISTS idx_vuln_sources_source_vuln_id ON vulnerability_sources(source, vulnerability_id) WHERE raw_json IS NOT NULL"},
		},
		{
			name:      "019_down",
			version:   19,
			direction: MigrationDirectionDown,
			want:      []string{"-- No-op: idx_vuln_sources_source_vuln_id is owned by 001_initial. SELECT 1"},
		},
		{
			name:      "020_up",
			version:   20,
			direction: MigrationDirectionUp,
			want:      []string{"CREATE INDEX IF NOT EXISTS idx_lifecycle_package_map_product_slug ON lifecycle_package_map(product_slug)"},
		},
		{
			name:      "020_down",
			version:   20,
			direction: MigrationDirectionDown,
			want:      []string{"-- No-op: idx_lifecycle_package_map_product_slug is owned by 001_initial. SELECT 1"},
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
				got[i] = strings.Join(strings.Fields(strings.TrimSuffix(statement, ";")), " ")
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("%s statements = %#v, want exact ordered %#v", migration.name, got, tt.want)
			}
			if !migrationRunsInTransaction(migration) {
				t.Fatalf("migrationRunsInTransaction(%s) = false, want transactional migration", migration.name)
			}
		})
	}
}
