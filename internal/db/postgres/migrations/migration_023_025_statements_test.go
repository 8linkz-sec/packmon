package migrations

import (
	"reflect"
	"strings"
	"testing"
)

func TestMigration023Through025StatementContracts(t *testing.T) {
	tests := []struct {
		name      string
		version   int
		direction MigrationDirection
		want      []string
	}{
		{
			name:      "023_up",
			version:   23,
			direction: MigrationDirectionUp,
			want:      []string{"CREATE INDEX idx_vulnerabilities_recent_published ON vulnerabilities(published DESC, id DESC) WHERE withdrawn IS NULL"},
		},
		{
			name:      "023_down",
			version:   23,
			direction: MigrationDirectionDown,
			want:      []string{"DROP INDEX IF EXISTS idx_vulnerabilities_recent_published"},
		},
		{
			name:      "024_up",
			version:   24,
			direction: MigrationDirectionUp,
			want: []string{
				"CREATE INDEX IF NOT EXISTS idx_vulnerabilities_nvd_candidate ON vulnerabilities(id) WHERE severity = 'UNKNOWN' OR (severity = 'LOW' AND cvss_score IS NULL)",
				"CREATE INDEX IF NOT EXISTS idx_vuln_aliases_cve_alias ON vulnerability_aliases(alias_id text_pattern_ops, vulnerability_id) WHERE alias_id LIKE 'CVE-%'",
				"CREATE INDEX IF NOT EXISTS idx_vulnerabilities_cisa_kev ON vulnerabilities(id) WHERE cisa_kev = TRUE",
			},
		},
		{
			name:      "024_down",
			version:   24,
			direction: MigrationDirectionDown,
			want:      []string{"-- No-op: vulnerability enrichment indexes are owned by 001_initial. SELECT 1"},
		},
		{
			name:      "025_up",
			version:   25,
			direction: MigrationDirectionUp,
			want: []string{
				"ALTER TABLE api_keys ADD COLUMN deleted_at TIMESTAMPTZ",
				"CREATE INDEX idx_api_keys_deleted_at ON api_keys(deleted_at) WHERE deleted_at IS NOT NULL",
			},
		},
		{
			name:      "025_down",
			version:   25,
			direction: MigrationDirectionDown,
			want: []string{
				"DROP INDEX IF EXISTS idx_api_keys_deleted_at",
				"ALTER TABLE api_keys DROP COLUMN IF EXISTS deleted_at",
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
