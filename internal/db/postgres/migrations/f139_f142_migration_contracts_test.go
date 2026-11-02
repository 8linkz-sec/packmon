package migrations

import (
	"reflect"
	"strings"
	"testing"
)

func TestF139F142EmbeddedSQLContracts(t *testing.T) {
	tests := []struct {
		name      string
		version   int
		direction MigrationDirection
		want      []string
	}{
		{
			name:      "016_up",
			version:   16,
			direction: MigrationDirectionUp,
			want: []string{
				"ALTER TABLE admin_audit_log ADD COLUMN previous_digest TEXT NOT NULL DEFAULT '', ADD COLUMN row_digest TEXT NOT NULL DEFAULT ''",
				"CREATE INDEX idx_admin_audit_digest ON admin_audit_log(row_digest)",
			},
		},
		{
			name:      "016_down",
			version:   16,
			direction: MigrationDirectionDown,
			want: []string{
				"DROP INDEX IF EXISTS idx_admin_audit_digest",
				"ALTER TABLE admin_audit_log DROP COLUMN IF EXISTS row_digest, DROP COLUMN IF EXISTS previous_digest",
			},
		},
		{
			name:      "017_up",
			version:   17,
			direction: MigrationDirectionUp,
			want: []string{
				"CREATE INDEX idx_queue_listing_requested_at ON refresh_queue(requested_at DESC, id DESC)",
				"CREATE INDEX idx_queue_listing_status_requested_at ON refresh_queue(status, requested_at DESC, id DESC)",
			},
		},
		{
			name:      "017_down",
			version:   17,
			direction: MigrationDirectionDown,
			want: []string{
				"DROP INDEX IF EXISTS idx_queue_listing_status_requested_at",
				"DROP INDEX IF EXISTS idx_queue_listing_requested_at",
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
				t.Fatalf("migrationRunsInTransaction(%s) = false, want transactional two-statement migration", migration.name)
			}
		})
	}
}
