package migrations

import (
	"reflect"
	"strings"
	"testing"
)

func TestF189F190EmbeddedSQLContracts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		direction MigrationDirection
		want      []string
	}{
		{
			name:      "up",
			direction: MigrationDirectionUp,
			want: []string{
				"ALTER TABLE vulnerabilities DROP CONSTRAINT IF EXISTS vulnerabilities_cvss_score_range_check",
				"ALTER TABLE vulnerabilities DROP CONSTRAINT IF EXISTS vulnerabilities_epss_score_range_check",
				"ALTER TABLE vulnerabilities DROP CONSTRAINT IF EXISTS vulnerabilities_epss_percentile_range_check",
				"ALTER TABLE vulnerabilities ADD CONSTRAINT vulnerabilities_cvss_score_range_check CHECK (cvss_score IS NULL OR (cvss_score >= 0 AND cvss_score <= 10)) NOT VALID, ADD CONSTRAINT vulnerabilities_epss_score_range_check CHECK (epss_score IS NULL OR (epss_score >= 0 AND epss_score <= 1)) NOT VALID, ADD CONSTRAINT vulnerabilities_epss_percentile_range_check CHECK (epss_percentile IS NULL OR (epss_percentile >= 0 AND epss_percentile <= 1)) NOT VALID",
				"ALTER TABLE vulnerabilities VALIDATE CONSTRAINT vulnerabilities_cvss_score_range_check",
				"ALTER TABLE vulnerabilities VALIDATE CONSTRAINT vulnerabilities_epss_score_range_check",
				"ALTER TABLE vulnerabilities VALIDATE CONSTRAINT vulnerabilities_epss_percentile_range_check",
			},
		},
		{
			name:      "down",
			direction: MigrationDirectionDown,
			want: []string{
				"ALTER TABLE vulnerabilities DROP CONSTRAINT IF EXISTS vulnerabilities_epss_percentile_range_check",
				"ALTER TABLE vulnerabilities DROP CONSTRAINT IF EXISTS vulnerabilities_epss_score_range_check",
				"ALTER TABLE vulnerabilities DROP CONSTRAINT IF EXISTS vulnerabilities_cvss_score_range_check",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			embedded, err := ReadEmbeddedMigration(41, tt.direction)
			if err != nil {
				t.Fatalf("ReadEmbeddedMigration(041, %s): %v", tt.direction, err)
			}
			migration := migrationFile{
				version:   embedded.Version,
				name:      embedded.Name,
				direction: embedded.Direction,
				sql:       embedded.SQL,
			}
			if !migrationRunsInTransaction(migration) {
				t.Fatalf("migration 041 %s is not transactional", tt.direction)
			}

			statements, err := splitSQLStatements(embedded.SQL)
			if err != nil {
				t.Fatalf("splitSQLStatements(041, %s): %v", tt.direction, err)
			}
			got := make([]string, len(statements))
			for i, statement := range statements {
				got[i] = strings.Join(strings.Fields(statement), " ")
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("041 %s parsed statements changed\ngot:  %#v\nwant: %#v", tt.direction, got, tt.want)
			}
		})
	}
}
