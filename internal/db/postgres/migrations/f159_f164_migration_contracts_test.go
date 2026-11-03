package migrations

import (
	"reflect"
	"strings"
	"testing"
)

func TestF159F164EmbeddedSQLContracts(t *testing.T) {
	tests := []struct {
		name      string
		version   int
		direction MigrationDirection
		want      []string
	}{
		{
			name: "026_up", version: 26, direction: MigrationDirectionUp,
			want: []string{
				"ALTER TABLE scan_log ADD COLUMN IF NOT EXISTS idempotency_key TEXT, ADD COLUMN IF NOT EXISTS request_digest TEXT NOT NULL DEFAULT ''",
				"CREATE UNIQUE INDEX IF NOT EXISTS idx_scan_log_idempotency_key ON scan_log(idempotency_key) WHERE idempotency_key IS NOT NULL",
			},
		},
		{
			name: "026_down", version: 26, direction: MigrationDirectionDown,
			want: []string{
				"DROP INDEX IF EXISTS idx_scan_log_idempotency_key",
				"ALTER TABLE scan_log DROP COLUMN IF EXISTS request_digest, DROP COLUMN IF EXISTS idempotency_key",
			},
		},
		{
			name: "027_up", version: 27, direction: MigrationDirectionUp,
			want: []string{
				"UPDATE vulnerabilities SET severity = 'LOW', updated_at = NOW() WHERE TRIM(severity) = '' OR UPPER(TRIM(severity)) = 'UNKNOWN'",
				"UPDATE vulnerabilities SET severity = UPPER(TRIM(severity)), updated_at = NOW() WHERE severity IS DISTINCT FROM UPPER(TRIM(severity)) AND UPPER(TRIM(severity)) IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')",
				"UPDATE vulnerabilities SET severity = 'LOW', updated_at = NOW() WHERE severity NOT IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')",
				"UPDATE malicious_findings SET severity = COALESCE(NULLIF(UPPER(TRIM(severity)), ''), 'UNKNOWN'), updated_at = NOW() WHERE severity IS DISTINCT FROM COALESCE(NULLIF(UPPER(TRIM(severity)), ''), 'UNKNOWN') AND COALESCE(NULLIF(UPPER(TRIM(severity)), ''), 'UNKNOWN') IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN')",
				"UPDATE malicious_findings SET severity = 'UNKNOWN', updated_at = NOW() WHERE severity NOT IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN')",
				"UPDATE package_reputation_cache SET severity = CASE WHEN TRIM(severity) = '' OR UPPER(TRIM(severity)) = 'UNKNOWN' THEN 'CRITICAL' ELSE UPPER(TRIM(severity)) END, updated_at = NOW() WHERE severity IS DISTINCT FROM CASE WHEN TRIM(severity) = '' OR UPPER(TRIM(severity)) = 'UNKNOWN' THEN 'CRITICAL' ELSE UPPER(TRIM(severity)) END AND CASE WHEN TRIM(severity) = '' OR UPPER(TRIM(severity)) = 'UNKNOWN' THEN 'CRITICAL' ELSE UPPER(TRIM(severity)) END IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')",
				"UPDATE package_reputation_cache SET severity = 'CRITICAL', updated_at = NOW() WHERE severity NOT IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')",
				"ALTER TABLE vulnerabilities DROP CONSTRAINT IF EXISTS vulnerabilities_severity_check",
				"ALTER TABLE malicious_findings DROP CONSTRAINT IF EXISTS malicious_findings_severity_check",
				"ALTER TABLE package_reputation_cache DROP CONSTRAINT IF EXISTS package_reputation_cache_severity_check",
				"ALTER TABLE vulnerabilities ADD CONSTRAINT vulnerabilities_severity_check CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')) NOT VALID",
				"ALTER TABLE malicious_findings ADD CONSTRAINT malicious_findings_severity_check CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN')) NOT VALID",
				"ALTER TABLE package_reputation_cache ADD CONSTRAINT package_reputation_cache_severity_check CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')) NOT VALID",
				"ALTER TABLE vulnerabilities VALIDATE CONSTRAINT vulnerabilities_severity_check",
				"ALTER TABLE malicious_findings VALIDATE CONSTRAINT malicious_findings_severity_check",
				"ALTER TABLE package_reputation_cache VALIDATE CONSTRAINT package_reputation_cache_severity_check",
			},
		},
		{
			name: "027_down", version: 27, direction: MigrationDirectionDown,
			want: []string{
				"ALTER TABLE package_reputation_cache DROP CONSTRAINT IF EXISTS package_reputation_cache_severity_check",
				"ALTER TABLE malicious_findings DROP CONSTRAINT IF EXISTS malicious_findings_severity_check",
				"ALTER TABLE vulnerabilities DROP CONSTRAINT IF EXISTS vulnerabilities_severity_check",
			},
		},
		{
			name: "028_up", version: 28, direction: MigrationDirectionUp,
			want: []string{"CREATE INDEX IF NOT EXISTS idx_package_check_status_socket_updated_at ON package_check_status(updated_at) WHERE source = 'socket'"},
		},
		{
			name: "028_down", version: 28, direction: MigrationDirectionDown,
			want: []string{"SELECT 1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			embedded, err := ReadEmbeddedMigration(tt.version, tt.direction)
			if err != nil {
				t.Fatalf("ReadEmbeddedMigration(%03d, %s) error = %v", tt.version, tt.direction, err)
			}
			migration := migrationFile{version: embedded.Version, name: embedded.Name, direction: embedded.Direction, sql: embedded.SQL}
			statements, err := splitSQLStatements(migration.sql)
			if err != nil {
				t.Fatalf("splitSQLStatements(%s) error = %v", migration.name, err)
			}
			got := make([]string, len(statements))
			for i, statement := range statements {
				got[i] = f159F164NormalizeSQL(statement)
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

func f159F164NormalizeSQL(statement string) string {
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
