package migrations

import (
	"reflect"
	"strings"
	"testing"
)

func TestF165F170EmbeddedSQLContracts(t *testing.T) {
	allowedEcosystems := "'npm', 'pypi', 'go', 'maven', 'cargo', 'nuget', 'composer', 'gem', 'pub', 'cocoapods', 'swiftpm', 'hex', 'cran', 'actions', 'docker'"
	ecosystemUpdate := func(table, suffix string) string {
		return "UPDATE " + table + " SET ecosystem = LOWER(TRIM(ecosystem))" + suffix + " WHERE ecosystem IS DISTINCT FROM LOWER(TRIM(ecosystem)) AND LOWER(TRIM(ecosystem)) IN (" + allowedEcosystems + ")"
	}
	ecosystemConstraint := func(table string) string {
		name := table + "_ecosystem_check"
		return "IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = '" + name + "') THEN ALTER TABLE " + table + " ADD CONSTRAINT " + name + " CHECK (ecosystem IN (" + allowedEcosystems + ")) NOT VALID; END IF;"
	}
	doParts := []string{"DO $$ BEGIN"}
	for _, table := range []string{"affected_packages", "malicious_findings", "package_reputation_cache", "package_check_status", "refresh_queue", "lifecycle_package_map", "lifecycle_sync_tombstones"} {
		doParts = append(doParts, ecosystemConstraint(table))
	}
	doParts = append(doParts,
		"IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'malicious_findings_risk_type_check') THEN ALTER TABLE malicious_findings ADD CONSTRAINT malicious_findings_risk_type_check CHECK (risk_type IN ('malware', 'supply_chain', 'typosquatting')) NOT VALID; END IF;",
		"IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'vulnerability_sources_manual_id_check') THEN ALTER TABLE vulnerability_sources ADD CONSTRAINT vulnerability_sources_manual_id_check CHECK (source <> 'manual' OR (vulnerability_id LIKE 'manual:%' AND source_id LIKE 'manual:%')) NOT VALID; END IF;",
		"IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'malicious_findings_manual_id_check') THEN ALTER TABLE malicious_findings ADD CONSTRAINT malicious_findings_manual_id_check CHECK (source <> 'manual' OR id LIKE 'manual:%') NOT VALID; END IF;",
		"IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'refresh_queue_status_check') THEN ALTER TABLE refresh_queue ADD CONSTRAINT refresh_queue_status_check CHECK (status IN ('pending', 'processing', 'paused', 'done', 'error')) NOT VALID; END IF;",
		"IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'refresh_queue_priority_check') THEN ALTER TABLE refresh_queue ADD CONSTRAINT refresh_queue_priority_check CHECK (priority BETWEEN 0 AND 3) NOT VALID; END IF;",
		"END $$",
	)

	want031Up := []string{
		ecosystemUpdate("affected_packages", ""),
		ecosystemUpdate("malicious_findings", ", updated_at = NOW()"),
		ecosystemUpdate("package_reputation_cache", ", updated_at = NOW()"),
		ecosystemUpdate("package_check_status", ", updated_at = NOW()"),
		ecosystemUpdate("refresh_queue", ""),
		ecosystemUpdate("lifecycle_package_map", ", updated_at = NOW()"),
		ecosystemUpdate("lifecycle_sync_tombstones", ", updated_at = NOW()"),
		"UPDATE malicious_findings SET risk_type = CASE WHEN LOWER(TRIM(risk_type)) IN ('', 'malware') THEN 'malware' WHEN LOWER(TRIM(risk_type)) IN ('supply_chain', 'supply-chain', 'supply chain') THEN 'supply_chain' WHEN LOWER(TRIM(risk_type)) IN ('typosquatting', 'typosquat', 'typo-squatting') THEN 'typosquatting' ELSE 'malware' END, updated_at = NOW() WHERE risk_type IS DISTINCT FROM CASE WHEN LOWER(TRIM(risk_type)) IN ('', 'malware') THEN 'malware' WHEN LOWER(TRIM(risk_type)) IN ('supply_chain', 'supply-chain', 'supply chain') THEN 'supply_chain' WHEN LOWER(TRIM(risk_type)) IN ('typosquatting', 'typosquat', 'typo-squatting') THEN 'typosquatting' ELSE 'malware' END",
		"UPDATE refresh_queue SET status = LOWER(TRIM(status)) WHERE LOWER(TRIM(status)) IN ('pending', 'processing', 'paused', 'done', 'error') AND status IS DISTINCT FROM LOWER(TRIM(status))",
		"UPDATE refresh_queue SET status = 'error', processed_at = COALESCE(processed_at, NOW()), error = COALESCE(NULLIF(error, ''), 'normalized invalid queue status during migration 031') WHERE status NOT IN ('pending', 'processing', 'paused', 'done', 'error')",
		"UPDATE refresh_queue SET priority = CASE WHEN priority < 0 THEN 0 WHEN priority > 3 THEN 3 ELSE priority END WHERE priority < 0 OR priority > 3",
		strings.Join(doParts, " "),
	}
	for _, table := range []string{"affected_packages", "malicious_findings", "package_reputation_cache", "package_check_status", "refresh_queue", "lifecycle_package_map", "lifecycle_sync_tombstones"} {
		want031Up = append(want031Up, "ALTER TABLE "+table+" VALIDATE CONSTRAINT "+table+"_ecosystem_check")
	}
	want031Up = append(want031Up,
		"ALTER TABLE malicious_findings VALIDATE CONSTRAINT malicious_findings_risk_type_check",
		"ALTER TABLE vulnerability_sources VALIDATE CONSTRAINT vulnerability_sources_manual_id_check",
		"ALTER TABLE malicious_findings VALIDATE CONSTRAINT malicious_findings_manual_id_check",
		"ALTER TABLE refresh_queue VALIDATE CONSTRAINT refresh_queue_status_check",
		"ALTER TABLE refresh_queue VALIDATE CONSTRAINT refresh_queue_priority_check",
	)

	tests := []struct {
		name      string
		version   int
		direction MigrationDirection
		want      []string
		wantRaw   string
	}{
		{name: "029_up", version: 29, direction: MigrationDirectionUp, want: []string{"UPDATE api_keys SET name = '', key_hash = 'deleted:' || id::text WHERE deleted_at IS NOT NULL"}},
		{name: "029_down", version: 29, direction: MigrationDirectionDown, want: []string{""}, wantRaw: "-- Irreversible data minimization: deleted API-key labels and hashes are not restored.\n"},
		{name: "030_up", version: 30, direction: MigrationDirectionUp, want: []string{"ALTER TABLE scan_log ADD COLUMN IF NOT EXISTS client_version TEXT"}},
		{name: "030_down", version: 30, direction: MigrationDirectionDown, want: []string{"SELECT 1"}},
		{name: "031_up", version: 31, direction: MigrationDirectionUp, want: want031Up},
		{name: "031_down", version: 31, direction: MigrationDirectionDown, want: []string{
			"ALTER TABLE refresh_queue DROP CONSTRAINT IF EXISTS refresh_queue_priority_check",
			"ALTER TABLE refresh_queue DROP CONSTRAINT IF EXISTS refresh_queue_status_check",
			"ALTER TABLE malicious_findings DROP CONSTRAINT IF EXISTS malicious_findings_manual_id_check",
			"ALTER TABLE vulnerability_sources DROP CONSTRAINT IF EXISTS vulnerability_sources_manual_id_check",
			"ALTER TABLE malicious_findings DROP CONSTRAINT IF EXISTS malicious_findings_risk_type_check",
			"ALTER TABLE lifecycle_sync_tombstones DROP CONSTRAINT IF EXISTS lifecycle_sync_tombstones_ecosystem_check",
			"ALTER TABLE lifecycle_package_map DROP CONSTRAINT IF EXISTS lifecycle_package_map_ecosystem_check",
			"ALTER TABLE refresh_queue DROP CONSTRAINT IF EXISTS refresh_queue_ecosystem_check",
			"ALTER TABLE package_check_status DROP CONSTRAINT IF EXISTS package_check_status_ecosystem_check",
			"ALTER TABLE package_reputation_cache DROP CONSTRAINT IF EXISTS package_reputation_cache_ecosystem_check",
			"ALTER TABLE malicious_findings DROP CONSTRAINT IF EXISTS malicious_findings_ecosystem_check",
			"ALTER TABLE affected_packages DROP CONSTRAINT IF EXISTS affected_packages_ecosystem_check",
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			embedded, err := ReadEmbeddedMigration(tt.version, tt.direction)
			if err != nil {
				t.Fatalf("ReadEmbeddedMigration(%03d, %s) error = %v", tt.version, tt.direction, err)
			}
			if tt.wantRaw != "" && embedded.SQL != tt.wantRaw {
				t.Fatalf("%s raw SQL = %q, want exact comment-only %q", embedded.Name, embedded.SQL, tt.wantRaw)
			}
			migration := migrationFile{version: embedded.Version, name: embedded.Name, direction: embedded.Direction, sql: embedded.SQL}
			statements, err := splitSQLStatements(migration.sql)
			if err != nil {
				t.Fatalf("splitSQLStatements(%s) error = %v", migration.name, err)
			}
			got := make([]string, len(statements))
			for i, statement := range statements {
				got[i] = f165F170NormalizeSQL(statement)
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

func f165F170NormalizeSQL(statement string) string {
	lines := strings.Split(strings.TrimSuffix(statement, ";"), "\n")
	kept := lines[:0]
	for _, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "--") {
			continue
		}
		kept = append(kept, line)
	}
	normalized := strings.Join(strings.Fields(strings.Join(kept, "\n")), " ")
	normalized = strings.ReplaceAll(normalized, "( ", "(")
	normalized = strings.ReplaceAll(normalized, " )", ")")
	return normalized
}
