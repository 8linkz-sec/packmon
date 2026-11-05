package sqlite

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestF226MigrateSchemaPropagatesLaterStageFailures(t *testing.T) {
	tests := []struct {
		name     string
		contains string
		skip     int
		want     string
	}{
		{
			name:     "malicious column inspection",
			contains: "PRAGMA table_info",
			skip:     5,
			want:     "inspect table malicious_local",
		},
		{
			name:     "scan history column inspection",
			contains: "PRAGMA table_info",
			skip:     8,
			want:     "inspect table scan_history",
		},
		{
			name:     "package name normalization",
			contains: "FROM malicious_local",
			want:     "inspect malicious_local package names",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			database, rule := openFaultyDB(t, tc.contains, tc.skip)
			seedLegacySchemaOn(t, database, schemaSQL)

			err := migrateSchema(database)
			if !errors.Is(err, errInjectedFault) {
				t.Fatalf("migrateSchema() error = %v, want injected fault", err)
			}
			if !rule.didFire() {
				t.Fatal("the injected fault did not fire")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("migrateSchema() error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestF226RowKeyMigrationRollsBackFailedStatement(t *testing.T) {
	database, rule := openFaultyDB(t, "RENAME TO vulnerabilities_local_old", 0)
	seedLegacySchemaOn(t, database, `CREATE TABLE vulnerabilities_local (
		id TEXT NOT NULL,
		ecosystem TEXT NOT NULL,
		name TEXT NOT NULL,
		version_ranges TEXT,
		severity TEXT NOT NULL,
		cvss_score REAL,
		epss_score REAL,
		cisa_kev INTEGER DEFAULT 0,
		summary TEXT
	)`)

	err := migrateVulnerabilityRowKeys(database)
	if !errors.Is(err, errInjectedFault) || !strings.Contains(err.Error(), "migrate schema") {
		t.Fatalf("migrateVulnerabilityRowKeys() error = %v, want injected migration fault", err)
	}
	if !rule.didFire() {
		t.Fatal("the injected fault did not fire")
	}
	if exists, inspectErr := tableExists(database, "vulnerabilities_local"); inspectErr != nil || !exists {
		t.Fatalf("vulnerabilities_local after rollback = %v, %v; want original table", exists, inspectErr)
	}
	if exists, inspectErr := tableExists(database, "vulnerabilities_local_old"); inspectErr != nil || exists {
		t.Fatalf("vulnerabilities_local_old after rollback = %v, %v; want no renamed table", exists, inspectErr)
	}
}

func TestF226HistoryColumnFailureAndDuplicateCleanupFailure(t *testing.T) {
	t.Run("history commit column", func(t *testing.T) {
		database, rule := openFaultyDB(t, "ALTER TABLE scan_history ADD COLUMN", 0)
		seedLegacySchemaOn(t, database, `CREATE TABLE scan_history (
			id INTEGER PRIMARY KEY,
			repo_name TEXT,
			scanned_at TEXT NOT NULL,
			findings_count INTEGER NOT NULL DEFAULT 0
		)`)

		err := ensureScanHistorySchema(database)
		if !errors.Is(err, errInjectedFault) || !strings.Contains(err.Error(), "commit column") {
			t.Fatalf("ensureScanHistorySchema() error = %v, want commit-column fault", err)
		}
		if !rule.didFire() {
			t.Fatal("the injected fault did not fire")
		}
	})

	t.Run("normalized vulnerability duplicate cleanup", func(t *testing.T) {
		database, rule := openFaultyDB(t, "DELETE FROM vulnerabilities_local", 0)
		seedLegacySchemaOn(t, database, legacyVulnerabilitiesTable,
			`INSERT INTO vulnerabilities_local (row_key, id, ecosystem, name, severity)
			 VALUES ('legacy-row', 'GHSA-test', 'PyPI', 'Django', 'HIGH')`)

		err := normalizeExistingVulnerabilityPackageNames(database)
		if !errors.Is(err, errInjectedFault) || !strings.Contains(err.Error(), "remove duplicate normalized vulnerability row") {
			t.Fatalf("normalizeExistingVulnerabilityPackageNames() error = %v, want duplicate-cleanup fault", err)
		}
		if !rule.didFire() {
			t.Fatal("the injected fault did not fire")
		}
	})
}

func TestF226ColumnEnsurersPropagateEveryInspectionFailure(t *testing.T) {
	tests := []struct {
		name   string
		seed   string
		run    func(*testing.T, string, int) error
		probes int
	}{
		{
			name: "vulnerability columns",
			seed: legacyVulnerabilitiesTable,
			run: func(t *testing.T, seed string, skip int) error {
				database, rule := openFaultyDB(t, "PRAGMA table_info", skip)
				seedLegacySchemaOn(t, database, seed)
				err := ensureVulnerabilityLocalColumns(database)
				if !rule.didFire() {
					t.Fatal("the injected fault did not fire")
				}
				return err
			},
			probes: 4,
		},
		{
			name: "malicious columns",
			seed: `CREATE TABLE malicious_local (
				id TEXT PRIMARY KEY,
				ecosystem TEXT NOT NULL,
				name TEXT NOT NULL
			)`,
			run: func(t *testing.T, seed string, skip int) error {
				database, rule := openFaultyDB(t, "PRAGMA table_info", skip)
				seedLegacySchemaOn(t, database, seed)
				err := ensureMaliciousLocalColumns(database)
				if !rule.didFire() {
					t.Fatal("the injected fault did not fire")
				}
				return err
			},
			probes: 3,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for skip := 0; skip < tc.probes; skip++ {
				t.Run(fmt.Sprintf("probe_%d", skip+1), func(t *testing.T) {
					if err := tc.run(t, tc.seed, skip); !errors.Is(err, errInjectedFault) {
						t.Fatalf("inspection %d error = %v, want injected fault", skip+1, err)
					}
				})
			}
		})
	}
}
