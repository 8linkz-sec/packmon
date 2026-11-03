//go:build integration

package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
)

func TestPackageNameRepairAuditFailuresRollBackRepairs(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()
	legacyTime := time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)

	seedStatements := []struct {
		sql  string
		args []any
	}{
		{
			sql: `INSERT INTO vulnerabilities(id, summary, severity, published, modified, updated_at)
				VALUES ('PYSEC-f204-audit-rollback', 'F204 repair rollback', 'HIGH', $1, $1, $1)`,
			args: []any{legacyTime},
		},
		{
			sql: `INSERT INTO affected_packages(vulnerability_id, ecosystem, name, version_ranges, versions_affected)
				VALUES ('PYSEC-f204-audit-rollback', 'pypi', ' F204.Pkg_Name ', '[]'::jsonb, '["1.0.0"]'::jsonb)`,
		},
		{
			sql: `INSERT INTO malicious_findings(
					id, ecosystem, name, version_ranges, versions, source, risk_type, severity,
					summary, reference_urls, created_by, created_at, updated_at
				)
				VALUES
					('MAL-f204-audit-rollback', 'pypi', ' F204.Evil_Pkg ', NULL, NULL,
					 'openssf', 'malware', 'CRITICAL', 'F204 malicious repair', '[]'::jsonb,
					 'feed', $1, $1),
					('MAL-f204-empty-name', 'pypi', E' \t ', NULL, NULL,
					 'openssf', 'malware', 'CRITICAL', 'F204 empty canonical name', '[]'::jsonb,
					 'feed', $1, $1)`,
			args: []any{legacyTime},
		},
	}
	for _, statement := range seedStatements {
		if _, err := store.pool.Exec(ctx, statement.sql, statement.args...); err != nil {
			t.Fatalf("seed package-name repair fixtures: %v", err)
		}
	}

	generation := dashboardStatsCacheGeneration(store)
	assertRolledBack := func(t *testing.T, label string, repaired int, err error, wantSubstring string) {
		t.Helper()
		if repaired != 0 {
			t.Fatalf("%s repair count = %d, want 0", label, repaired)
		}
		if err == nil || !strings.Contains(err.Error(), wantSubstring) {
			t.Fatalf("%s repair error = %v, want %q", label, err, wantSubstring)
		}
		assertF204PackageNameRepairState(t, store, false, legacyTime)
		if got := dashboardStatsCacheGeneration(store); got != generation {
			t.Fatalf("cache generation after %s rollback = %d, want %d", label, got, generation)
		}
		var auditRows int
		if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM admin_audit_log`).Scan(&auditRows); err != nil {
			t.Fatalf("count audit rows after %s rollback: %v", label, err)
		}
		if auditRows != 0 {
			t.Fatalf("audit rows after %s rollback = %d, want 0", label, auditRows)
		}
	}

	lockConn, err := store.pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire package-name repair lock blocker: %v", err)
	}
	if _, err := lockConn.Exec(ctx, `SELECT pg_advisory_lock($1)`, openssfSnapshotLockKey); err != nil {
		lockConn.Release()
		t.Fatalf("hold package-name repair lock: %v", err)
	}
	for _, audited := range []bool{false, true} {
		label := "lock failure"
		if audited {
			label = "audited lock failure"
		}
		t.Run(label, func(t *testing.T) {
			readyConn, err := store.pool.Acquire(ctx)
			if err != nil {
				t.Fatalf("prewarm repair connection: %v", err)
			}
			var repairPID int
			if err := readyConn.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&repairPID); err != nil {
				readyConn.Release()
				t.Fatalf("read prewarmed repair backend: %v", err)
			}
			readyConn.Release()

			type repairResult struct {
				repaired int
				err      error
			}
			lockCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			result := make(chan repairResult, 1)
			go func() {
				var outcome repairResult
				if audited {
					outcome.repaired, outcome.err = store.RepairCaseInsensitivePackageNamesWithAudit(lockCtx, &db.AdminAuditEntry{Action: "startup_package_name_repair"})
				} else {
					outcome.repaired, outcome.err = store.RepairCaseInsensitivePackageNames(lockCtx)
				}
				result <- outcome
			}()

			waitDeadline := time.Now().Add(3 * time.Second)
			blockedOnAdvisoryLock := false
			for !blockedOnAdvisoryLock && time.Now().Before(waitDeadline) {
				if err := lockConn.QueryRow(ctx, `
					SELECT EXISTS (
						SELECT 1
						FROM pg_stat_activity
						WHERE pid = $1
						  AND wait_event_type = 'Lock'
						  AND wait_event = 'advisory'
						  AND query LIKE '%pg_advisory_xact_lock%'
					)`, repairPID).Scan(&blockedOnAdvisoryLock); err != nil {
					cancel()
					<-result
					t.Fatalf("observe repair advisory-lock wait: %v", err)
				}
				if !blockedOnAdvisoryLock {
					time.Sleep(10 * time.Millisecond)
				}
			}
			if !blockedOnAdvisoryLock {
				cancel()
				outcome := <-result
				t.Fatalf("repair backend %d never reached advisory-lock wait; result = (%d, %v)", repairPID, outcome.repaired, outcome.err)
			}

			cancel()
			outcome := <-result
			assertRolledBack(t, label, outcome.repaired, outcome.err, "acquire OpenSSF finding source lock")
			if !errors.Is(outcome.err, context.Canceled) {
				t.Fatalf("%s error = %v, want context canceled after observed advisory-lock wait", label, outcome.err)
			}
		})
	}
	var unlocked bool
	if err := lockConn.QueryRow(ctx, `SELECT pg_advisory_unlock($1)`, openssfSnapshotLockKey).Scan(&unlocked); err != nil || !unlocked {
		lockConn.Release()
		t.Fatalf("release package-name repair lock blocker = %v, %v", unlocked, err)
	}
	lockConn.Release()

	if _, err := store.pool.Exec(ctx, `
		CREATE FUNCTION packmon_test_f204_reject_affected_repair() RETURNS trigger
		LANGUAGE plpgsql AS $$
		BEGIN
			RAISE EXCEPTION 'F204 affected repair rejected';
		END
		$$;
		CREATE TRIGGER packmon_test_f204_reject_affected_repair
		BEFORE INSERT ON affected_packages
		FOR EACH ROW
		WHEN (NEW.vulnerability_id = 'PYSEC-f204-audit-rollback')
		EXECUTE FUNCTION packmon_test_f204_reject_affected_repair()`); err != nil {
		t.Fatalf("install affected repair fault: %v", err)
	}
	for _, audited := range []bool{false, true} {
		label := "affected phase failure"
		var repaired int
		var err error
		if audited {
			label = "audited affected phase failure"
			repaired, err = store.RepairCaseInsensitivePackageNamesWithAudit(ctx, &db.AdminAuditEntry{Action: "startup_package_name_repair"})
		} else {
			repaired, err = store.RepairCaseInsensitivePackageNames(ctx)
		}
		assertRolledBack(t, label, repaired, err, "F204 affected repair rejected")
	}
	if _, err := store.pool.Exec(ctx, `
		DROP TRIGGER packmon_test_f204_reject_affected_repair ON affected_packages;
		DROP FUNCTION packmon_test_f204_reject_affected_repair()`); err != nil {
		t.Fatalf("remove affected repair fault: %v", err)
	}

	if _, err := store.pool.Exec(ctx, `
		CREATE FUNCTION packmon_test_f204_reject_malicious_repair() RETURNS trigger
		LANGUAGE plpgsql AS $$
		BEGIN
			RAISE EXCEPTION 'F204 malicious repair rejected';
		END
		$$;
		CREATE TRIGGER packmon_test_f204_reject_malicious_repair
		BEFORE UPDATE OF name ON malicious_findings
		FOR EACH ROW
		WHEN (OLD.id = 'MAL-f204-audit-rollback')
		EXECUTE FUNCTION packmon_test_f204_reject_malicious_repair()`); err != nil {
		t.Fatalf("install malicious repair fault: %v", err)
	}
	repaired, err := store.RepairCaseInsensitivePackageNamesWithAudit(ctx, &db.AdminAuditEntry{Action: "startup_package_name_repair"})
	assertRolledBack(t, "audited malicious phase failure", repaired, err, "F204 malicious repair rejected")
	if _, err := store.pool.Exec(ctx, `
		DROP TRIGGER packmon_test_f204_reject_malicious_repair ON malicious_findings;
		DROP FUNCTION packmon_test_f204_reject_malicious_repair()`); err != nil {
		t.Fatalf("remove malicious repair fault: %v", err)
	}

	tests := []struct {
		name          string
		audit         *db.AdminAuditEntry
		wantSentinel  error
		wantSubstring string
	}{
		{
			name:          "nil audit",
			wantSentinel:  db.ErrAdminAuditLog,
			wantSubstring: errNilAdminAuditEntry.Error(),
		},
		{
			name:          "malformed audit details",
			audit:         &db.AdminAuditEntry{Action: "startup_package_name_repair", Details: json.RawMessage(`{`)},
			wantSubstring: "postgres: prepare package name repair audit",
		},
		{
			name:          "anonymous audit",
			audit:         &db.AdminAuditEntry{Action: "  "},
			wantSentinel:  db.ErrAdminAuditLog,
			wantSubstring: errAnonymousAdminAuditEntry.Error(),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			repaired, err := store.RepairCaseInsensitivePackageNamesWithAudit(ctx, tc.audit)
			assertRolledBack(t, tc.name, repaired, err, tc.wantSubstring)
			if tc.wantSentinel != nil && !errors.Is(err, tc.wantSentinel) {
				t.Fatalf("failed audited repair error = %v, want errors.Is(%v)", err, tc.wantSentinel)
			}
		})
	}

	audit := &db.AdminAuditEntry{
		Action:  "startup_package_name_repair",
		Details: json.RawMessage(`null`),
	}
	repaired, err = store.RepairCaseInsensitivePackageNamesWithAudit(ctx, audit)
	if err != nil {
		t.Fatalf("RepairCaseInsensitivePackageNamesWithAudit(null details): %v", err)
	}
	if repaired != 3 {
		t.Fatalf("RepairCaseInsensitivePackageNamesWithAudit(null details) = %d, want 3", repaired)
	}
	if got := dashboardStatsCacheGeneration(store); got != generation+1 {
		t.Fatalf("cache generation after committed audited repair = %d, want %d", got, generation+1)
	}
	assertF204PackageNameRepairState(t, store, true, legacyTime)

	entries, err := store.ListAdminAuditLog(ctx, 2)
	if err != nil {
		t.Fatalf("ListAdminAuditLog after repair: %v", err)
	}
	if len(entries) != 1 || entries[0].Action != audit.Action || entries[0].IntegrityStatus != db.AdminAuditIntegrityVerified {
		t.Fatalf("repair audit entries = %+v, want one verified startup audit", entries)
	}
	var details map[string]string
	if err := json.Unmarshal(entries[0].Details, &details); err != nil {
		t.Fatalf("repair audit details = %s: %v", entries[0].Details, err)
	}
	if len(details) != 1 || details["repaired"] != "3" {
		t.Fatalf("repair audit details = %#v, want only repaired=3", details)
	}
}

func assertF204PackageNameRepairState(t *testing.T, store *Store, committed bool, legacyTime time.Time) {
	t.Helper()

	ctx := context.Background()
	wantAffected, forbiddenAffected := " F204.Pkg_Name ", "f204-pkg-name"
	wantMalicious := " F204.Evil_Pkg "
	if committed {
		wantAffected, forbiddenAffected = forbiddenAffected, wantAffected
		wantMalicious = "f204-evil-pkg"
	}

	var affectedRows, wantedAffectedRows, forbiddenAffectedRows int
	if err := store.pool.QueryRow(ctx, `
		SELECT count(*),
		       count(*) FILTER (WHERE name = $1),
		       count(*) FILTER (WHERE name = $2)
		FROM affected_packages
		WHERE vulnerability_id = 'PYSEC-f204-audit-rollback'`, wantAffected, forbiddenAffected).Scan(
		&affectedRows, &wantedAffectedRows, &forbiddenAffectedRows,
	); err != nil {
		t.Fatalf("count affected package-name repair rows: %v", err)
	}
	if affectedRows != 1 || wantedAffectedRows != 1 || forbiddenAffectedRows != 0 {
		t.Fatalf("affected repair rows = total %d, wanted %q %d, forbidden %q %d; want 1, 1, 0", affectedRows, wantAffected, wantedAffectedRows, forbiddenAffected, forbiddenAffectedRows)
	}

	var affectedRanges, affectedVersions string
	if err := store.pool.QueryRow(ctx, `
		SELECT version_ranges::text, versions_affected::text
		FROM affected_packages
		WHERE vulnerability_id = 'PYSEC-f204-audit-rollback' AND name = $1`, wantAffected).Scan(
		&affectedRanges, &affectedVersions,
	); err != nil {
		t.Fatalf("read exact affected package-name repair row %q: %v", wantAffected, err)
	}
	if affectedRanges != `[]` || affectedVersions != `["1.0.0"]` {
		t.Fatalf("affected repair JSON = (%s, %s), want ([], [\"1.0.0\"])", affectedRanges, affectedVersions)
	}

	var vulnerabilityUpdated time.Time
	if err := store.pool.QueryRow(ctx, `
		SELECT updated_at FROM vulnerabilities WHERE id = 'PYSEC-f204-audit-rollback'`).Scan(&vulnerabilityUpdated); err != nil {
		t.Fatalf("read repaired vulnerability timestamp: %v", err)
	}
	if committed == vulnerabilityUpdated.Equal(legacyTime) {
		t.Fatalf("vulnerability updated_at = %v with committed=%v, want seed timestamp preserved on rollback and advanced on commit", vulnerabilityUpdated, committed)
	}

	var maliciousName, maliciousReferences string
	var maliciousRangesNull, maliciousVersionsNull bool
	var maliciousUpdated time.Time
	if err := store.pool.QueryRow(ctx, `
		SELECT name, version_ranges IS NULL, versions IS NULL, reference_urls::text, updated_at
		FROM malicious_findings
		WHERE id = 'MAL-f204-audit-rollback'`).Scan(
		&maliciousName, &maliciousRangesNull, &maliciousVersionsNull, &maliciousReferences, &maliciousUpdated,
	); err != nil {
		t.Fatalf("read exact malicious package-name repair row: %v", err)
	}
	if maliciousName != wantMalicious || !maliciousRangesNull || !maliciousVersionsNull || maliciousReferences != `[]` {
		t.Fatalf("malicious repair row = name %q, ranges-null %v, versions-null %v, references %s; want %q, true, true, []", maliciousName, maliciousRangesNull, maliciousVersionsNull, maliciousReferences, wantMalicious)
	}
	if committed == maliciousUpdated.Equal(legacyTime) {
		t.Fatalf("malicious updated_at = %v with committed=%v, want seed timestamp preserved on rollback and advanced on commit", maliciousUpdated, committed)
	}

	var emptyName, emptyReferences string
	var emptyRangesNull, emptyVersionsNull bool
	var emptyUpdated time.Time
	if err := store.pool.QueryRow(ctx, `
		SELECT name, version_ranges IS NULL, versions IS NULL, reference_urls::text, updated_at
		FROM malicious_findings
		WHERE id = 'MAL-f204-empty-name'`).Scan(
		&emptyName, &emptyRangesNull, &emptyVersionsNull, &emptyReferences, &emptyUpdated,
	); err != nil {
		t.Fatalf("read empty-name malicious fixture: %v", err)
	}
	if emptyName != " \t " || !emptyRangesNull || !emptyVersionsNull || emptyReferences != `[]` || !emptyUpdated.Equal(legacyTime) {
		t.Fatalf("empty canonical malicious row = name %q, ranges-null %v, versions-null %v, references %s, updated %v; want untouched whitespace, NULL, NULL, [], %v", emptyName, emptyRangesNull, emptyVersionsNull, emptyReferences, emptyUpdated, legacyTime)
	}
}
