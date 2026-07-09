package postgres

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
)

func TestQueueClearUsesDBRefreshStatusHelper(t *testing.T) {
	t.Parallel()

	source := string(readRefreshQueueAdminSource(t))
	if strings.Contains(source, "func normalizeQueueStatuses") {
		t.Fatal("postgres queue code still defines a local status normalization wrapper; use db.NormalizeClearableRefreshStatuses directly")
	}
	if strings.Count(source, "db.NormalizeClearableRefreshStatuses") < 3 {
		t.Fatal("postgres queue clear paths should delegate clearable status policy to internal/db")
	}
}

func TestCountScansByDayQueryUsesScannedAtRange(t *testing.T) {
	t.Parallel()

	text := countScansByDaySQL
	if strings.Contains(text, "timezone('UTC', scan_log.scanned_at)::date = days.day") {
		t.Fatal("CountScansByDay must not wrap scan_log.scanned_at in a date expression; keep the scanned_at index usable")
	}
	for _, want := range []string{
		"scan_log.scanned_at >= days.day",
		"scan_log.scanned_at < days.day + INTERVAL '1 day'",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("CountScansByDay query missing sargable range marker %q", want)
		}
	}
}

func TestSearchPackagesUsesFindingTypeCollectors(t *testing.T) {
	t.Parallel()

	got := packageSearchCollectorPlan("")
	want := []packageSearchCollector{
		packageSearchCollectorVulnerability,
		packageSearchCollectorMalicious,
		packageSearchCollectorReputationMalicious,
		packageSearchCollectorReputationSupplyChain,
		packageSearchCollectorLifecycleEOL,
		packageSearchCollectorLifecycleWarning,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("packageSearchCollectorPlan(\"\") = %#v, want %#v", got, want)
	}

	got = packageSearchCollectorPlan("vulnerability")
	want = []packageSearchCollector{
		packageSearchCollectorVulnerability,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("packageSearchCollectorPlan(\"vulnerability\") = %#v, want %#v", got, want)
	}
}

func TestAdminAuthAuditMutationsUseConsistentLockOrderAndCAS(t *testing.T) {
	t.Parallel()

	got := adminAuthAuditMutationSteps()
	want := []adminAuthAuditMutationStep{
		adminAuthAuditStepLockAuth,
		adminAuthAuditStepMutate,
		adminAuthAuditStepInsertAudit,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("adminAuthAuditMutationSteps() = %#v, want %#v", got, want)
	}
	if !strings.Contains(changeAdminPasswordSQL, "WHERE id = 1 AND password_hash = $2") {
		t.Fatal("changeAdminPasswordSQL must keep password-hash compare-and-swap predicate")
	}
	if !strings.Contains(lockAdminAuthForMutationSQL, "FOR UPDATE") {
		t.Fatal("lockAdminAuthForMutationSQL must lock admin_auth before audit mutation")
	}
	if !strings.Contains(insertAdminAuditLogLockSQL, "LOCK TABLE admin_audit_log") {
		t.Fatal("insertAdminAuditLogTx must retain explicit admin_audit_log lock")
	}
}

func TestExportSyncLifecycleUsesIndexableTimestampFilters(t *testing.T) {
	t.Parallel()

	since := time.Unix(1700000000, 0).UTC()
	query, _, err := buildExportSyncLifecycleQuery(db.SyncExportOptions{Since: &since}, since.Add(time.Hour), 0)
	if err != nil {
		t.Fatalf("build lifecycle sync query: %v", err)
	}
	if strings.Contains(query, "GREATEST(m.updated_at, p.updated_at, r.updated_at)") {
		t.Fatal("exportSyncLifecycle must not filter lifecycle deltas through a cross-table GREATEST timestamp expression")
	}
	for _, want := range []string{
		"m.updated_at <= $1",
		"p.updated_at <= $1",
		"r.updated_at <= $1",
		"m.updated_at >= $2",
		"p.updated_at >= $2",
		"r.updated_at >= $2",
	} {
		if !strings.Contains(query, want) {
			t.Fatalf("exportSyncLifecycle query missing indexable lifecycle timestamp marker %q", want)
		}
	}
}

func TestExportSyncVulnerabilitiesUsesIndexableTimestampFilters(t *testing.T) {
	t.Parallel()

	since := time.Unix(1700000000, 0).UTC()
	query, _, err := buildExportSyncVulnerabilitiesQuery(db.SyncExportOptions{Since: &since}, since.Add(time.Hour), 0)
	if err != nil {
		t.Fatalf("build vulnerability sync query: %v", err)
	}
	if strings.Contains(query, "GREATEST(v.updated_at, ap.updated_at)") {
		t.Fatal("exportSyncVulnerabilities must not filter deltas through a cross-table GREATEST timestamp expression")
	}
	for _, want := range []string{
		"v.updated_at <= $1",
		"ap.updated_at <= $1",
		"v.updated_at >= $2",
		"ap.updated_at >= $2",
	} {
		if !strings.Contains(query, want) {
			t.Fatalf("exportSyncVulnerabilities query missing indexable timestamp marker %q", want)
		}
	}
}
