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

// TestListAPIKeysPageReturnsStableSlices covers the paged key listing used by the
// admin keys page. Pages must not overlap or skip a key, otherwise an operator
// reviewing keys for revocation can miss one entirely.
func TestListAPIKeysPageReturnsStableSlices(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()

	for _, name := range []string{"page-key-a", "page-key-b", "page-key-c"} {
		if _, err := store.CreateAPIKey(ctx, name, "hash-"+name, nil); err != nil {
			t.Fatalf("CreateAPIKey(%s): %v", name, err)
		}
	}

	all, err := store.ListAPIKeys(ctx)
	if err != nil {
		t.Fatalf("ListAPIKeys: %v", err)
	}
	if len(all) < 3 {
		t.Fatalf("ListAPIKeys returned %d keys, want at least the 3 just created", len(all))
	}

	first, err := store.ListAPIKeysPage(ctx, 2, 0)
	if err != nil {
		t.Fatalf("ListAPIKeysPage(2, 0): %v", err)
	}
	second, err := store.ListAPIKeysPage(ctx, 2, 2)
	if err != nil {
		t.Fatalf("ListAPIKeysPage(2, 2): %v", err)
	}
	if len(first) != 2 {
		t.Fatalf("first page holds %d keys, want 2", len(first))
	}
	if len(second) == 0 {
		t.Fatal("second page is empty although more keys exist")
	}
	for _, a := range first {
		for _, b := range second {
			if a.ID == b.ID {
				t.Fatalf("key %d appears on both pages", a.ID)
			}
		}
	}
	// The paged listing must agree with the unpaged one, in the same order.
	if first[0].ID != all[0].ID || first[1].ID != all[1].ID {
		t.Fatalf("page order %d,%d does not match the full listing %d,%d",
			first[0].ID, first[1].ID, all[0].ID, all[1].ID)
	}
}

// TestListAPIKeysPageRejectsNonPositiveLimit keeps an unbounded query out of the
// admin page: a limit of zero or less must return nothing rather than every key.
func TestListAPIKeysPageRejectsNonPositiveLimit(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()

	if _, err := store.CreateAPIKey(ctx, "limit-guard", "hash-limit-guard", nil); err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}
	for _, limit := range []int{0, -1} {
		got, err := store.ListAPIKeysPage(ctx, limit, 0)
		if err != nil {
			t.Fatalf("ListAPIKeysPage(%d, 0) error = %v", limit, err)
		}
		if len(got) != 0 {
			t.Fatalf("ListAPIKeysPage(%d, 0) returned %d keys, want none", limit, len(got))
		}
	}
	// A negative offset must be clamped, not passed through to SQL as an error.
	if _, err := store.ListAPIKeysPage(ctx, 5, -10); err != nil {
		t.Fatalf("ListAPIKeysPage with a negative offset error = %v", err)
	}
}

// TestImportMaliciousFeedWithAuditWritesAuditInsideTransaction covers the audited
// import path. The audit entry has to land in the same transaction as the import,
// so the recorded count can never describe rows that were rolled back.
func TestImportMaliciousFeedWithAuditWritesAuditInsideTransaction(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()

	var seenImported, seenDeleted int
	imported, deleted, err := store.ImportMaliciousFeedWithAudit(ctx, "socket", []db.MaliciousFinding{{
		ID:        "MAL-audit-1",
		Ecosystem: "npm",
		Name:      "audited-malicious",
		Source:    "socket",
		Severity:  "HIGH",
		Summary:   "audit fixture",
	}}, nil, nil, func(imported, deleted int) db.AdminAuditEntry {
		seenImported, seenDeleted = imported, deleted
		return db.AdminAuditEntry{Action: "feed.malicious.import", IP: "127.0.0.1"}
	})
	if err != nil {
		t.Fatalf("ImportMaliciousFeedWithAudit: %v", err)
	}
	if imported != 1 {
		t.Fatalf("imported = %d, want 1", imported)
	}
	if seenImported != imported || seenDeleted != deleted {
		t.Fatalf("audit callback saw (%d, %d), want the returned (%d, %d)",
			seenImported, seenDeleted, imported, deleted)
	}

	entries, err := store.ListAdminAuditLog(ctx, 20)
	if err != nil {
		t.Fatalf("ListAdminAuditLog: %v", err)
	}
	if !auditLogHasAction(entries, "feed.malicious.import") {
		t.Fatal("audited import wrote no admin audit entry")
	}
}

// TestImportMaliciousFeedWithoutAuditWritesNoAuditEntry covers the unaudited
// entry point: a feed import driven by the sync worker rather than an admin must
// not manufacture an admin audit trail. Passing a nil *builder* is the supported
// way to say "no audit"; a builder that runs must produce a usable entry.
func TestImportMaliciousFeedWithoutAuditWritesNoAuditEntry(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()

	if _, _, err := store.ImportMaliciousFeedWithAudit(ctx, "socket", []db.MaliciousFinding{{
		ID:        "MAL-unaudited",
		Ecosystem: "npm",
		Name:      "unaudited-malicious",
		Source:    "socket",
		Severity:  "HIGH",
		Summary:   "unaudited fixture",
	}}, nil, nil, nil); err != nil {
		t.Fatalf("ImportMaliciousFeedWithAudit(nil audit): %v", err)
	}

	entries, err := store.ListAdminAuditLog(ctx, 20)
	if err != nil {
		t.Fatalf("ListAdminAuditLog: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("unaudited import wrote %d audit entries, want 0", len(entries))
	}
}

// TestImportMaliciousFeedWithAuditRollsBackOnAnAnonymousAuditEntry pins the
// fail-closed contract end to end.
//
// The builder can no longer return nothing -- db.FeedImportAuditBuilder returns a
// value, so that state is gone at the type level. What remains reachable is the
// zero value: an entry with no action. The audit column is NOT NULL but accepts
// "", so without the guard the import would commit alongside a nameless audit row
// that records nothing. It must fail under db.ErrAdminAuditLog and leave no
// findings behind, or the audit log becomes bypassable from the call site.
func TestImportMaliciousFeedWithAuditRollsBackOnAnAnonymousAuditEntry(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()

	_, _, err := store.ImportMaliciousFeedWithAudit(ctx, "socket", []db.MaliciousFinding{{
		ID:        "MAL-nil-audit",
		Ecosystem: "npm",
		Name:      "nil-audit-malicious",
		Source:    "socket",
		Severity:  "HIGH",
		Summary:   "nil audit fixture",
	}}, nil, nil, func(int, int) db.AdminAuditEntry { return db.AdminAuditEntry{} })
	if err == nil {
		t.Fatal("ImportMaliciousFeedWithAudit(anonymous entry) error = nil, want a refusal")
	}
	if !errors.Is(err, db.ErrAdminAuditLog) {
		t.Fatalf("error = %v, want it to match db.ErrAdminAuditLog", err)
	}

	found, err := store.FindMalicious(ctx, "npm", "nil-audit-malicious", "1.0.0")
	if err != nil {
		t.Fatalf("FindMalicious: %v", err)
	}
	if len(found) != 0 {
		t.Fatalf("import committed %d findings despite the failed audit", len(found))
	}
}

// TestPruneMaliciousFindingsForSourceUpdatedBeforeIsScopedToItsSource covers the
// retention sweep. Pruning must remove only stale rows of the named source; a
// wrong scope would silently delete another feed's live malware findings.
func TestPruneMaliciousFindingsForSourceUpdatedBeforeIsScopedToItsSource(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()

	for _, item := range []db.MaliciousFinding{
		{ID: "MAL-prune-old", Ecosystem: "npm", Name: "prune-old", Source: "socket", Severity: "HIGH", Summary: "old"},
		{ID: "MAL-prune-other", Ecosystem: "npm", Name: "prune-other", Source: "osv", Severity: "HIGH", Summary: "other source"},
	} {
		if _, _, err := store.ImportMaliciousFeed(ctx, item.Source, []db.MaliciousFinding{item}, nil, nil); err != nil {
			t.Fatalf("ImportMaliciousFeed(%s): %v", item.Source, err)
		}
	}

	// Nothing is older than the epoch, so a cutoff in the past must delete nothing.
	pruned, err := store.PruneMaliciousFindingsForSourceUpdatedBefore(ctx, "socket", time.Unix(0, 0).UTC())
	if err != nil {
		t.Fatalf("PruneMaliciousFindingsForSourceUpdatedBefore(past cutoff): %v", err)
	}
	if pruned != 0 {
		t.Fatalf("past cutoff pruned %d rows, want 0", pruned)
	}

	// A cutoff in the future makes every socket row stale, but must not touch osv.
	pruned, err = store.PruneMaliciousFindingsForSourceUpdatedBefore(ctx, "socket", time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatalf("PruneMaliciousFindingsForSourceUpdatedBefore(future cutoff): %v", err)
	}
	if pruned == 0 {
		t.Fatal("future cutoff pruned nothing, want the stale socket rows removed")
	}

	remaining, err := store.FindMalicious(ctx, "npm", "prune-other", "1.0.0")
	if err != nil {
		t.Fatalf("FindMalicious(other source): %v", err)
	}
	if len(remaining) == 0 {
		t.Fatal("pruning the socket source also removed the osv finding")
	}
}

// TestEnqueueRefreshWithAuditRecordsTheQueuePosition covers the audited enqueue
// used by the admin queue form. The callback has to see the same position the
// caller gets, otherwise the audit log and the UI disagree about the queue.
func TestEnqueueRefreshWithAuditRecordsTheQueuePosition(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()

	var seenCreated bool
	var seenPosition int
	created, position, err := store.EnqueueRefreshWithAudit(ctx, &db.RefreshJob{
		Ecosystem: "npm",
		Name:      "audited-refresh",
		Source:    "admin",
		Priority:  db.RefreshPriorityManual,
	}, func(created bool, position int) db.AdminAuditEntry {
		seenCreated, seenPosition = created, position
		return db.AdminAuditEntry{Action: "queue.enqueue", IP: "127.0.0.1"}
	})
	if err != nil {
		t.Fatalf("EnqueueRefreshWithAudit: %v", err)
	}
	if !created {
		t.Fatal("EnqueueRefreshWithAudit reported no new job for an empty queue")
	}
	if seenCreated != created || seenPosition != position {
		t.Fatalf("audit callback saw (%v, %d), want the returned (%v, %d)",
			seenCreated, seenPosition, created, position)
	}
	if position < 1 {
		t.Fatalf("queue position = %d, want a 1-based position", position)
	}

	entries, err := store.ListAdminAuditLog(ctx, 20)
	if err != nil {
		t.Fatalf("ListAdminAuditLog: %v", err)
	}
	if !auditLogHasAction(entries, "queue.enqueue") {
		t.Fatal("audited enqueue wrote no admin audit entry")
	}
}

// TestEnqueueRefreshNoPositionSkipsTheCountingQuery covers the cheap variant used
// on the scan hot path. It must still deduplicate against a pending job, because
// that is the only thing protecting the queue from one entry per scanned package.
func TestEnqueueRefreshNoPositionSkipsTheCountingQuery(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()

	job := &db.RefreshJob{Ecosystem: "npm", Name: "hot-path-refresh", Source: "scan", Priority: db.RefreshPriorityNormal}
	created, err := store.EnqueueRefreshNoPosition(ctx, job)
	if err != nil {
		t.Fatalf("EnqueueRefreshNoPosition: %v", err)
	}
	if !created {
		t.Fatal("first EnqueueRefreshNoPosition reported no new job")
	}

	again, err := store.EnqueueRefreshNoPosition(ctx, &db.RefreshJob{
		Ecosystem: "npm",
		Name:      "hot-path-refresh",
		Source:    "scan",
		Priority:  db.RefreshPriorityNormal,
	})
	if err != nil {
		t.Fatalf("second EnqueueRefreshNoPosition: %v", err)
	}
	if again {
		t.Fatal("duplicate EnqueueRefreshNoPosition created a second pending job")
	}
}

// TestCompleteClaimedRefreshRecordsBothOutcomes covers the worker's completion
// call. A finished job must leave the pending queue in both the success and the
// failure case -- a job stuck in `processing` blocks its package forever.
func TestCompleteClaimedRefreshRecordsBothOutcomes(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()

	for _, tc := range []struct {
		name   string
		pkg    string
		jobErr error
	}{
		{name: "success", pkg: "complete-ok"},
		{name: "failure", pkg: "complete-failed", jobErr: context.DeadlineExceeded},
	} {
		if _, _, err := store.EnqueueRefresh(ctx, &db.RefreshJob{
			Ecosystem: "npm", Name: tc.pkg, Source: "scan", Priority: db.RefreshPriorityNormal,
		}); err != nil {
			t.Fatalf("%s: EnqueueRefresh: %v", tc.name, err)
		}

		claimed, err := store.DequeueRefresh(ctx, "scan")
		if err != nil {
			t.Fatalf("%s: DequeueRefresh: %v", tc.name, err)
		}
		if claimed == nil {
			t.Fatalf("%s: DequeueRefresh returned no job", tc.name)
		}
		if err := store.CompleteClaimedRefresh(ctx, claimed.ID, claimed.ProcessedAt, tc.jobErr); err != nil {
			t.Fatalf("%s: CompleteClaimedRefresh: %v", tc.name, err)
		}

		next, err := store.DequeueRefresh(ctx, "scan")
		if err != nil {
			t.Fatalf("%s: DequeueRefresh after completion: %v", tc.name, err)
		}
		if next != nil && next.ID == claimed.ID {
			t.Fatalf("%s: completed job %d was handed out again", tc.name, claimed.ID)
		}
	}
}

// TestCompleteClaimedRefreshRequiresTheClaimTimestamp covers the guard that makes
// the completion conditional. Without the claim timestamp the UPDATE would match
// on the job ID alone, letting a stale worker overwrite a job another worker has
// since re-claimed.
func TestCompleteClaimedRefreshRequiresTheClaimTimestamp(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()

	err := store.CompleteClaimedRefresh(ctx, 1, nil, nil)
	if err == nil {
		t.Fatal("CompleteClaimedRefresh(nil claim timestamp) error = nil, want a refusal")
	}
	if !strings.Contains(err.Error(), "claim timestamp") {
		t.Fatalf("error = %v, want it to name the missing claim timestamp", err)
	}
}

// TestCompleteClaimedRefreshIgnoresAMismatchedClaim is the behavioural half of
// the same guard: completing with the wrong timestamp must not touch the row.
func TestCompleteClaimedRefreshIgnoresAMismatchedClaim(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()

	if _, _, err := store.EnqueueRefresh(ctx, &db.RefreshJob{
		Ecosystem: "npm", Name: "stale-claim", Source: "scan", Priority: db.RefreshPriorityNormal,
	}); err != nil {
		t.Fatalf("EnqueueRefresh: %v", err)
	}
	claimed, err := store.DequeueRefresh(ctx, "scan")
	if err != nil || claimed == nil {
		t.Fatalf("DequeueRefresh = %v, %v; want a claimed job", claimed, err)
	}

	stale := time.Unix(0, 0).UTC()
	if err := store.CompleteClaimedRefresh(ctx, claimed.ID, &stale, nil); err != nil {
		t.Fatalf("CompleteClaimedRefresh(stale claim) error = %v, want a silent no-op", err)
	}

	// The real claim must still be able to complete the job.
	if err := store.CompleteClaimedRefresh(ctx, claimed.ID, claimed.ProcessedAt, nil); err != nil {
		t.Fatalf("CompleteClaimedRefresh(real claim): %v", err)
	}
}

// TestRepairCaseInsensitivePackageNamesLeavesCleanDataAlone covers the repair
// pass that runs on startup. On a database without duplicate-cased rows it must
// be a no-op: a repair that rewrites healthy rows is worse than none.
func TestRepairCaseInsensitivePackageNamesLeavesCleanDataAlone(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()

	repaired, err := store.RepairCaseInsensitivePackageNames(ctx)
	if err != nil {
		t.Fatalf("RepairCaseInsensitivePackageNames: %v", err)
	}
	if repaired != 0 {
		t.Fatalf("repair touched %d rows on a clean database, want 0", repaired)
	}

	// Running it a second time must stay idempotent.
	again, err := store.RepairCaseInsensitivePackageNames(ctx)
	if err != nil {
		t.Fatalf("second RepairCaseInsensitivePackageNames: %v", err)
	}
	if again != 0 {
		t.Fatalf("second repair touched %d rows, want 0", again)
	}
}

// TestRepairCaseInsensitivePackageNamesWithAuditRecordsEveryRun pins the audited
// startup repair. The audit row is written unconditionally and carries the count,
// so the log answers "did the repair run?" and not merely "did it change data?" --
// a repair that silently skipped its run would otherwise be indistinguishable
// from one that found nothing.
func TestRepairCaseInsensitivePackageNamesWithAuditRecordsEveryRun(t *testing.T) {
	store, _ := startDockerPostgresStore(t)
	ctx := context.Background()

	repaired, err := store.RepairCaseInsensitivePackageNamesWithAudit(ctx,
		&db.AdminAuditEntry{Action: "maintenance.repair_names", IP: "127.0.0.1"})
	if err != nil {
		t.Fatalf("RepairCaseInsensitivePackageNamesWithAudit: %v", err)
	}
	if repaired != 0 {
		t.Fatalf("repair touched %d rows on a clean database, want 0", repaired)
	}

	entries, err := store.ListAdminAuditLog(ctx, 20)
	if err != nil {
		t.Fatalf("ListAdminAuditLog: %v", err)
	}
	var entry *db.AdminAuditLogEntry
	for i := range entries {
		if entries[i].Action == "maintenance.repair_names" {
			entry = &entries[i]
			break
		}
	}
	if entry == nil {
		t.Fatal("audited repair wrote no admin audit entry")
	}
	// The column is jsonb, so compare parsed values rather than raw text.
	var details map[string]string
	if err := json.Unmarshal(entry.Details, &details); err != nil {
		t.Fatalf("audit details %s are not a JSON object: %v", entry.Details, err)
	}
	if details["repaired"] != "0" {
		t.Fatalf("audit details = %s, want repaired=0 recorded", entry.Details)
	}
	// The IP column is a network type, so PostgreSQL reads the address back with
	// its prefix length attached.
	if !strings.HasPrefix(entry.IP, "127.0.0.1") {
		t.Fatalf("audit IP = %q, want the supplied 127.0.0.1", entry.IP)
	}
}

func auditLogHasAction(entries []db.AdminAuditLogEntry, action string) bool {
	for _, entry := range entries {
		if strings.EqualFold(entry.Action, action) {
			return true
		}
	}
	return false
}
