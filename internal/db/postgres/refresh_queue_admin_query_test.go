package postgres

import (
	"os"
	"strings"
	"testing"

	"github.com/8linkz-sec/packmon/internal/db"
)

func TestOldestQueueJobsQueryMatchesActiveSourceRequestedAtIndex(t *testing.T) {
	t.Parallel()

	data := readRefreshQueueAdminSource(t)
	source := string(data)
	start := strings.Index(source, "func (s *Store) OldestQueueJobs")
	end := strings.Index(source, "func (s *Store) ListQueueJobs")
	if start < 0 || end < 0 || end <= start {
		t.Fatal("could not locate OldestQueueJobs query block")
	}
	oldestQueueJobs := source[start:end]
	for _, want := range []string{
		"db.DrainableRefreshStatusPredicateSQL()",
		"AND source <> ''",
		"GROUP BY source",
	} {
		if !strings.Contains(oldestQueueJobs, want) {
			t.Fatalf("OldestQueueJobs query missing %q", want)
		}
	}
	if strings.Contains(oldestQueueJobs, "status IN ('pending', 'processing')") {
		t.Fatal("OldestQueueJobs embeds drainable refresh statuses instead of using the db helper")
	}
	if got, want := db.DrainableRefreshStatusPredicateSQL(), "status IN ('pending', 'processing')"; got != want {
		t.Fatalf("DrainableRefreshStatusPredicateSQL() = %q, want %q", got, want)
	}
}

func TestQueueClearAndPurgeAuditDeleteUsesReturningRows(t *testing.T) {
	t.Parallel()

	data := readRefreshQueueAdminSource(t)
	source := string(data)

	for name, next := range map[string]string{
		"PurgeQueueWithAudit": "func purgeQueueTx",
		"ClearQueueWithAudit": "func deleteQueueJobsForStatusesWithAuditSampleTx",
	} {
		block := sourceBlockAnyEnd(t, source, "func (s *Store) "+name, []string{next, "func queueJobsForStatusesTx", "func clearQueueTx"})
		if !strings.Contains(block, "deleteQueueJobsForStatusesWithAuditSampleTx") {
			t.Fatalf("%s must build audit details from the DELETE ... RETURNING helper", name)
		}
		for _, forbidden := range []string{
			"queueJobsForStatusesTx",
			"purgeQueueTx(ctx, tx)",
			"clearQueueTx(ctx, tx",
		} {
			if strings.Contains(block, forbidden) {
				t.Fatalf("%s still uses separate snapshot/delete path %q", name, forbidden)
			}
		}
	}

	helper := sourceBlock(t, source, "func deleteQueueJobsForStatusesWithAuditSampleTx", "type queueAuditSampleRow")
	for _, want := range []string{
		"WITH deleted AS",
		"DELETE FROM refresh_queue",
		"RETURNING id, ecosystem, name, source, priority, status, requested_at, processed_at, error",
		"SELECT COUNT(*)::int AS total_deleted FROM deleted",
		"FROM deleted",
		"ORDER BY id",
		"LIMIT $2",
	} {
		if !strings.Contains(helper, want) {
			t.Fatalf("delete queue audit helper missing %q", want)
		}
	}
	if strings.Contains(helper, "SELECT id, ecosystem, name, source, priority, status, requested_at, processed_at, error\n\t\tFROM refresh_queue") {
		t.Fatal("delete queue audit helper still selects audit rows from refresh_queue instead of DELETE ... RETURNING")
	}
}

func sourceBlock(t *testing.T, source, startMarker, endMarker string) string {
	t.Helper()

	start := strings.Index(source, startMarker)
	end := strings.Index(source, endMarker)
	if start < 0 || end < 0 || end <= start {
		t.Fatalf("could not locate source block from %q to %q", startMarker, endMarker)
	}
	return source[start:end]
}

func sourceBlockAnyEnd(t *testing.T, source, startMarker string, endMarkers []string) string {
	t.Helper()

	start := strings.Index(source, startMarker)
	if start < 0 {
		t.Fatalf("could not locate source block start %q", startMarker)
	}
	end := -1
	for _, marker := range endMarkers {
		idx := strings.Index(source[start+len(startMarker):], marker)
		if idx < 0 {
			continue
		}
		idx += start + len(startMarker)
		if end < 0 || idx < end {
			end = idx
		}
	}
	if end < 0 || end <= start {
		t.Fatalf("could not locate source block end after %q", startMarker)
	}
	return source[start:end]
}

func readRefreshQueueAdminSource(t *testing.T) []byte {
	t.Helper()

	for _, path := range []string{"refresh_queue_admin.go", "admin_stats.go"} {
		//nolint:gosec // G304: path built by the test itself, not from request data.
		data, err := os.ReadFile(path)
		if err == nil {
			return data
		}
	}
	t.Fatal("read refresh queue admin queries: neither refresh_queue_admin.go nor admin_stats.go exists")
	return nil
}
