package postgres

import (
	"os"
	"strings"
	"testing"
)

func TestFeedImportDeletesDoNotRefreshExistingTombstones(t *testing.T) {
	vulnerabilitySource, err := os.ReadFile("vulnerabilities.go")
	if err != nil {
		t.Fatalf("read vulnerabilities.go: %v", err)
	}
	vulnerabilityText := string(vulnerabilitySource)

	for i, tail := range strings.Split(vulnerabilityText, "SET withdrawn = COALESCE(withdrawn, NOW())")[1:] {
		window := tail
		if len(window) > 500 {
			window = window[:500]
		}
		if !strings.Contains(window, "AND withdrawn IS NULL") {
			t.Fatalf("vulnerability tombstone update %d refreshes updated_at for already withdrawn rows:\n%s", i+1, window)
		}
	}

	maliciousSource, err := os.ReadFile("malicious.go")
	if err != nil {
		t.Fatalf("read malicious.go: %v", err)
	}
	maliciousText := string(maliciousSource)

	for i, tail := range strings.Split(maliciousText, "SET removed_at = COALESCE(removed_at, NOW())")[1:] {
		window := tail
		if len(window) > 500 {
			window = window[:500]
		}
		if !strings.Contains(window, "AND removed_at IS NULL") {
			t.Fatalf("malicious tombstone update %d refreshes updated_at for already removed rows:\n%s", i+1, window)
		}
	}
}

// TestMaliciousUpsertRefreshesUpdatedAtForEveryResync guards the fix for the
// cutoff-prune regression. pruneStaleFindings withdraws OpenSSF findings whose
// updated_at predates the sync start, so the upsert MUST refresh updated_at for
// every re-seen entry. Gating the ON CONFLICT update behind a content diff (the
// old "skip unchanged rows" optimization) leaves unchanged live malware at a
// stale updated_at, so the next sync of an unchanged catalog withdraws all of
// it -- 231k findings vanished this way in production.
func TestMaliciousUpsertRefreshesUpdatedAtForEveryResync(t *testing.T) {
	source, err := os.ReadFile("malicious.go")
	if err != nil {
		t.Fatalf("read malicious.go: %v", err)
	}
	text := string(source)

	const marker = "ON CONFLICT (id) DO UPDATE SET"
	idx := strings.Index(text, marker)
	if idx < 0 {
		t.Fatal("malicious upsert missing ON CONFLICT (id) DO UPDATE block")
	}
	block := text[idx:]
	if end := strings.Index(block, "`"); end >= 0 {
		block = block[:end]
	}
	if !strings.Contains(block, "updated_at = NOW()") {
		t.Fatal("malicious upsert must refresh updated_at = NOW() on conflict so the cutoff prune keeps re-seen findings")
	}
	if strings.Contains(block, "IS DISTINCT FROM") {
		t.Fatal("malicious upsert must NOT gate the conflict update behind a content diff; the cutoff prune requires updated_at refreshed for every re-seen entry")
	}
}

func TestVulnCheckStreamImportRunsBatchesStatusAndAuditInOneTransaction(t *testing.T) {
	source, err := os.ReadFile("vulnerability_enrichment.go")
	if err != nil {
		t.Fatalf("read vulnerability_enrichment.go: %v", err)
	}
	text := string(source)

	required := []string{
		"func (s *Store) ImportVulnCheckStreamWithAudit",
		"err := withTx(ctx, s.pool, func(tx pgx.Tx) error",
		"status, streamTotal, txErr := stream(func(batch []db.VulnCheckEntry) error",
		"batchUpdated, err := enrichVulnCheckTx(ctx, tx, batch)",
		"upsertFeedSyncStatusTx(ctx, tx, status)",
		// The builder returns a value, so the audit row is written through the
		// address of a local -- the point being that it happens inside the same tx.
		"entry := audit(updated, 0)",
		"insertAdminAuditLogTx(ctx, tx, &entry)",
	}
	for _, want := range required {
		if !strings.Contains(text, want) {
			t.Fatalf("VulnCheck stream import missing transactional fragment %q", want)
		}
	}
}
