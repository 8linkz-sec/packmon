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

func TestMaliciousUpsertSkipsUnchangedActiveRows(t *testing.T) {
	source, err := os.ReadFile("malicious.go")
	if err != nil {
		t.Fatalf("read malicious.go: %v", err)
	}
	text := string(source)

	required := []string{
		"WHERE malicious_findings.ecosystem IS DISTINCT FROM EXCLUDED.ecosystem",
		"OR malicious_findings.version_ranges IS DISTINCT FROM EXCLUDED.version_ranges",
		"OR malicious_findings.reference_urls IS DISTINCT FROM EXCLUDED.reference_urls",
		"OR malicious_findings.removed_at IS NOT NULL",
	}
	for _, want := range required {
		if !strings.Contains(text, want) {
			t.Fatalf("malicious upsert missing idempotency guard %q", want)
		}
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
		"insertAdminAuditLogTx(ctx, tx, audit(updated, 0))",
	}
	for _, want := range required {
		if !strings.Contains(text, want) {
			t.Fatalf("VulnCheck stream import missing transactional fragment %q", want)
		}
	}
}
