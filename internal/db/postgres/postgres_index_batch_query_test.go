package postgres

import (
	"os"
	"strings"
	"testing"
)

func TestGHSARepairQueryMatchesSourceLeadingPartialIndexPredicate(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile("ghsa_repair.go")
	if err != nil {
		t.Fatalf("read GHSA repair query: %v", err)
	}
	source := string(data)
	want := "WHERE vs.source = 'ghsa'\n\t\t\t  AND vs.raw_json IS NOT NULL"
	if !strings.Contains(source, want) {
		t.Fatalf("GHSA repair query source filter does not align with source-leading partial index, missing %q", want)
	}
}

func TestScanLogWritersLeaveRollupMaintenanceToDatabaseView(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile("scan_logs.go")
	if err != nil {
		t.Fatalf("read scan log writers: %v", err)
	}
	source := string(data)
	for _, forbidden := range []string{
		"INSERT INTO scan_log_totals",
		"UPDATE scan_log_totals",
	} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("scan_log writer still manually mutates rollup with %q; scan_log_totals view must derive totals from scan_log", forbidden)
		}
	}
}
