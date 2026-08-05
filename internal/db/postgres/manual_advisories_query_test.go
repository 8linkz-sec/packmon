package postgres

import (
	"os"
	"strings"
	"testing"
)

func TestManualAdvisoryVulnerabilityQueriesMatchSourceLeadingIndexPredicate(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile("manual_advisories.go")
	if err != nil {
		t.Fatalf("read manual advisory queries: %v", err)
	}
	source := string(data)
	if count := strings.Count(source, "vs.raw_json IS NOT NULL"); count < 4 {
		t.Fatalf("manual vulnerability source predicates with raw_json IS NOT NULL = %d, want at least 4", count)
	}
	for _, want := range []string{
		"FROM vulnerability_sources vs\n\t\t\tINNER JOIN vulnerabilities v ON v.id = vs.vulnerability_id",
		"WHERE vs.source = $3\n\t\t\t  AND vs.raw_json IS NOT NULL",
		"WHERE vs.source = $2\n\t\t\t  AND vs.raw_json IS NOT NULL",
	} {
		if !strings.Contains(source, want) {
			t.Fatalf("manual advisory query source filter does not align with source-leading partial index, missing %q", want)
		}
	}
}
