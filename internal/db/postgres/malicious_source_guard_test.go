package postgres

import (
	"os"
	"sort"
	"strings"
	"testing"
)

func TestVulnerabilitiesSourceDoesNotOwnMaliciousPersistence(t *testing.T) {
	t.Parallel()

	methods := storeMethodsInSourceFile(t, "vulnerabilities.go")
	disallowedMethods := []string{
		"FindMalicious",
		"FindMaliciousBatch",
		"UpsertMaliciousFinding",
		"ImportMaliciousFeed",
		"ImportMaliciousFeedWithAudit",
		"DeleteMaliciousFinding",
		"DeleteMaliciousFindingForSource",
		"DeleteMaliciousFindingsNotInSource",
		"PruneMaliciousFindingsForSourceUpdatedBefore",
		"ListMaliciousFindings",
	}

	var offenders []string
	for _, method := range disallowedMethods {
		if methods[method] {
			offenders = append(offenders, method)
		}
	}

	source, err := os.ReadFile("vulnerabilities.go")
	if err != nil {
		t.Fatalf("read vulnerabilities.go: %v", err)
	}
	for _, marker := range []string{
		"func validateMaliciousFindingVersions(",
		"func maliciousFindingAffectsVersion(",
		"func upsertMaliciousFindingTx(",
		"func deleteMaliciousFindingForSourceTx(",
	} {
		if strings.Contains(string(source), marker) {
			offenders = append(offenders, marker)
		}
	}

	sort.Strings(offenders)
	if len(offenders) > 0 {
		t.Fatalf("vulnerabilities.go still owns malicious-package persistence: %s", strings.Join(offenders, ", "))
	}
}
