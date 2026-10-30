package postgres

import (
	"os"
	"strings"
	"testing"
)

func TestEveryMaliciousFindingMutationEntryPointTakesGlobalLock(t *testing.T) {
	t.Parallel()
	tests := []struct {
		file string
		name string
	}{
		{"malicious.go", "UpsertMaliciousFinding"},
		{"malicious.go", "importMaliciousFeed"},
		{"malicious.go", "DeleteMaliciousFinding"},
		{"malicious.go", "DeleteMaliciousFindingForSource"},
		{"malicious.go", "DeleteMaliciousFindingsNotInSource"},
		{"malicious.go", "PruneMaliciousFindingsForSourceUpdatedBefore"},
		{"manual_advisories.go", "UpsertManualAdvisory"},
		{"manual_advisories.go", "UpsertManualAdvisoryWithAudit"},
		{"manual_advisories.go", "DeleteManualAdvisory"},
		{"manual_advisories.go", "DeleteManualAdvisoryWithAudit"},
		{"package_name_repair.go", "RepairCaseInsensitivePackageNames"},
		{"package_name_repair.go", "RepairCaseInsensitivePackageNamesWithAudit"},
		{"malicious_snapshot.go", "replaceMaliciousFindingsSnapshot"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := functionSource(t, tt.file, tt.name)
			if !strings.Contains(body, "acquireMaliciousMutationLockTx") && !strings.Contains(body, "acquireMaliciousMutationLocksTx") {
				t.Fatalf("%s in %s mutates malicious_findings without the global transaction lock", tt.name, tt.file)
			}
		})
	}
}

func TestOpenSSFAndUnscopedMutationEntryPointsTakeSourceLockBeforeGlobalLock(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		file string
		name string
	}{
		{"malicious.go", "UpsertMaliciousFinding"},
		{"malicious.go", "importMaliciousFeed"},
		{"malicious.go", "DeleteMaliciousFinding"},
		{"malicious.go", "DeleteMaliciousFindingForSource"},
		{"malicious.go", "DeleteMaliciousFindingsNotInSource"},
		{"malicious.go", "PruneMaliciousFindingsForSourceUpdatedBefore"},
		{"package_name_repair.go", "RepairCaseInsensitivePackageNames"},
		{"package_name_repair.go", "RepairCaseInsensitivePackageNamesWithAudit"},
		{"malicious_snapshot.go", "replaceMaliciousFindingsSnapshot"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			body := functionSource(t, tt.file, tt.name)
			if !strings.Contains(body, "acquireMaliciousMutationLocksTx") {
				t.Fatalf("%s in %s can touch OpenSSF rows without the source-first lock helper", tt.name, tt.file)
			}
		})
	}
}

func TestMaliciousLockOrderIsNarrowThenGlobalThenPerID(t *testing.T) {
	t.Parallel()
	snapshot := functionSource(t, "malicious_snapshot.go", "replaceMaliciousFindingsSnapshot")
	sessionIndex := strings.Index(snapshot, "openssfSnapshotLockKey")
	globalIndex := strings.Index(snapshot, "acquireMaliciousMutationLocksTx")
	if sessionIndex < 0 || globalIndex < 0 || sessionIndex >= globalIndex {
		t.Fatalf("OpenSSF snapshot lock order must be session lock then global mutation lock")
	}

	for _, name := range []string{"UpsertManualAdvisory", "UpsertManualAdvisoryWithAudit", "DeleteManualAdvisory", "DeleteManualAdvisoryWithAudit"} {
		body := functionSource(t, "manual_advisories.go", name)
		globalIndex := strings.Index(body, "acquireMaliciousMutationLockTx")
		perIDIndex := strings.Index(body, "acquireManualAdvisoryLockTx")
		if globalIndex < 0 || perIDIndex < 0 || globalIndex >= perIDIndex {
			t.Fatalf("%s lock order must be global mutation lock then per-ID lock", name)
		}
	}
}

func functionSource(t *testing.T, file, name string) string {
	t.Helper()
	// #nosec G304 -- every caller passes a fixed repository-local source file
	// literal from the table above; this helper does not accept external input.
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("read %s: %v", file, err)
	}
	text := string(raw)
	needle := "func "
	start := -1
	for offset := 0; offset < len(text); {
		index := strings.Index(text[offset:], needle)
		if index < 0 {
			break
		}
		index += offset
		lineEnd := strings.IndexByte(text[index:], '\n')
		if lineEnd < 0 {
			lineEnd = len(text) - index
		}
		signature := text[index : index+lineEnd]
		if strings.Contains(signature, name+"(") {
			start = index
			break
		}
		offset = index + len(needle)
	}
	if start < 0 {
		t.Fatalf("function %s not found in %s", name, file)
	}
	end := strings.Index(text[start+1:], "\nfunc ")
	if end < 0 {
		return text[start:]
	}
	return text[start : start+1+end]
}
