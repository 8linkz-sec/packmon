package ci

import (
	"os"
	"strings"
	"testing"
)

func TestOpenAPIIncludesCanonicalScanAndSyncFields(t *testing.T) {
	data, err := os.ReadFile("../../api/openapi/packmon-v1.yaml")
	if err != nil {
		t.Fatalf("read OpenAPI spec: %v", err)
	}
	spec := string(data)
	for _, want := range []string{
		"parse_errors:",
		"findings_truncated:",
		"resources:",
		"ResourceLink:",
		"versions_affected:",
		"reference_urls:",
		"enum: [osv, ghsa, openssf, malicious, vulncheck, cisakev, epss, socket]",
		"enum: [healthy, warning, error, disabled, pending]",
	} {
		if !strings.Contains(spec, want) {
			t.Fatalf("OpenAPI spec missing %q", want)
		}
	}
}
