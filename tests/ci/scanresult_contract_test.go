package ci

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/8linkz/packmon/internal/domain"
)

// canonicalScanResult is a fully-populated result used to pin the wire shape
// shared by every surface. All three surfaces serialize domain.ScanResult
// directly:
//   - CLI JSON:  json.MarshalIndent(result) in cmd/packmon/scan.go
//   - API:       writeJSON(domain.ScanResult{...}) in internal/api/v1/handler.go
//   - Webhook:   domain.WebhookEnvelope{Result: ...} in internal/scanner/webhook.go
//
// Keeping them on one struct is the contract; this test fails if any field is
// renamed/removed, if omitempty hides a required field, or if the webhook
// envelope ever stops embedding the canonical result unchanged.
func canonicalScanResult() domain.ScanResult {
	dbAge := 2
	return domain.ScanResult{
		ScanID:           "scan-123",
		Mode:             "remote",
		ScannedAt:        time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC),
		DurationMs:       42,
		PackagesScanned:  3,
		FindingsCount:    1,
		FindingsBlocking: true,
		FeedStatus:       "healthy",
		DBAgeDays:        &dbAge,
		DBStale:          false,
		Summary: domain.ScanSummary{
			BySeverity: map[string]int{"HIGH": 1},
			ByType:     map[string]int{"vulnerability": 1},
			BySource:   map[string]int{"ghsa": 1},
		},
		Findings: []domain.Finding{
			{
				Name:         "lodash",
				Version:      "4.17.0",
				Ecosystem:    domain.EcosystemNPM,
				Type:         domain.FindingTypeVulnerability,
				Severity:     domain.SeverityHigh,
				AdvisoryID:   "GHSA-xxxx",
				Title:        "Prototype pollution",
				FixedVersion: "4.17.21",
				URL:          "https://github.com/advisories/GHSA-xxxx",
				Resources:    []domain.ResourceLink{{Label: "NVD", URL: "https://nvd.nist.gov/vuln/detail/CVE-2020-0001"}},
				Source:       "ghsa",
			},
		},
		ParseErrors:       []string{"requirements.txt: malformed line 5"},
		FindingsTruncated: true,
		FeedVersions:      map[string]string{"ghsa": "2026-06-01"},
		ManualCount:       1,
	}
}

// requiredScanResultFields lists wire names that must appear in the serialized
// canonical result on every surface. omitempty fields are populated in the
// fixture so their absence is a real contract break.
var requiredScanResultFields = []string{
	`"scan_id"`, `"mode"`, `"scanned_at"`, `"duration_ms"`, `"packages_scanned"`,
	`"findings_count"`, `"findings_blocking"`, `"feed_status"`, `"db_age_days"`,
	`"db_stale"`, `"summary"`, `"by_severity"`, `"by_type"`, `"by_source"`,
	`"findings"`, `"parse_errors"`, `"findings_truncated"`, `"feed_versions"`,
	`"manual_advisories_count"`,
	// Finding-level fields, incl. the reference links that the OpenAPI contract
	// and SARIF/JUnit/HTML writers rely on.
	`"advisory_id"`, `"resources"`, `"label"`, `"url"`,
}

func TestScanResultCanonicalShapeIsStable(t *testing.T) {
	result := canonicalScanResult()

	canonical, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal canonical result: %v", err)
	}
	got := string(canonical)
	for _, field := range requiredScanResultFields {
		if !strings.Contains(got, field) {
			t.Errorf("canonical ScanResult JSON missing field %s\n%s", field, got)
		}
	}

	// Round-trip must reproduce the original value exactly.
	var roundTripped domain.ScanResult
	if err := json.Unmarshal(canonical, &roundTripped); err != nil {
		t.Fatalf("unmarshal canonical result: %v", err)
	}
	if !reflect.DeepEqual(roundTripped, result) {
		t.Fatalf("round-trip mismatch:\nwant %+v\ngot  %+v", result, roundTripped)
	}
}

func TestWebhookEmbedsCanonicalScanResultUnchanged(t *testing.T) {
	result := canonicalScanResult()

	canonical, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal canonical result: %v", err)
	}

	envelope := domain.WebhookEnvelope{
		Event:     "scan.completed",
		Version:   "1",
		Timestamp: result.ScannedAt,
		Source:    "packmon",
		Result:    result,
	}
	envBytes, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("marshal webhook envelope: %v", err)
	}

	var decoded struct {
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(envBytes, &decoded); err != nil {
		t.Fatalf("decode webhook envelope: %v", err)
	}

	// The result subtree must round-trip to the same canonical value.
	var fromWebhook, fromCanonical domain.ScanResult
	if err := json.Unmarshal(decoded.Result, &fromWebhook); err != nil {
		t.Fatalf("decode webhook result: %v", err)
	}
	if err := json.Unmarshal(canonical, &fromCanonical); err != nil {
		t.Fatalf("decode canonical result: %v", err)
	}
	if !reflect.DeepEqual(fromWebhook, fromCanonical) {
		t.Fatalf("webhook result diverges from canonical shape:\nwant %+v\ngot  %+v", fromCanonical, fromWebhook)
	}
}
