package ci

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/domain"
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
		BlockThreshold:   domain.SeverityHigh,
		FeedStatus:       "healthy",
		ScanError:        "remote check failed: example",
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

// These wire names must appear in the serialized canonical result on every
// surface. omitempty fields are populated in the fixture so their absence is a
// real contract break.
var requiredScanResultFields = []string{
	"scan_id", "mode", "scanned_at", "duration_ms", "packages_scanned",
	"findings_count", "findings_blocking", "block_threshold", "feed_status", "db_age_days",
	"scan_error", "db_stale", "summary", "findings", "parse_errors", "findings_truncated",
	"feed_versions", "manual_advisories_count",
}

var requiredScanSummaryFields = []string{
	"by_severity", "by_type", "by_source",
}

var requiredFindingFields = []string{
	"advisory_id", "url", "resources",
}

var requiredResourceLinkFields = []string{
	"label", "url",
}

func TestScanResultCanonicalShapeIsStable(t *testing.T) {
	result := canonicalScanResult()

	canonical, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal canonical result: %v", err)
	}
	for _, field := range missingScanResultContractFields(canonical) {
		t.Errorf("canonical ScanResult JSON missing field %s\n%s", field, string(canonical))
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

func TestScanResultContractDetectsMissingResourceLinkURL(t *testing.T) {
	canonical, err := json.Marshal(canonicalScanResult())
	if err != nil {
		t.Fatalf("marshal canonical result: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(canonical, &decoded); err != nil {
		t.Fatalf("decode canonical result JSON: %v", err)
	}
	findings := decoded["findings"].([]any)
	firstFinding := findings[0].(map[string]any)
	resources := firstFinding["resources"].([]any)
	firstResource := resources[0].(map[string]any)
	delete(firstResource, "url")

	mutated, err := json.Marshal(decoded)
	if err != nil {
		t.Fatalf("marshal mutated result JSON: %v", err)
	}

	missing := missingScanResultContractFields(mutated)
	if !containsString(missing, "findings[0].resources[0].url") {
		t.Fatalf("missing fields = %v, want findings[0].resources[0].url", missing)
	}
}

func missingScanResultContractFields(canonical []byte) []string {
	var missing []string
	var root map[string]json.RawMessage
	if err := json.Unmarshal(canonical, &root); err != nil {
		return []string{"<invalid JSON>"}
	}

	appendMissingJSONFields(&missing, root, "", requiredScanResultFields)

	var summary map[string]json.RawMessage
	if err := json.Unmarshal(root["summary"], &summary); err != nil {
		missing = append(missing, "summary.<object>")
	} else {
		appendMissingJSONFields(&missing, summary, "summary", requiredScanSummaryFields)
	}

	var findings []map[string]json.RawMessage
	if err := json.Unmarshal(root["findings"], &findings); err != nil || len(findings) == 0 {
		missing = append(missing, "findings[0]")
		return missing
	}
	appendMissingJSONFields(&missing, findings[0], "findings[0]", requiredFindingFields)

	var resources []map[string]json.RawMessage
	if err := json.Unmarshal(findings[0]["resources"], &resources); err != nil || len(resources) == 0 {
		missing = append(missing, "findings[0].resources[0]")
		return missing
	}
	appendMissingJSONFields(&missing, resources[0], "findings[0].resources[0]", requiredResourceLinkFields)

	return missing
}

func appendMissingJSONFields(missing *[]string, object map[string]json.RawMessage, prefix string, fields []string) {
	for _, field := range fields {
		if _, ok := object[field]; ok {
			continue
		}
		if prefix == "" {
			*missing = append(*missing, field)
			continue
		}
		*missing = append(*missing, prefix+"."+field)
	}
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func TestEmptyScanResultFindingsSerializeAsArray(t *testing.T) {
	result := domain.ScanResult{
		ScanID:           "scan-empty",
		Mode:             "remote",
		ScannedAt:        time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC),
		BlockThreshold:   domain.SeverityCritical,
		FeedStatus:       "healthy",
		Summary:          domain.EmptyScanSummary(),
		Findings:         []domain.Finding{},
		FeedVersions:     map[string]string{},
		FindingsBlocking: false,
	}

	body, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal empty result: %v", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		t.Fatalf("decode empty result JSON: %v", err)
	}
	if got := string(raw["findings"]); got != "[]" {
		t.Fatalf("empty ScanResult findings = %s, want []", got)
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
