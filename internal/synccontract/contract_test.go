package synccontract

import (
	"reflect"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
)

func TestResponseFromExportMapsAllWireFields(t *testing.T) {
	t.Parallel()

	score := 9.8
	epssScore := 0.42
	epssPercentile := 0.99
	releaseDate := time.Date(2026, 6, 1, 15, 4, 5, 0, time.FixedZone("CEST", 2*60*60))
	eoas := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	eoes := true
	cursor := &db.SyncCursor{
		Vulnerabilities:       10,
		MaliciousCursor:       "mal-cursor",
		ReputationDone:        true,
		LifecycleCursor:       "life-cursor",
		VulnerabilitiesCursor: "vuln-cursor",
	}
	exported := &db.SyncExport{
		SyncedAt:  time.Date(2026, 6, 28, 10, 11, 12, 13, time.FixedZone("CEST", 2*60*60)),
		SyncedXID: 123,
		Vulnerabilities: []db.SyncVulnerability{{
			ID:               "GHSA-test",
			Ecosystem:        "npm",
			Name:             "left-pad",
			VersionRanges:    `[{"type":"SEMVER","events":[{"introduced":"0"}]}]`,
			VersionsAffected: `["1.0.0"]`,
			References:       `[{"type":"ADVISORY","url":"https://example.test/advisory"}]`,
			Severity:         "HIGH",
			CVSSScore:        &score,
			EPSSScore:        &epssScore,
			EPSSPercentile:   &epssPercentile,
			CISAKEV:          true,
			Summary:          "summary",
			Source:           "osv",
			Withdrawn:        true,
		}},
		Malicious: []db.SyncMalicious{{
			ID:            "MAL-test",
			Ecosystem:     "pypi",
			Name:          "evil",
			VersionRanges: `[]`,
			Versions:      `["2.0.0"]`,
			ReferenceURLs: `["https://example.test/mal"]`,
			RiskType:      "malware",
			Severity:      "CRITICAL",
			Summary:       "malicious",
			Source:        "openssf",
			Withdrawn:     true,
		}},
		Reputation: []db.SyncReputationFinding{{
			ID:        "rep",
			Ecosystem: "npm",
			Name:      "pkg",
			Version:   "1.2.3",
			Type:      "malware_history",
			RiskType:  "risk",
			Severity:  "LOW",
			Summary:   "history",
			Withdrawn: true,
		}},
		Lifecycle: []db.SyncLifecycleRelease{{
			ID:           "life",
			Ecosystem:    "maven",
			Name:         "org.example:lib",
			ProductSlug:  "example",
			ProductLabel: "Example",
			Cycle:        "4",
			Latest:       "4.2.1",
			ReleaseDate:  &releaseDate,
			IsEOAS:       true,
			EOASFrom:     &eoas,
			IsEOES:       &eoes,
			IsMaintained: true,
			Withdrawn:    true,
		}},
		Truncated:  true,
		NextCursor: cursor,
	}

	resp := ResponseFromExport(exported, "degraded", map[string]string{"osv": "2026-06-28T00:00:00Z"})

	if resp.SyncedAt != "2026-06-28T08:11:12.000000013Z" || resp.SyncedXID != 123 {
		t.Fatalf("sync metadata = %q/%d", resp.SyncedAt, resp.SyncedXID)
	}
	if resp.FeedStatus != "degraded" || resp.FeedVersions["osv"] != "2026-06-28T00:00:00Z" {
		t.Fatalf("feed state = %q %#v", resp.FeedStatus, resp.FeedVersions)
	}
	if !resp.Truncated || !resp.HasMore {
		t.Fatalf("pagination flags = truncated %v has_more %v, want both true", resp.Truncated, resp.HasMore)
	}
	if resp.NextCursor == nil || resp.NextCursor.Vulnerabilities != cursor.Vulnerabilities || resp.NextCursor.MaliciousCursor != cursor.MaliciousCursor || !resp.NextCursor.ReputationDone {
		t.Fatalf("next cursor = %+v", resp.NextCursor)
	}
	if len(resp.Vulnerabilities) != 1 || resp.Vulnerabilities[0].ID != "GHSA-test" || !resp.Vulnerabilities[0].CISAKEV || resp.Vulnerabilities[0].CVSSScore != &score {
		t.Fatalf("vulnerability wire row = %+v", resp.Vulnerabilities)
	}
	if len(resp.Malicious) != 1 || resp.Malicious[0].ReferenceURLs != `["https://example.test/mal"]` || !resp.Malicious[0].Withdrawn {
		t.Fatalf("malicious wire row = %+v", resp.Malicious)
	}
	if len(resp.Reputation) != 1 || resp.Reputation[0].Type != "malware_history" || !resp.Reputation[0].Withdrawn {
		t.Fatalf("reputation wire row = %+v", resp.Reputation)
	}
	wantLifecycle := Lifecycle{
		ID:           "life",
		Ecosystem:    "maven",
		Name:         "org.example:lib",
		ProductSlug:  "example",
		ProductLabel: "Example",
		Cycle:        "4",
		Latest:       "4.2.1",
		ReleaseDate:  stringPtr("2026-06-01"),
		IsEOAS:       true,
		EOASFrom:     stringPtr("2026-07-01"),
		IsEOES:       &eoes,
		IsMaintained: true,
		Withdrawn:    true,
	}
	if len(resp.Lifecycle) != 1 || !reflect.DeepEqual(resp.Lifecycle[0], wantLifecycle) {
		t.Fatalf("lifecycle wire row = %+v, want %+v", resp.Lifecycle, wantLifecycle)
	}
}

func stringPtr(value string) *string {
	return &value
}
