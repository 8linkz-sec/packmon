package scanner

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/8linkz/packmon/internal/domain"
)

func TestCheckRemoteSendsAPIKey(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer test-key" {
			t.Fatalf("Authorization header = %q, want %q", got, "Bearer test-key")
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(domain.ScanResult{
			ScanID:       "scan-1",
			Mode:         "remote",
			ScannedAt:    time.Now().UTC(),
			Summary:      domain.ScanSummary{BySeverity: map[string]int{}, ByType: map[string]int{}, BySource: map[string]int{}},
			Findings:     []domain.Finding{},
			FeedVersions: map[string]string{},
		})
	}))
	defer closeSilently(server)

	sc := New(nil, Config{
		ServerURL: server.URL,
		APIKey:    "test-key",
		Timeout:   5 * time.Second,
	})

	if _, _, _, err := sc.checkRemote(context.Background(), []domain.Package{{
		Name:      "lodash",
		Version:   "1.0.0",
		Ecosystem: domain.Ecosystem("npm"),
	}}); err != nil {
		t.Fatalf("checkRemote() error = %v", err)
	}
}

// ---------------------------------------------------------------------------
// hasBlockingFindings tests
// ---------------------------------------------------------------------------

func TestHasBlockingFindings_MalwareAlwaysBlocks(t *testing.T) {
	t.Parallel()

	sc := New(nil, Config{FailOn: domain.SeverityCritical})

	findings := []domain.Finding{
		{
			Type:     domain.FindingTypeMalicious,
			Severity: domain.SeverityLow,
			Source:   "openssf",
		},
	}

	if !sc.hasBlockingFindings(findings) {
		t.Fatal("malware findings must always block, regardless of fail-on threshold")
	}
}

func TestHasBlockingFindings_VulnAboveThreshold(t *testing.T) {
	t.Parallel()

	sc := New(nil, Config{FailOn: domain.SeverityHigh})

	tests := []struct {
		name     string
		severity domain.Severity
		want     bool
	}{
		{"CRITICAL blocks with HIGH threshold", domain.SeverityCritical, true},
		{"HIGH blocks with HIGH threshold", domain.SeverityHigh, true},
		{"MEDIUM does NOT block with HIGH threshold", domain.SeverityMedium, false},
		{"LOW does NOT block with HIGH threshold", domain.SeverityLow, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := []domain.Finding{
				{Type: domain.FindingTypeVulnerability, Severity: tt.severity, Source: "osv"},
			}
			got := sc.hasBlockingFindings(findings)
			if got != tt.want {
				t.Fatalf("hasBlockingFindings() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHasBlockingFindings_NoneThresholdNeverBlocks(t *testing.T) {
	t.Parallel()

	sc := New(nil, Config{FailOn: domain.SeverityNone})

	findings := []domain.Finding{
		{Type: domain.FindingTypeVulnerability, Severity: domain.SeverityCritical, Source: "osv"},
	}

	if sc.hasBlockingFindings(findings) {
		t.Fatal("with FailOn=NONE, vulnerability findings should never block")
	}
}

func TestHasBlockingFindings_MalwareBlocksEvenWithNoneThreshold(t *testing.T) {
	t.Parallel()

	sc := New(nil, Config{FailOn: domain.SeverityNone})

	findings := []domain.Finding{
		{Type: domain.FindingTypeMalicious, Severity: domain.SeverityUnknown, Source: "socket"},
	}

	if !sc.hasBlockingFindings(findings) {
		t.Fatal("malware must block even with NONE threshold")
	}
}

func TestHasBlockingFindings_NoFindings(t *testing.T) {
	t.Parallel()

	sc := New(nil, Config{FailOn: domain.SeverityLow})

	if sc.hasBlockingFindings(nil) {
		t.Fatal("nil findings should not block")
	}
	if sc.hasBlockingFindings([]domain.Finding{}) {
		t.Fatal("empty findings should not block")
	}
}

// ---------------------------------------------------------------------------
// resolveMode tests
// ---------------------------------------------------------------------------

func TestResolveMode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cfgMode Mode
		want    Mode
	}{
		{"explicit remote", ModeRemote, ModeRemote},
		{"explicit local", ModeLocal, ModeLocal},
		{"explicit auto", ModeAuto, ModeAuto},
		{"empty string defaults to auto", Mode(""), ModeAuto},
		{"unknown string defaults to auto", Mode("unknown"), ModeAuto},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sc := New(nil, Config{Mode: tt.cfgMode})
			if got := sc.resolveMode(); got != tt.want {
				t.Fatalf("resolveMode() = %q, want %q", got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// buildSummary tests (scanner package level)
// ---------------------------------------------------------------------------

func TestBuildSummary_Scanner(t *testing.T) {
	t.Parallel()

	findings := []domain.Finding{
		{Severity: domain.SeverityCritical, Type: domain.FindingTypeVulnerability, Source: "osv"},
		{Severity: domain.SeverityHigh, Type: domain.FindingTypeMalicious, Source: "openssf"},
		{Severity: domain.SeverityCritical, Type: domain.FindingTypeVulnerability, Source: "ghsa"},
	}

	s := buildSummary(findings)

	if s.BySeverity["CRITICAL"] != 2 {
		t.Fatalf("BySeverity[CRITICAL] = %d, want 2", s.BySeverity["CRITICAL"])
	}
	if s.BySeverity["HIGH"] != 1 {
		t.Fatalf("BySeverity[HIGH] = %d, want 1", s.BySeverity["HIGH"])
	}
	if s.ByType["vulnerability"] != 2 {
		t.Fatalf("ByType[vulnerability] = %d, want 2", s.ByType["vulnerability"])
	}
	if s.ByType["malicious"] != 1 {
		t.Fatalf("ByType[malicious] = %d, want 1", s.ByType["malicious"])
	}
	if s.BySource["osv"] != 1 {
		t.Fatalf("BySource[osv] = %d, want 1", s.BySource["osv"])
	}
}

// ---------------------------------------------------------------------------
// dedup tests
// ---------------------------------------------------------------------------

func TestDedup(t *testing.T) {
	t.Parallel()

	pkgs := []domain.Package{
		{Name: "lodash", Version: "4.17.15", Ecosystem: domain.EcosystemNPM},
		{Name: "lodash", Version: "4.17.15", Ecosystem: domain.EcosystemNPM}, // duplicate
		{Name: "lodash", Version: "4.17.21", Ecosystem: domain.EcosystemNPM}, // different version
		{Name: "requests", Version: "2.28.0", Ecosystem: domain.EcosystemPyPI},
	}

	result := dedup(pkgs)
	if len(result) != 3 {
		t.Fatalf("dedup() returned %d packages, want 3", len(result))
	}
}
