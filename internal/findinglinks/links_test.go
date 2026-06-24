package findinglinks

import (
	"reflect"
	"testing"

	"github.com/8linkz-sec/packmon/internal/domain"
)

func TestResourceLinksFromVulnerabilityReferencesPrefersMatchingAdvisoryLinks(t *testing.T) {
	t.Parallel()

	raw := `[
		{"type":"WEB","url":"https://github.com/acme/lib/security/advisories/GHSA-abcd-efgh-ijkl"},
		{"type":"WEB","url":"https://github.com/acme/lib/security/advisories/GHSA-wrong-wrong-wrong"},
		{"type":"ADVISORY","url":"https://nvd.nist.gov/vuln/detail/CVE-2026-0001"},
		{"type":"PACKAGE","url":"https://github.com/acme/lib"},
		{"type":"WEB","url":"https://packetstorm.news/files/id"}
	]`

	got := ResourceLinksFromVulnerabilityReferences("GHSA-abcd-efgh-ijkl", raw)
	if len(got) != 2 {
		t.Fatalf("resources = %+v, want GHSA and NVD", got)
	}
	if got[0].Label != "GHSA" || got[0].URL != "https://github.com/acme/lib/security/advisories/GHSA-abcd-efgh-ijkl" {
		t.Fatalf("resources[0] = %+v, want matching GHSA", got[0])
	}
	if got[1].Label != "NVD" || got[1].URL != "https://nvd.nist.gov/vuln/detail/CVE-2026-0001" {
		t.Fatalf("resources[1] = %+v, want NVD", got[1])
	}
}

func TestAdvisoryURLUsesCanonicalAndSafeFallbackPolicy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   domain.Finding
		want string
	}{
		{
			name: "ghsa",
			in:   domain.Finding{AdvisoryID: "GHSA-abcd-efgh-ijkl"},
			want: "https://github.com/advisories/GHSA-abcd-efgh-ijkl",
		},
		{
			name: "cve",
			in:   domain.Finding{AdvisoryID: "CVE-2026-0001"},
			want: "https://nvd.nist.gov/vuln/detail/CVE-2026-0001",
		},
		{
			name: "reversinglabs",
			in:   domain.Finding{AdvisoryID: "reversinglabs:pypi/evil@1.0.0", Ecosystem: domain.EcosystemPyPI, Name: "evil", Source: "reversinglabs"},
			want: "https://secure.software/pypi/packages/evil",
		},
		{
			name: "safe resource fallback",
			in:   domain.Finding{URL: "javascript:alert(1)", Resources: []domain.ResourceLink{{Label: "ok", URL: "https://example.test/advisory"}}},
			want: "https://example.test/advisory",
		},
		{
			name: "unsafe only",
			in:   domain.Finding{URL: "javascript:alert(1)", Resources: []domain.ResourceLink{{Label: "data", URL: "data:text/html,owned"}}},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := AdvisoryURL(tt.in); got != tt.want {
				t.Fatalf("AdvisoryURL() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFindingLinksPreservesUnsafeValuesAsPlainText(t *testing.T) {
	t.Parallel()

	links, plain := FindingLinks(domain.Finding{
		URL: "https://example.test/advisory",
		Resources: []domain.ResourceLink{
			{Label: "bad", URL: "javascript:alert(1)"},
			{Label: "ok", URL: "https://example.test/resource"},
		},
	})
	if len(links) != 2 || links[0].URL != "https://example.test/advisory" || links[1].Label != "ok" {
		t.Fatalf("links = %+v, want primary and resource http links", links)
	}
	if len(plain) != 1 || plain[0] != "javascript:alert(1)" {
		t.Fatalf("plain = %+v, want unsafe value as plain text", plain)
	}
}

func TestAdvisoryLabel(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   domain.Finding
		want string
	}{
		{name: "explicit advisory", in: domain.Finding{AdvisoryID: " CVE-2026-0001 "}, want: " CVE-2026-0001 "},
		{name: "malicious", in: domain.Finding{Type: domain.FindingTypeMalicious}, want: "MALWARE"},
		{name: "malware history", in: domain.Finding{Type: domain.FindingTypeSupplyChainRisk, RiskType: " malware_history "}, want: "MALWARE-HISTORY"},
		{name: "supply chain", in: domain.Finding{Type: domain.FindingTypeSupplyChainRisk}, want: "SUPPLY-CHAIN"},
		{name: "lifecycle", in: domain.Finding{Type: domain.FindingTypeLifecycle}, want: "LIFECYCLE"},
		{name: "unknown", in: domain.Finding{}, want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := AdvisoryLabel(tt.in); got != tt.want {
				t.Fatalf("AdvisoryLabel() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestResourceLinkHelpers(t *testing.T) {
	t.Parallel()

	if got := ResourceLinkFromURL("https://osv.dev/vulnerability/GHSA-abcd-efgh-ijkl"); got.Label != "OSV" {
		t.Fatalf("ResourceLinkFromURL(OSV) = %+v", got)
	}
	if got := ResourceLinkFromURL("javascript:alert(1)"); got != (domain.ResourceLink{}) {
		t.Fatalf("ResourceLinkFromURL(unsafe) = %+v", got)
	}

	raw := `["ftp://example.test/file","https://example.test/first","https://example.test/second"]`
	if got := FirstSafeHTTPURLFromJSON(raw); got != "https://example.test/first" {
		t.Fatalf("FirstSafeHTTPURLFromJSON() = %q", got)
	}
	for _, raw := range []string{"", "not json", `["javascript:alert(1)"]`} {
		if got := FirstSafeHTTPURLFromJSON(raw); got != "" {
			t.Fatalf("FirstSafeHTTPURLFromJSON(%q) = %q, want empty", raw, got)
		}
	}

	if got := SecureSoftwarePackageURL(domain.EcosystemNPM, "@scope/pkg"); got != "https://secure.software/npm/packages/@scope%2Fpkg" {
		t.Fatalf("SecureSoftwarePackageURL() = %q", got)
	}
	if got := SecureSoftwarePackageURL("", "pkg"); got != "" {
		t.Fatalf("SecureSoftwarePackageURL(empty ecosystem) = %q", got)
	}
}

func TestResourceLinksFromVulnerabilityReferencesCanonicalAndInvalidInputs(t *testing.T) {
	t.Parallel()

	got := ResourceLinksFromVulnerabilityReferences("CVE-2026-0001", "")
	want := []domain.ResourceLink{{Label: "NVD", URL: "https://nvd.nist.gov/vuln/detail/CVE-2026-0001"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("empty refs = %+v, want %+v", got, want)
	}

	got = ResourceLinksFromVulnerabilityReferences("RUSTSEC-2026-0001", "not json")
	want = []domain.ResourceLink{{Label: "RustSec", URL: "https://rustsec.org/advisories/RUSTSEC-2026-0001.html"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("invalid refs = %+v, want %+v", got, want)
	}

	if got := ResourceLinksFromVulnerabilityReferences("", ""); got != nil {
		t.Fatalf("empty advisory resources = %+v, want nil", got)
	}
}

func TestClassifyVulnerabilityResourceCoversReferenceKinds(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		advisoryID string
		ref        VulnerabilityReference
		wantLabel  string
		wantOK     bool
	}{
		{name: "empty URL", ref: VulnerabilityReference{URL: ""}, wantOK: false},
		{name: "package refs ignored", ref: VulnerabilityReference{Type: "PACKAGE", URL: "https://example.test/pkg"}, wantOK: false},
		{name: "vulncheck type", ref: VulnerabilityReference{Type: "VULNCHECK", URL: "https://vulncheck.com/advisory"}, wantLabel: "VulnCheck", wantOK: true},
		{name: "generic landing page ignored", ref: VulnerabilityReference{URL: "https://github.com/acme/lib"}, wantOK: false},
		{name: "github advisory", advisoryID: "GHSA-abcd-efgh-ijkl", ref: VulnerabilityReference{URL: "https://github.com/acme/lib/security/advisories/GHSA-abcd-efgh-ijkl"}, wantLabel: "GHSA", wantOK: true},
		{name: "rustsec advisory", ref: VulnerabilityReference{URL: "https://rustsec.org/advisories/RUSTSEC-2026-0001.html"}, wantLabel: "RustSec", wantOK: true},
		{name: "huntr advisory", ref: VulnerabilityReference{URL: "https://huntr.dev/bounties/abc"}, wantLabel: "Huntr", wantOK: true},
		{name: "cve org", ref: VulnerabilityReference{URL: "https://cve.org/CVERecord?id=CVE-2026-0001"}, wantLabel: "CVE", wantOK: true},
		{name: "github non landing", ref: VulnerabilityReference{URL: "https://github.com/acme/lib/issues/1"}, wantLabel: "GitHub", wantOK: true},
		{name: "custom host", ref: VulnerabilityReference{URL: "https://vendor.example/advisory"}, wantLabel: "vendor.example", wantOK: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, _, ok := ClassifyVulnerabilityResource(tt.advisoryID, tt.ref)
			if ok != tt.wantOK || got.Label != tt.wantLabel {
				t.Fatalf("ClassifyVulnerabilityResource() = %+v, %v; want label %q ok %v", got, ok, tt.wantLabel, tt.wantOK)
			}
		})
	}
}

func TestReferencePolicyAndScores(t *testing.T) {
	t.Parallel()

	if ShouldStoreVulnerabilityReference("https://packetstormsecurity.com/files/1") {
		t.Fatal("packetstorm reference should not be stored")
	}
	if !ShouldStoreVulnerabilityReference("::::") {
		t.Fatal("unparseable non-blocked reference should be retained as plain diagnostic data")
	}
	if !IsBlockedReferenceHost("packetstorm.news") {
		t.Fatal("packetstorm.news should be blocked")
	}
	if IsBlockedReferenceHost("example.test") {
		t.Fatal("example.test should not be blocked")
	}

	tests := map[string]int{
		"GHSA":      ResourceScore("GHSA-abcd-efgh-ijkl", "GHSA"),
		"NVD":       ResourceScore("CVE-2026-0001", "NVD"),
		"RustSec":   ResourceScore("RUSTSEC-2026-0001", "RustSec"),
		"OSV":       ResourceScore("", "OSV"),
		"Huntr":     ResourceScore("", "Huntr"),
		"CVE":       ResourceScore("", "CVE"),
		"GitHub":    ResourceScore("", "GitHub"),
		"OtherHost": ResourceScore("", "vendor.example"),
	}
	want := map[string]int{"GHSA": 0, "NVD": 0, "RustSec": 0, "OSV": 40, "Huntr": 50, "CVE": 60, "GitHub": 70, "OtherHost": 100}
	if !reflect.DeepEqual(tests, want) {
		t.Fatalf("ResourceScore map = %+v, want %+v", tests, want)
	}
}
