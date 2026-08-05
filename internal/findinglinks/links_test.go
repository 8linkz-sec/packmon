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
		{name: "malware history", in: domain.Finding{Type: domain.FindingTypeSupplyChainRisk, RiskType: " " + domain.RiskTypeMalwareHistory + " "}, want: "MALWARE-HISTORY"},
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
	if got := ResourceLinkFromURL("https://www.rustsec.org/advisories/RUSTSEC-2026-0001.html"); got.Label != "RustSec" {
		t.Fatalf("ResourceLinkFromURL(RustSec) = %+v", got)
	}
	if got := ResourceLinkFromURL("https://example.test/path"); got.Label != "example.test" {
		t.Fatalf("ResourceLinkFromURL(custom host) = %+v", got)
	}
	if got := ResourceLinkFromURL("javascript:alert(1)"); got != (domain.ResourceLink{}) {
		t.Fatalf("ResourceLinkFromURL(unsafe) = %+v", got)
	}
	if got := ResourceLinkFromURL("://bad"); got != (domain.ResourceLink{}) {
		t.Fatalf("ResourceLinkFromURL(malformed) = %+v", got)
	}
	if got := ResourceLinkFromURL("//osv.dev/vulnerability/GHSA-abcd-efgh-ijkl"); got != (domain.ResourceLink{}) {
		t.Fatalf("ResourceLinkFromURL(protocol-relative) = %+v", got)
	}

	raw := `["ftp://example.test/file","https://example.test/first","https://example.test/second"]`
	if got := FirstSafeHTTPURLFromJSON(raw); got != "https://example.test/first" {
		t.Fatalf("FirstSafeHTTPURLFromJSON() = %q", got)
	}
	for _, tt := range []struct {
		raw  string
		want string
	}{
		{raw: ""},
		{raw: "not json"},
		{raw: `[]`},
		{raw: `["javascript:alert(1)"]`},
		{raw: `["//safe.example/path"]`},
		{raw: `["https://[::1","https://safe.example"]`, want: "https://safe.example"},
		{raw: `["not a url","https://nvd.nist.gov/vuln/detail/CVE-2026-0001"]`, want: "https://nvd.nist.gov/vuln/detail/CVE-2026-0001"},
	} {
		if got := FirstSafeHTTPURLFromJSON(tt.raw); got != tt.want {
			t.Fatalf("FirstSafeHTTPURLFromJSON(%q) = %q, want %q", tt.raw, got, tt.want)
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

	got = ResourceLinksFromVulnerabilityReferences("GHSA-abcd-efgh-ijkl", " ")
	want = []domain.ResourceLink{{Label: "GHSA", URL: "https://github.com/advisories/GHSA-abcd-efgh-ijkl"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("blank refs = %+v, want %+v", got, want)
	}

	got = ResourceLinksFromVulnerabilityReferences("OSV-2026-0001", " ")
	if got != nil {
		t.Fatalf("OSV without references resources = %+v, want nil", got)
	}

	for _, tt := range []struct {
		id    string
		label string
		url   string
	}{
		{id: "GHSA-abcd-efgh-ijkl", label: "GHSA", url: "https://github.com/advisories/GHSA-abcd-efgh-ijkl"},
		{id: "RUSTSEC-2026-0001", label: "RustSec", url: "https://rustsec.org/advisories/RUSTSEC-2026-0001.html"},
		{id: "CVE-2026-0001", label: "NVD", url: "https://nvd.nist.gov/vuln/detail/CVE-2026-0001"},
	} {
		link, score, ok := CanonicalVulnerabilityResource(tt.id)
		if !ok {
			t.Fatalf("CanonicalVulnerabilityResource(%q) ok = false", tt.id)
		}
		if link.Label != tt.label || link.URL != tt.url || score != 5 {
			t.Fatalf("CanonicalVulnerabilityResource(%q) = %+v score=%d, want %s %s score 5", tt.id, link, score, tt.label, tt.url)
		}
	}

	if _, _, ok := CanonicalVulnerabilityResource("OSV-2026-1"); ok {
		t.Fatal("CanonicalVulnerabilityResource(OSV) ok = true, want false")
	}
}

func TestResourceLinksFromVulnerabilityReferencesPolicyExamples(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		advisoryID string
		raw        string
		want       []domain.ResourceLink
	}{
		{
			name:       "prefers matching GHSA and keeps NVD",
			advisoryID: "GHSA-4744-96p5-mp2j",
			raw: `[
				{"type":"WEB","url":"https://github.com/pyload/pyload/security/advisories/GHSA-4744-96p5-mp2j"},
				{"type":"WEB","url":"https://github.com/pyload/pyload/security/advisories/GHSA-r7mc-x6x7-cqxx"},
				{"type":"ADVISORY","url":"https://nvd.nist.gov/vuln/detail/CVE-2026-33509"},
				{"type":"PACKAGE","url":"https://github.com/pyload/pyload"}
			]`,
			want: []domain.ResourceLink{
				{Label: "GHSA", URL: "https://github.com/pyload/pyload/security/advisories/GHSA-4744-96p5-mp2j"},
				{Label: "NVD", URL: "https://nvd.nist.gov/vuln/detail/CVE-2026-33509"},
			},
		},
		{
			name:       "adds canonical GHSA and skips Packet Storm",
			advisoryID: "GHSA-pf38-5p22-x6h6",
			raw: `[
				{"type":"ADVISORY","url":"https://nvd.nist.gov/vuln/detail/CVE-2023-0297"},
				{"type":"WEB","url":"https://huntr.dev/bounties/3fd606f7-83e1-4265-b083-2e1889a05e65"},
				{"type":"WEB","url":"http://packetstormsecurity.com/files/171096/pyLoad-js2py-Python-Execution.html"}
			]`,
			want: []domain.ResourceLink{
				{Label: "GHSA", URL: "https://github.com/advisories/GHSA-pf38-5p22-x6h6"},
				{Label: "NVD", URL: "https://nvd.nist.gov/vuln/detail/CVE-2023-0297"},
				{Label: "Huntr", URL: "https://huntr.dev/bounties/3fd606f7-83e1-4265-b083-2e1889a05e65"},
			},
		},
		{
			name:       "skips generic project landing pages",
			advisoryID: "GHSA-h73m-pcfw-25h2",
			raw: `[
				{"type":"ADVISORY","url":"https://nvd.nist.gov/vuln/detail/CVE-2023-47890"},
				{"type":"WEB","url":"https://github.com/pyload/pyload/commit/695bb70cd88608dc4fee18a6a7ecb66722ebfd8f"},
				{"type":"WEB","url":"https://github.com/pyload/pyload"},
				{"type":"WEB","url":"http://pyload.com"}
			]`,
			want: []domain.ResourceLink{
				{Label: "GHSA", URL: "https://github.com/advisories/GHSA-h73m-pcfw-25h2"},
				{Label: "NVD", URL: "https://nvd.nist.gov/vuln/detail/CVE-2023-47890"},
				{Label: "GitHub", URL: "https://github.com/pyload/pyload/commit/695bb70cd88608dc4fee18a6a7ecb66722ebfd8f"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := ResourceLinksFromVulnerabilityReferences(tt.advisoryID, tt.raw); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("ResourceLinksFromVulnerabilityReferences() = %+v, want %+v", got, tt.want)
			}
		})
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
		{name: "vulncheck attribution", advisoryID: "CVE-2026-0001", ref: VulnerabilityReference{Type: "VULNCHECK", URL: "https://vulncheck.com/cve/CVE-2026-0001"}, wantLabel: "VulnCheck", wantOK: true},
		{name: "vulncheck non http ignored", ref: VulnerabilityReference{Type: "VULNCHECK", URL: "file:///tmp/advisory"}, wantOK: false},
		{name: "vulncheck parse error ignored", ref: VulnerabilityReference{Type: "VULNCHECK", URL: "https://[::1"}, wantOK: false},
		{name: "protocol relative known host ignored", ref: VulnerabilityReference{URL: "//osv.dev/vulnerability/GHSA-abcd-efgh-ijkl"}, wantOK: false},
		{name: "javascript known host ignored", ref: VulnerabilityReference{URL: "javascript://osv.dev/%0aalert(1)"}, wantOK: false},
		{name: "file known host ignored", ref: VulnerabilityReference{URL: "file://osv.dev/vulnerability/GHSA-abcd-efgh-ijkl"}, wantOK: false},
		{name: "mailto known host ignored", ref: VulnerabilityReference{URL: "mailto://osv.dev/vulnerability/GHSA-abcd-efgh-ijkl"}, wantOK: false},
		{name: "generic landing page ignored", ref: VulnerabilityReference{URL: "https://github.com/acme/lib"}, wantOK: false},
		{name: "github advisory", advisoryID: "GHSA-abcd-efgh-ijkl", ref: VulnerabilityReference{URL: "https://github.com/acme/lib/security/advisories/GHSA-abcd-efgh-ijkl"}, wantLabel: "GHSA", wantOK: true},
		{name: "nvd", advisoryID: "CVE-2026-0001", ref: VulnerabilityReference{URL: "https://nvd.nist.gov/vuln/detail/CVE-2026-0001"}, wantLabel: "NVD", wantOK: true},
		{name: "rustsec advisory", ref: VulnerabilityReference{URL: "https://rustsec.org/advisories/RUSTSEC-2026-0001.html"}, wantLabel: "RustSec", wantOK: true},
		{name: "osv", advisoryID: "OSV-2026-0001", ref: VulnerabilityReference{URL: "https://osv.dev/vulnerability/OSV-2026-0001"}, wantLabel: "OSV", wantOK: true},
		{name: "huntr advisory", ref: VulnerabilityReference{URL: "https://huntr.dev/bounties/abc"}, wantLabel: "Huntr", wantOK: true},
		{name: "cve org", ref: VulnerabilityReference{URL: "https://cve.org/CVERecord?id=CVE-2026-0001"}, wantLabel: "CVE", wantOK: true},
		{name: "github non landing", ref: VulnerabilityReference{URL: "https://github.com/acme/lib/issues/1"}, wantLabel: "GitHub", wantOK: true},
		{name: "github commit", advisoryID: "CVE-2026-0001", ref: VulnerabilityReference{URL: "https://github.com/acme/lib/commit/abc"}, wantLabel: "GitHub", wantOK: true},
		{name: "custom host", ref: VulnerabilityReference{URL: "https://vendor.example/advisory"}, wantLabel: "vendor.example", wantOK: true},
		{name: "package ref skipped", advisoryID: "CVE-2026-0001", ref: VulnerabilityReference{Type: "PACKAGE", URL: "https://vendor.example/package"}, wantOK: false},
		{name: "blocked host skipped", advisoryID: "CVE-2026-0001", ref: VulnerabilityReference{URL: "https://packetstorm.news/files/id"}, wantOK: false},
		{name: "blank skipped", advisoryID: "CVE-2026-0001", ref: VulnerabilityReference{URL: " "}, wantOK: false},
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

func TestClassifyVulnerabilityResourceRulesAllowHostExtension(t *testing.T) {
	t.Parallel()

	rules := []vulnerabilityResourceRule{
		{
			label: "VendorDB",
			matches: func(ctx vulnerabilityResourceContext) bool {
				return ctx.host == "vendor.example" && ctx.path == "/advisories/cve-2026-0001"
			},
		},
	}

	got, score, ok := classifyVulnerabilityResourceWithRules(
		"CVE-2026-0001",
		VulnerabilityReference{URL: "https://vendor.example/advisories/CVE-2026-0001"},
		rules,
	)
	if !ok {
		t.Fatal("classifyVulnerabilityResourceWithRules() ok = false, want true")
	}
	if got.Label != "VendorDB" || got.URL != "https://vendor.example/advisories/CVE-2026-0001" {
		t.Fatalf("classifyVulnerabilityResourceWithRules() = %+v, want VendorDB resource", got)
	}
	if score != ResourceScore("CVE-2026-0001", "VendorDB") {
		t.Fatalf("classifyVulnerabilityResourceWithRules() score = %d, want %d", score, ResourceScore("CVE-2026-0001", "VendorDB"))
	}
}

func TestReferencePolicyAndScores(t *testing.T) {
	t.Parallel()

	if ShouldStoreVulnerabilityReference("https://packetstormsecurity.com/files/1") {
		t.Fatal("packetstorm reference should not be stored")
	}
	if ShouldStoreVulnerabilityReference("https://packetstorm.news/files/id/172914") {
		t.Fatal("packetstorm.news reference should not be stored")
	}
	if ShouldStoreVulnerabilityReference("https://web.archive.org/web/20201221104133/http://packetstormsecurity.com/files/136484/Apache-OpenMeetings-3.1.0-Path-Traversal.html") {
		t.Fatal("archived Packet Storm reference should not be stored")
	}
	if ShouldStoreVulnerabilityReference("") {
		t.Fatal("empty reference should not be stored")
	}
	if !ShouldStoreVulnerabilityReference("https://github.com/advisories/GHSA-pf38-5p22-x6h6") {
		t.Fatal("GitHub advisory reference should be stored")
	}
	if !ShouldStoreVulnerabilityReference("::::") {
		t.Fatal("unparseable non-blocked reference should be retained as plain diagnostic data")
	}
	if !ShouldStoreVulnerabilityReference("://not a url") {
		t.Fatal("malformed non-empty reference should be kept unless it contains a blocked value")
	}
	if !IsBlockedReferenceHost("packetstormsecurity.com") {
		t.Fatal("packetstormsecurity.com should be blocked")
	}
	if !IsBlockedReferenceHost("packetstorm.news") {
		t.Fatal("packetstorm.news should be blocked")
	}
	if IsBlockedReferenceHost("example.test") {
		t.Fatal("example.test should not be blocked")
	}

	tests := map[string]int{
		"GHSA":                ResourceScore("GHSA-abcd-efgh-ijkl", "GHSA"),
		"NVD":                 ResourceScore("CVE-2026-0001", "NVD"),
		"RustSec":             ResourceScore("RUSTSEC-2026-0001", "RustSec"),
		"OSV":                 ResourceScore("OSV-2026-0001", "OSV"),
		"Huntr":               ResourceScore("", "Huntr"),
		"CVE":                 ResourceScore("", "CVE"),
		"GitHub":              ResourceScore("", "GitHub"),
		"OtherHost":           ResourceScore("", "vendor.example"),
		"Default":             ResourceScore("OSV-2026-0001", "vendor.example"),
		"NonCanonicalGHSA":    ResourceScore("CVE-2026-0001", "GHSA"),
		"NonCanonicalNVD":     ResourceScore("GHSA-abcd-efgh-ijkl", "NVD"),
		"NonCanonicalRustSec": ResourceScore("GHSA-abcd-efgh-ijkl", "RustSec"),
	}
	want := map[string]int{
		"GHSA": 0, "NVD": 0, "RustSec": 0, "OSV": 40, "Huntr": 50, "CVE": 60, "GitHub": 70,
		"OtherHost": 100, "Default": 100, "NonCanonicalGHSA": 10, "NonCanonicalNVD": 20, "NonCanonicalRustSec": 30,
	}
	if !reflect.DeepEqual(tests, want) {
		t.Fatalf("ResourceScore map = %+v, want %+v", tests, want)
	}
}
