package findinglinks

import (
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
