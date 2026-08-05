package web

import (
	"io/fs"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/domain"
)

// TestPackageFindingAdvisorySourceLabelRecognisesEveryIDScheme covers the
// attribution derived from an advisory identifier alone. It is the first choice
// for the resource label, so a missed prefix silently downgrades a precise
// "GHSA advisory" link to a generic one.
func TestPackageFindingAdvisorySourceLabelRecognisesEveryIDScheme(t *testing.T) {
	t.Parallel()

	for id, want := range map[string]string{
		"GHSA-aaaa-bbbb-cccc": "GHSA",
		"ghsa-aaaa-bbbb-cccc": "GHSA",
		"  CVE-2026-1234  ":   "NVD",
		"RUSTSEC-2026-0001":   "RustSec",
		"MAL-2026-1":          "",
		"":                    "",
	} {
		if got := packageFindingAdvisorySourceLabel(id); got != want {
			t.Errorf("packageFindingAdvisorySourceLabel(%q) = %q, want %q", id, got, want)
		}
	}
}

// TestPackageFindingSourceLabelNormalisesKnownFeeds pins the display name of
// every feed the UI can attribute a finding to. An unmapped source falls through
// to its raw spelling, which is acceptable but must not happen for known feeds.
func TestPackageFindingSourceLabelNormalisesKnownFeeds(t *testing.T) {
	t.Parallel()

	for source, want := range map[string]string{
		"":                          "",
		"ghsa":                      "GHSA",
		"GHSA":                      "GHSA",
		"osv":                       "OSV",
		"nvd":                       "NVD",
		"vulncheck":                 "VulnCheck",
		"openssf":                   "OpenSSF",
		"socket":                    "Socket.dev",
		"socket.dev":                "Socket.dev",
		"endoflife.date":            "endoflife.date",
		domain.ManualAdvisorySource: "Manual",
	} {
		if got := packageFindingSourceLabel(source); got != want {
			t.Errorf("packageFindingSourceLabel(%q) = %q, want %q", source, got, want)
		}
	}

	// An unknown source is echoed rather than dropped, so the UI still shows
	// where a finding came from.
	if got := packageFindingSourceLabel("brand-new-feed"); got != "brand-new-feed" {
		t.Errorf("packageFindingSourceLabel(unknown) = %q, want the raw source", got)
	}
}

// TestPackageFindingFallbackResourceLabelPrefersTheAdvisoryID covers the
// precedence at the top of the fallback chain: an identifier that names its own
// source beats the feed that happened to deliver the finding.
func TestPackageFindingFallbackResourceLabelPrefersTheAdvisoryID(t *testing.T) {
	t.Parallel()

	got := packageFindingFallbackResourceLabel(domain.Finding{
		Type:       domain.FindingTypeVulnerability,
		AdvisoryID: "GHSA-aaaa-bbbb-cccc",
		Source:     "osv",
	})
	if got != "GHSA advisory" {
		t.Fatalf("label = %q, want the advisory ID to win over the delivering feed", got)
	}
}

// TestPackageFindingFallbackResourceLabelCoversEveryFindingType walks the
// per-type wording. Each finding type gets its own noun, so a malware report
// cannot be presented to the user as an ordinary advisory.
func TestPackageFindingFallbackResourceLabelCoversEveryFindingType(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		finding domain.Finding
		want    string
	}{
		{
			name:    "malicious with a known source",
			finding: domain.Finding{Type: domain.FindingTypeMalicious, Source: "socket"},
			want:    "Socket.dev malware report",
		},
		{
			name:    "malicious without any attribution",
			finding: domain.Finding{Type: domain.FindingTypeMalicious},
			want:    "Malware report",
		},
		{
			name:    "supply chain",
			finding: domain.Finding{Type: domain.FindingTypeSupplyChainRisk, Source: "openssf"},
			want:    "OpenSSF supply-chain report",
		},
		{
			name:    "supply chain without attribution",
			finding: domain.Finding{Type: domain.FindingTypeSupplyChainRisk},
			want:    "Supply-chain risk report",
		},
		{
			name: "malware history is called out separately",
			finding: domain.Finding{
				Type:     domain.FindingTypeSupplyChainRisk,
				RiskType: domain.RiskTypeMalwareHistory,
				Source:   "openssf",
			},
			want: "OpenSSF malware history report",
		},
		{
			name: "malware history without attribution",
			finding: domain.Finding{
				Type:     domain.FindingTypeSupplyChainRisk,
				RiskType: "MALWARE_HISTORY",
			},
			want: "Malware history report",
		},
		{
			name:    "lifecycle",
			finding: domain.Finding{Type: domain.FindingTypeLifecycle, Source: "endoflife.date"},
			want:    "endoflife.date lifecycle report",
		},
		{
			name:    "lifecycle without attribution",
			finding: domain.Finding{Type: domain.FindingTypeLifecycle},
			want:    "Lifecycle report",
		},
		{
			name:    "vulnerability",
			finding: domain.Finding{Type: domain.FindingTypeVulnerability, Source: "osv"},
			want:    "OSV advisory",
		},
		{
			name:    "unknown type without attribution",
			finding: domain.Finding{},
			want:    "Finding advisory",
		},
	} {
		if got := packageFindingFallbackResourceLabel(tc.finding); got != tc.want {
			t.Errorf("%s: label = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// TestPackageFindingFallbackResourceLabelFallsBackToTheURLTarget covers the last
// resort: with no advisory ID and no known source, the link host still has to
// tell the user where the report lives.
func TestPackageFindingFallbackResourceLabelFallsBackToTheURLTarget(t *testing.T) {
	t.Parallel()

	label := packageFindingFallbackResourceLabel(domain.Finding{
		Type: domain.FindingTypeVulnerability,
		URL:  "https://github.com/advisories/GHSA-aaaa-bbbb-cccc",
	})
	if label == "" {
		t.Fatal("label is empty although a URL was present")
	}
	if !strings.HasSuffix(label, "advisory") {
		t.Fatalf("label = %q, want it to end in advisory", label)
	}
}

// TestNormalizeStaticAssetFSPathRejectsTraversal is the security-relevant half of
// the asset resolver: every accepted path has to stay inside static/, because the
// result is used to read a file out of the embedded asset filesystem.
func TestNormalizeStaticAssetFSPathRejectsTraversal(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{
		"", "   ", "/", "..", "../secrets", "/../secrets",
		"static/../../etc/passwd", "static/", "/static/",
		`static\css\app.css`, `..\..\windows\system32`,
	} {
		if got, ok := normalizeStaticAssetFSPath(raw); ok {
			t.Errorf("normalizeStaticAssetFSPath(%q) = %q, true; want a rejection", raw, got)
		}
	}
}

// TestNormalizeStaticAssetFSPathAlwaysStaysUnderStatic states the invariant the
// resolver actually guarantees, rather than enumerating rejected inputs: every
// accepted result is a valid FS path strictly below static/. Note that a bare
// "static" is *not* the prefix form -- it normalises to "static/static", an
// ordinary asset name, which is still inside the sandbox.
func TestNormalizeStaticAssetFSPathAlwaysStaysUnderStatic(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{
		"css/app.css", "/css/app.css", "static/css/app.css", "/static/css/app.css",
		"static", "/static", "js/../css/app.css", "static/js/../css/app.css",
		"./css/app.css", "css//app.css",
	} {
		got, ok := normalizeStaticAssetFSPath(raw)
		if !ok {
			continue
		}
		if !strings.HasPrefix(got, "static/") {
			t.Errorf("normalizeStaticAssetFSPath(%q) = %q, want a path under static/", raw, got)
		}
		if strings.Contains(got, "..") {
			t.Errorf("normalizeStaticAssetFSPath(%q) = %q, want no traversal segments", raw, got)
		}
		if !fs.ValidPath(got) {
			t.Errorf("normalizeStaticAssetFSPath(%q) = %q, want a valid io/fs path", raw, got)
		}
	}
}

// TestNormalizeStaticAssetFSPathAcceptsAssetsWithOrWithoutThePrefix covers the
// two shapes templates use, and pins that both normalise to the same FS path.
func TestNormalizeStaticAssetFSPathAcceptsAssetsWithOrWithoutThePrefix(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{
		"css/app.css", "/css/app.css", "static/css/app.css", "/static/css/app.css",
		"static/./css/app.css",
	} {
		got, ok := normalizeStaticAssetFSPath(raw)
		if !ok {
			t.Errorf("normalizeStaticAssetFSPath(%q) was rejected", raw)
			continue
		}
		if got != "static/css/app.css" {
			t.Errorf("normalizeStaticAssetFSPath(%q) = %q, want static/css/app.css", raw, got)
		}
	}
}

// TestFormatTimeISOOmitsTheZeroTime keeps an unset timestamp out of the rendered
// datetime attribute. "0001-01-01T00:00:00Z" in a <time> element reads as a real
// date to both users and assistive technology.
func TestFormatTimeISOOmitsTheZeroTime(t *testing.T) {
	t.Parallel()

	if got := formatTimeISO(time.Time{}); got != "" {
		t.Fatalf("formatTimeISO(zero) = %q, want an empty string", got)
	}

	stamp := time.Date(2026, 8, 4, 9, 30, 0, 0, time.FixedZone("CEST", 2*60*60))
	got := formatTimeISO(stamp)
	if got != "2026-08-04T07:30:00Z" {
		t.Fatalf("formatTimeISO = %q, want the UTC RFC3339 form", got)
	}
}

// TestMessageResolvesCatalogKeys covers the exported message lookup used by
// callers outside the package. An unknown key must degrade to something
// printable rather than an empty label in the UI.
func TestMessageResolvesCatalogKeys(t *testing.T) {
	t.Parallel()

	known := Message(string(webMessageNever))
	if strings.TrimSpace(known) == "" {
		t.Fatal("Message returned nothing for a known catalog key")
	}
	// Surrounding whitespace in the key must not defeat the lookup.
	if padded := Message("  " + string(webMessageNever) + "  "); padded != known {
		t.Fatalf("Message(padded key) = %q, want %q", padded, known)
	}
	if unknown := Message("not.a.catalog.key"); strings.TrimSpace(unknown) == "" {
		t.Fatal("Message returned nothing for an unknown key")
	}
}

// TestAdminAlertStringValueReadsThroughIndirection covers the reflective lookup
// the admin templates use for flash messages. The data arrives as a map or a
// struct, sometimes behind pointers, and a miss must be an empty string rather
// than a panic in the middle of rendering a page.
func TestAdminAlertStringValueReadsThroughIndirection(t *testing.T) {
	t.Parallel()

	type payload struct {
		Error string
		Count int
	}

	value := "boom"
	pointerToStruct := &payload{Error: "boom"}

	for _, tc := range []struct {
		name string
		data any
		key  string
		want string
	}{
		{name: "map", data: map[string]any{"Error": "boom"}, key: "Error", want: "boom"},
		{name: "map with pointer value", data: map[string]any{"Error": &value}, key: "Error", want: "boom"},
		{name: "struct", data: payload{Error: "boom"}, key: "Error", want: "boom"},
		{name: "pointer to struct", data: pointerToStruct, key: "Error", want: "boom"},
		{name: "missing key", data: map[string]any{"Other": "x"}, key: "Error", want: ""},
		{name: "non-string field", data: payload{Count: 3}, key: "Count", want: ""},
		{name: "nil data", data: nil, key: "Error", want: ""},
		{name: "typed nil pointer", data: (*payload)(nil), key: "Error", want: ""},
		{name: "nil map value", data: map[string]any{"Error": nil}, key: "Error", want: ""},
		{name: "non-string keyed map", data: map[int]string{1: "x"}, key: "Error", want: ""},
		{name: "unsupported kind", data: 42, key: "Error", want: ""},
	} {
		if got := adminAlertStringValue(tc.data, tc.key); got != tc.want {
			t.Errorf("%s: adminAlertStringValue = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// TestAdminAlertBoolValueReadsThroughIndirection is the boolean counterpart,
// which gates whether an alert block renders at all.
func TestAdminAlertBoolValueReadsThroughIndirection(t *testing.T) {
	t.Parallel()

	type payload struct {
		Success bool
		Label   string
	}

	truth := true

	for _, tc := range []struct {
		name string
		data any
		key  string
		want bool
	}{
		{name: "map", data: map[string]any{"Success": true}, key: "Success", want: true},
		{name: "map with pointer value", data: map[string]any{"Success": &truth}, key: "Success", want: true},
		{name: "struct", data: payload{Success: true}, key: "Success", want: true},
		{name: "pointer to struct", data: &payload{Success: true}, key: "Success", want: true},
		{name: "false stays false", data: payload{}, key: "Success", want: false},
		{name: "non-bool field", data: payload{Label: "x"}, key: "Label", want: false},
		{name: "missing key", data: map[string]any{}, key: "Success", want: false},
		{name: "nil data", data: nil, key: "Success", want: false},
		{name: "typed nil pointer", data: (*payload)(nil), key: "Success", want: false},
	} {
		if got := adminAlertBoolValue(tc.data, tc.key); got != tc.want {
			t.Errorf("%s: adminAlertBoolValue = %v, want %v", tc.name, got, tc.want)
		}
	}
}
