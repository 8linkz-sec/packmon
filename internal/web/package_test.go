package web

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/domain"
)

const (
	testPackageDetailNameLimit    = 512
	testPackageDetailVersionLimit = 256
)

func TestHandlePackageRejectsTooLongNameBeforeLookup(t *testing.T) {
	store := &mockStore{}
	handler := HandlePackage(store, testRenderer(), discardLogger())
	name := strings.Repeat("a", testPackageDetailNameLimit+1)

	req := httptest.NewRequest(http.MethodGet, "/package/npm/"+name, nil)
	req.SetPathValue("ecosystem", "npm")
	req.SetPathValue("name", name)
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("Package status = %d, want %d", rec.Code, http.StatusNotFound)
	}
	if store.packageLookups != 0 {
		t.Fatalf("package lookups = %d, want none for too-long package name", store.packageLookups)
	}
}

func TestHandlePackageRejectsTooLongVersionBeforeLookup(t *testing.T) {
	store := &mockStore{}
	handler := HandlePackage(store, testRenderer(), discardLogger())
	version := strings.Repeat("1", testPackageDetailVersionLimit+1)

	req := httptest.NewRequest(http.MethodGet, "/package/npm/lodash?version="+version, nil)
	req.SetPathValue("ecosystem", "npm")
	req.SetPathValue("name", "lodash")
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("Package status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	if !strings.Contains(rec.Body.String(), "package version exceeds") {
		t.Fatalf("Package body = %q, want package version length error", rec.Body.String())
	}
	if store.packageLookups != 0 {
		t.Fatalf("package lookups = %d, want none for too-long package version", store.packageLookups)
	}
}

func TestHandlePackageScopedPackageBreadcrumbIsSemantic(t *testing.T) {
	body := renderPackageDetail(t, "npm", "@scope/pkg")

	for _, want := range []string{
		`<nav aria-label="Breadcrumb"`,
		`<ol`,
		`<a href="/search"`,
		`Search</a>`,
		`aria-current="page"><bdi dir="auto">npm/@scope/pkg</bdi>`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("Package breadcrumb missing marker %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, `<span class="inline-block bg-surface-2 text-fg px-2 py-0.5 rounded text-xs font-medium">npm</span> /`) {
		t.Fatalf("Package breadcrumb still renders ecosystem/name as plain slash-delimited text:\n%s", body)
	}
}

func TestHandlePackageBreadcrumbUsesValidatedSearchReturnTo(t *testing.T) {
	store := &mockStore{}
	handler := HandlePackage(store, testRenderer(), discardLogger())

	req := httptest.NewRequest(http.MethodGet, "/package/npm/lodash?return_to=%2Fsearch%3Fq%3Dlodash%26severity%3DHIGH%26finding%3Dvulnerability", nil)
	req.SetPathValue("ecosystem", "npm")
	req.SetPathValue("name", "lodash")
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Package status = %d, want %d", rec.Code, http.StatusOK)
	}
	body := rec.Body.String()
	want := `href="/search?finding=vulnerability&amp;q=lodash&amp;severity=HIGH"`
	if !strings.Contains(body, want) {
		t.Fatalf("Package breadcrumb missing filtered return_to %q:\n%s", want, body)
	}
	if !strings.Contains(body, `type="hidden" name="return_to" value="/search?finding=vulnerability&amp;q=lodash&amp;severity=HIGH"`) {
		t.Fatalf("Package version form did not preserve validated return_to:\n%s", body)
	}
}

func TestHandlePackageBreadcrumbRejectsUnsafeReturnTo(t *testing.T) {
	tests := []struct {
		name     string
		returnTo string
	}{
		{name: "absolute external URL", returnTo: "https://example.test/search?q=lodash"},
		{name: "scheme-relative external URL", returnTo: "//example.test/search?q=lodash"},
		{name: "other local path", returnTo: "/admin/?q=lodash"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &mockStore{}
			handler := HandlePackage(store, testRenderer(), discardLogger())

			req := httptest.NewRequest(http.MethodGet, "/package/npm/lodash?return_to="+url.QueryEscape(tt.returnTo), nil)
			req.SetPathValue("ecosystem", "npm")
			req.SetPathValue("name", "lodash")
			rec := httptest.NewRecorder()

			handler(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("Package status = %d, want %d", rec.Code, http.StatusOK)
			}
			body := rec.Body.String()
			if !strings.Contains(body, `<a href="/search" class="hover:underline">Search</a>`) {
				t.Fatalf("Package breadcrumb did not fall back to /search for unsafe return_to %q:\n%s", tt.returnTo, body)
			}
			if strings.Contains(body, "example.test") || strings.Contains(body, "/admin/?q=lodash") {
				t.Fatalf("Package breadcrumb rendered unsafe return_to %q:\n%s", tt.returnTo, body)
			}
		})
	}
}

func TestHandlePackageActivatesSearchNavigation(t *testing.T) {
	body := renderPackageDetail(t, "npm", "@scope/pkg")

	if !strings.Contains(body, `<a href="/search" aria-current="page"`) {
		t.Fatalf("Package detail did not mark Search nav as current:\n%s", body)
	}
}

func TestHandlePackageInteractiveControlsMeetTouchTargetHeight(t *testing.T) {
	store := &mockStore{
		vulnFindings: []domain.Finding{
			{
				Name:       "lodash",
				Ecosystem:  domain.EcosystemNPM,
				Type:       domain.FindingTypeVulnerability,
				Severity:   domain.SeverityHigh,
				AdvisoryID: "GHSA-test-1234",
				Title:      "Example advisory",
				Resources: []domain.ResourceLink{
					{Label: "GHSA", URL: "https://github.com/advisories/GHSA-test-1234"},
				},
			},
		},
	}
	handler := HandlePackage(store, testRenderer(), discardLogger())
	req := httptest.NewRequest(http.MethodGet, "/package/npm/lodash", nil)
	req.SetPathValue("ecosystem", "npm")
	req.SetPathValue("name", "lodash")
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Package status = %d, want %d", rec.Code, http.StatusOK)
	}
	body := rec.Body.String()
	versionButton := tagContaining(t, body, `<button`, `Check version`)
	if !strings.Contains(versionButton, "min-h-11") {
		t.Fatalf("version submit button missing min-h-11 touch target:\n%s", versionButton)
	}

	// Advisory resource chips are deliberately compact badge-sized links, but
	// must not shrink below the WCAG 2.5.8 minimum target size (24px).
	resourceLink := tagContaining(t, body, `<a`, `aria-label="GHSA opens in a new tab"`)
	if !strings.Contains(resourceLink, "min-h-6") {
		t.Fatalf("advisory resource chip missing min-h-6 minimum target size:\n%s", resourceLink)
	}
	if strings.Contains(resourceLink, "min-h-11") {
		t.Fatalf("advisory resource chip still uses oversized min-h-11:\n%s", resourceLink)
	}
}

func TestHandlePackageFallbackResourceLinksUseFindingContextLabels(t *testing.T) {
	store := &mockStore{
		vulnFindings: []domain.Finding{
			{
				Name:       "lodash",
				Ecosystem:  domain.EcosystemNPM,
				Type:       domain.FindingTypeVulnerability,
				Severity:   domain.SeverityHigh,
				AdvisoryID: "GHSA-test-1234",
				Title:      "Example vulnerability advisory",
				URL:        "https://github.com/advisories/GHSA-test-1234",
				Source:     "ghsa",
			},
		},
		malFindings: []domain.Finding{
			{
				Name:       "lodash",
				Ecosystem:  domain.EcosystemNPM,
				Type:       domain.FindingTypeMalicious,
				Severity:   domain.SeverityCritical,
				AdvisoryID: "MAL-2026-0001",
				Title:      "Malicious package report",
				URL:        "https://github.com/ossf/malicious-packages/blob/main/osv/malicious/npm/lodash/MAL-2026-0001.json",
				RiskType:   "malware",
				Source:     "openssf",
			},
		},
		repFindings: []domain.Finding{
			{
				Name:       "lodash",
				Version:    "1.3.0",
				Ecosystem:  domain.EcosystemNPM,
				Type:       domain.FindingTypeSupplyChainRisk,
				Severity:   domain.SeverityCritical,
				AdvisoryID: "reversinglabs:npm/lodash@1.3.0",
				Title:      "ReversingLabs reputation report",
				URL:        "https://secure.software/npm/packages/lodash",
				RiskType:   "removed_package",
				Source:     db.ReputationSourceReversingLabs,
			},
		},
	}
	handler := HandlePackage(store, testRenderer(), discardLogger())

	req := httptest.NewRequest(http.MethodGet, "/package/npm/lodash", nil)
	req.SetPathValue("ecosystem", "npm")
	req.SetPathValue("name", "lodash")
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Package status = %d, want %d", rec.Code, http.StatusOK)
	}
	body := rec.Body.String()
	for _, notWant := range []string{
		`aria-label="Link opens in a new tab"`,
		">Link",
	} {
		if strings.Contains(body, notWant) {
			t.Fatalf("Package fallback resource links still render generic label %q:\n%s", notWant, body)
		}
	}
	for _, want := range []string{
		`aria-label="GHSA advisory opens in a new tab"`,
		`<bdi dir="auto">GHSA advisory</bdi>`,
		`aria-label="OpenSSF malware report opens in a new tab"`,
		`<bdi dir="auto">OpenSSF malware report</bdi>`,
		`aria-label="ReversingLabs reputation report opens in a new tab"`,
		`<bdi dir="auto">ReversingLabs reputation report</bdi>`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("Package fallback resource links missing contextual label %q:\n%s", want, body)
		}
	}
}

func TestHandlePackageBidiIsolatesFindingIdentifiers(t *testing.T) {
	packageName := "pkg-\u05d0\u05d1"
	version := "1.0.0-\u05d2"
	advisoryID := "MAL-\u05d3-2026"
	title := "Malware report \u05d4"
	source := "openssf-\u05d5"
	resourceLabel := "OpenSSF \u05d6"
	store := &mockStore{
		malFindings: []domain.Finding{
			{
				Name:       packageName,
				Version:    version,
				Ecosystem:  domain.EcosystemNPM,
				Type:       domain.FindingTypeMalicious,
				Severity:   domain.SeverityCritical,
				AdvisoryID: advisoryID,
				Title:      title,
				RiskType:   "malware",
				Source:     source,
				Resources: []domain.ResourceLink{
					{Label: resourceLabel, URL: "https://github.com/ossf/malicious-packages"},
				},
			},
		},
	}
	handler := HandlePackage(store, testRenderer(), discardLogger())

	req := httptest.NewRequest(http.MethodGet, "/package/npm/pkg-%D7%90%D7%91?version=1.0.0-%D7%92", nil)
	req.SetPathValue("ecosystem", "npm")
	req.SetPathValue("name", packageName)
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Package status = %d, want %d", rec.Code, http.StatusOK)
	}
	body := rec.Body.String()
	for _, want := range []string{
		`<h1 class="text-2xl font-bold break-all"><bdi dir="auto">` + packageName + `</bdi></h1>`,
		`<input type="text" name="version" value="` + version + `" dir="auto"`,
		`<bdi dir="auto">` + advisoryID + `</bdi>`,
		`<bdi dir="auto">` + version + `</bdi>`,
		`<bdi dir="auto">` + title + `</bdi>`,
		`<bdi dir="auto">` + source + `</bdi>`,
		`<bdi dir="auto">` + resourceLabel + `</bdi>`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("Package response missing bidi-isolated marker %q:\n%s", want, body)
		}
	}
}

func TestHandlePackageRiskTypesRenderHumanHelp(t *testing.T) {
	store := &mockStore{
		vulnFindings: []domain.Finding{
			{
				Name:       "left-pad",
				Ecosystem:  domain.EcosystemNPM,
				Type:       domain.FindingTypeVulnerability,
				Severity:   domain.SeverityHigh,
				AdvisoryID: "GHSA-2026-0001",
				Title:      "Known vulnerability",
				RiskType:   "vulnerability",
				Source:     "osv",
			},
		},
		malFindings: []domain.Finding{
			{
				Name:       "left-pad",
				Ecosystem:  domain.EcosystemNPM,
				Type:       domain.FindingTypeMalicious,
				Severity:   domain.SeverityCritical,
				AdvisoryID: "MAL-2026-0001",
				Title:      "Confirmed malware",
				RiskType:   "malicious",
				Source:     "openssf",
			},
			{
				Name:       "left-pad",
				Ecosystem:  domain.EcosystemNPM,
				Type:       domain.FindingTypeMalicious,
				Severity:   domain.SeverityMedium,
				AdvisoryID: "MANUAL-2026-0001",
				Title:      "Source-specific risk",
				RiskType:   "credential_harvesting",
				Source:     "manual",
			},
		},
		repBatchFindings: []domain.Finding{
			{
				Name:       "left-pad",
				Version:    "1.3.0",
				Ecosystem:  domain.EcosystemNPM,
				Type:       domain.FindingTypeSupplyChainRisk,
				Severity:   domain.SeverityCritical,
				AdvisoryID: "reversinglabs:npm/left-pad@1.3.0",
				Title:      "Removed package release",
				RiskType:   "removed_package",
				Source:     db.ReputationSourceReversingLabs,
			},
			{
				Name:       "left-pad",
				Version:    "1.3.0",
				Ecosystem:  domain.EcosystemNPM,
				Type:       domain.FindingTypeSupplyChainRisk,
				Severity:   domain.SeverityHigh,
				AdvisoryID: "socket:npm/left-pad",
				Title:      "Malware history",
				RiskType:   "malware_history",
				Source:     "socket.dev",
			},
			{
				Name:       "left-pad",
				Version:    "1.3.0",
				Ecosystem:  domain.EcosystemNPM,
				Type:       domain.FindingTypeSupplyChainRisk,
				Severity:   domain.SeverityHigh,
				AdvisoryID: "socket:npm/left-pad-typo",
				Title:      "Typosquatting signal",
				RiskType:   "typosquatting",
				Source:     "socket.dev",
			},
			{
				Name:       "left-pad",
				Version:    "1.3.0",
				Ecosystem:  domain.EcosystemNPM,
				Type:       domain.FindingTypeSupplyChainRisk,
				Severity:   domain.SeverityMedium,
				AdvisoryID: "socket:npm/left-pad-supply-chain",
				Title:      "Supply-chain reputation signal",
				RiskType:   "supply_chain",
				Source:     "socket.dev",
			},
		},
		lifecycle: []domain.Finding{
			{
				Name:       "left-pad",
				Version:    "1.3.0",
				Ecosystem:  domain.EcosystemNPM,
				Type:       domain.FindingTypeLifecycle,
				Severity:   domain.SeverityHigh,
				AdvisoryID: "endoflife:npm:left-pad:eol",
				Title:      "Release line is end of life",
				RiskType:   "eol",
				Source:     "endoflife.date",
			},
			{
				Name:       "left-pad",
				Version:    "1.3.0",
				Ecosystem:  domain.EcosystemNPM,
				Type:       domain.FindingTypeLifecycle,
				Severity:   domain.SeverityMedium,
				AdvisoryID: "endoflife:npm:left-pad:eol-soon",
				Title:      "Release line reaches EOL soon",
				RiskType:   "eol_soon",
				Source:     "endoflife.date",
			},
			{
				Name:       "left-pad",
				Version:    "1.3.0",
				Ecosystem:  domain.EcosystemNPM,
				Type:       domain.FindingTypeLifecycle,
				Severity:   domain.SeverityLow,
				AdvisoryID: "endoflife:npm:left-pad:security-only",
				Title:      "Release line receives security fixes only",
				RiskType:   "security_support_only",
				Source:     "endoflife.date",
			},
		},
	}
	handler := HandlePackage(store, testRenderer(), discardLogger())

	req := httptest.NewRequest(http.MethodGet, "/package/npm/left-pad?version=1.3.0", nil)
	req.SetPathValue("ecosystem", "npm")
	req.SetPathValue("name", "left-pad")
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Package status = %d, want %d", rec.Code, http.StatusOK)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"Risk type reference",
		">Vulnerability</span>",
		"(vulnerability)",
		"Confirmed malicious package or release",
		"Registry or reputation source reports the package or version was removed",
		">Malicious package</span>",
		"(malicious)",
		">Removed package</span>",
		"(removed_package)",
		">Malware history</span>",
		"(malware_history)",
		">End-of-life</span>",
		"(eol)",
		">End-of-life soon</span>",
		"(eol_soon)",
		">Security support only</span>",
		"(security_support_only)",
		">Typosquatting</span>",
		"(typosquatting)",
		">Supply-chain risk</span>",
		"(supply_chain)",
		">Credential harvesting</span>",
		"(credential_harvesting)",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("Package response missing risk type help marker %q:\n%s", want, body)
		}
	}
	for _, notWant := range []string{
		">vulnerability</span>",
		">malicious</span>",
		">credential_harvesting</span>",
	} {
		if strings.Contains(body, notWant) {
			t.Fatalf("Package response exposed raw risk type label %q:\n%s", notWant, body)
		}
	}
}

func TestHandlePackageCapsDisplayedFindingRowsPerSection(t *testing.T) {
	const (
		displayLimit = 20
		totalRows    = displayLimit + 2
	)
	store := &mockStore{
		vulnFindings:     packageDetailFindings(totalRows, domain.FindingTypeVulnerability, "visible vulnerability"),
		malFindings:      packageDetailFindings(totalRows, domain.FindingTypeMalicious, "visible malicious"),
		repBatchFindings: packageDetailFindings(totalRows, domain.FindingTypeSupplyChainRisk, "visible supply-chain"),
		lifecycle:        packageDetailFindings(totalRows, domain.FindingTypeLifecycle, "visible lifecycle"),
	}
	handler := HandlePackage(store, testRenderer(), discardLogger())

	req := httptest.NewRequest(http.MethodGet, "/package/npm/lodash?version=1.2.3", nil)
	req.SetPathValue("ecosystem", "npm")
	req.SetPathValue("name", "lodash")
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Package status = %d, want %d", rec.Code, http.StatusOK)
	}
	if store.packageLookups != 4 {
		t.Fatalf("package lookups = %d, want all four finding stores queried", store.packageLookups)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"Malicious Package Reports (22)",
		"Supply-chain Risks (22)",
		"Vulnerabilities (22)",
		"Lifecycle (22)",
		"Showing first 20 of 22",
		"2 more not shown",
		"visible vulnerability 19",
		"visible malicious 19",
		"visible supply-chain 19",
		"visible lifecycle 19",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("Package response missing bounded finding marker %q:\n%s", want, body)
		}
	}
	for _, notWant := range []string{
		"visible vulnerability 20",
		"visible malicious 20",
		"visible supply-chain 20",
		"visible lifecycle 20",
		"visible vulnerability 21",
		"visible malicious 21",
		"visible supply-chain 21",
		"visible lifecycle 21",
	} {
		if strings.Contains(body, notWant) {
			t.Fatalf("Package response rendered row beyond display cap %q:\n%s", notWant, body)
		}
	}
}

func packageDetailFindings(count int, findingType domain.FindingType, titlePrefix string) []domain.Finding {
	findings := make([]domain.Finding, 0, count)
	for i := 0; i < count; i++ {
		findings = append(findings, domain.Finding{
			Name:       "lodash",
			Version:    "1.2.3",
			Ecosystem:  domain.EcosystemNPM,
			Type:       findingType,
			Severity:   domain.SeverityHigh,
			AdvisoryID: fmt.Sprintf("TEST-%02d", i),
			Title:      fmt.Sprintf("%s %02d", titlePrefix, i),
			RiskType:   packageDetailRiskType(findingType),
			Source:     "test",
		})
	}
	return findings
}

func packageDetailRiskType(findingType domain.FindingType) string {
	switch findingType {
	case domain.FindingTypeMalicious:
		return "malware"
	case domain.FindingTypeSupplyChainRisk:
		return "supply_chain"
	case domain.FindingTypeLifecycle:
		return "eol"
	default:
		return ""
	}
}

func TestHandlePackageLookupErrorLogsUseSafePackageContext(t *testing.T) {
	sensitiveName := "github.com/acme/private-path-token"
	sensitiveVersion := "v1.2.3-secret-version-token"
	store := &mockStore{
		vulnErr:      errors.New("vuln lookup unavailable"),
		malErr:       errors.New("malicious lookup unavailable"),
		repErr:       errors.New("reputation lookup unavailable"),
		lifecycleErr: errors.New("lifecycle lookup unavailable"),
	}
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	handler := HandlePackage(store, testRenderer(), logger)

	req := httptest.NewRequest(http.MethodGet, "/package/go/"+sensitiveName+"?version="+sensitiveVersion+"&access_token=query-token-secret", nil)
	req.SetPathValue("ecosystem", "go")
	req.SetPathValue("name", sensitiveName)
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Package status = %d, want %d", rec.Code, http.StatusOK)
	}
	logText := logs.String()
	for _, leaked := range []string{sensitiveName, sensitiveVersion, "private-path-token", "secret-version-token", "query-token-secret"} {
		if strings.Contains(logText, leaked) {
			t.Fatalf("Package lookup error log leaked %q:\n%s", leaked, logText)
		}
	}
	for _, want := range []string{
		`"ecosystem":"go"`,
		`"name_length":34`,
		`"version_present":true`,
		`"path":"/package/{ecosystem}/{name...}"`,
	} {
		if !strings.Contains(logText, want) {
			t.Fatalf("Package lookup error log missing safe context %q:\n%s", want, logText)
		}
	}
}

func TestLoadPackageFindingsRunsIndependentLookupsInParallel(t *testing.T) {
	release := make(chan struct{})
	store := &blockingPackageLookupStore{
		started: make(chan string, 4),
		release: release,
	}
	ctx := context.WithValue(context.Background(), packageLookupContextTestKey{}, "request")
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	done := make(chan packageFindings, 1)
	go func() {
		done <- loadPackageFindings(ctx, store, discardLogger(), packageLogContext{
			path:           "/package/{ecosystem}/{name...}",
			nameLength:     len("lodash"),
			versionPresent: true,
		}, "npm", "lodash", "1.0.0")
	}()

	wantStarted := map[string]struct{}{
		"vulnerabilities": {},
		"malicious":       {},
		"reputation":      {},
		"lifecycle":       {},
	}
	seenStarted := make(map[string]struct{}, len(wantStarted))
	var releaseOnce sync.Once
	releaseLookups := func() {
		releaseOnce.Do(func() {
			close(release)
		})
	}

	startTimer := time.NewTimer(500 * time.Millisecond)
	defer startTimer.Stop()
	for len(seenStarted) < len(wantStarted) {
		select {
		case lookup := <-store.started:
			if _, ok := wantStarted[lookup]; !ok {
				releaseLookups()
				t.Fatalf("lookup %q started, want one of %v", lookup, sortedLookupNames(wantStarted))
			}
			seenStarted[lookup] = struct{}{}
		case <-startTimer.C:
			releaseLookups()
			<-done
			t.Fatalf("lookups started before release = %v, want %v", sortedLookupNames(seenStarted), sortedLookupNames(wantStarted))
		}
	}

	releaseLookups()
	select {
	case findings := <-done:
		if findings.vulnerabilitiesLoadError != "" || findings.maliciousLoadError != "" || findings.reputationLoadError != "" || findings.lifecycleLoadError != "" {
			t.Fatalf("load errors = vulnerability %q, malicious %q, reputation %q, lifecycle %q",
				findings.vulnerabilitiesLoadError,
				findings.maliciousLoadError,
				findings.reputationLoadError,
				findings.lifecycleLoadError)
		}
		if len(findings.vulnerabilities) != 1 || len(findings.malicious) != 2 || len(findings.supplyChain) != 1 || len(findings.lifecycle) != 1 {
			t.Fatalf("finding counts = vulnerabilities %d, malicious %d, supply-chain %d, lifecycle %d; want 1, 2, 1, 1",
				len(findings.vulnerabilities), len(findings.malicious), len(findings.supplyChain), len(findings.lifecycle))
		}
	case <-time.After(time.Second):
		t.Fatal("loadPackageFindings did not return after releasing blocked lookups")
	}
}

type packageLookupContextTestKey struct{}

type blockingPackageLookupStore struct {
	mockStore
	started chan string
	release <-chan struct{}
}

func (s *blockingPackageLookupStore) FindVulnerabilities(ctx context.Context, _, _, _ string) ([]domain.Finding, error) {
	if err := s.blockLookup(ctx, "vulnerabilities"); err != nil {
		return nil, err
	}
	return []domain.Finding{{
		Type:   domain.FindingTypeVulnerability,
		Source: "osv",
	}}, nil
}

func (s *blockingPackageLookupStore) FindMalicious(ctx context.Context, _, _, _ string) ([]domain.Finding, error) {
	if err := s.blockLookup(ctx, "malicious"); err != nil {
		return nil, err
	}
	return []domain.Finding{{
		Type:     domain.FindingTypeMalicious,
		Source:   "openssf",
		RiskType: "malware",
	}}, nil
}

func (s *blockingPackageLookupStore) FindReputationFindingsBatch(ctx context.Context, _ []db.PackageQuery, _ string) ([]domain.Finding, error) {
	if err := s.blockLookup(ctx, "reputation"); err != nil {
		return nil, err
	}
	return []domain.Finding{
		{
			Type:     domain.FindingTypeSupplyChainRisk,
			Source:   db.ReputationSourceReversingLabs,
			RiskType: "removed_package",
		},
		{
			Type:     domain.FindingTypeMalicious,
			Source:   db.ReputationSourceReversingLabs,
			RiskType: "malware",
		},
	}, nil
}

func (s *blockingPackageLookupStore) FindLifecycleFindingsBatch(ctx context.Context, _ []db.PackageQuery, _ time.Time) ([]domain.Finding, error) {
	if err := s.blockLookup(ctx, "lifecycle"); err != nil {
		return nil, err
	}
	return []domain.Finding{{
		Type:     domain.FindingTypeLifecycle,
		Source:   "endoflife.date",
		RiskType: "eol",
	}}, nil
}

func (s *blockingPackageLookupStore) blockLookup(ctx context.Context, name string) error {
	if ctx.Value(packageLookupContextTestKey{}) != "request" {
		s.started <- name
		return errors.New("lookup did not receive request context")
	}
	select {
	case s.started <- name:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case <-s.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func sortedLookupNames(names map[string]struct{}) []string {
	sorted := make([]string, 0, len(names))
	for name := range names {
		sorted = append(sorted, name)
	}
	sortStrings(sorted)
	return sorted
}

func renderPackageDetail(t *testing.T, ecosystem, name string) string {
	t.Helper()

	store := &mockStore{}
	handler := HandlePackage(store, testRenderer(), discardLogger())
	req := httptest.NewRequest(http.MethodGet, "/package/"+ecosystem+"/"+name, nil)
	req.SetPathValue("ecosystem", ecosystem)
	req.SetPathValue("name", name)
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Package status = %d, want %d", rec.Code, http.StatusOK)
	}
	return rec.Body.String()
}

func tagContaining(t *testing.T, body, open, marker string) string {
	t.Helper()

	markerIndex := strings.Index(body, marker)
	if markerIndex < 0 {
		t.Fatalf("Body missing marker %q:\n%s", marker, body)
	}
	start := strings.LastIndex(body[:markerIndex], open)
	if start < 0 {
		t.Fatalf("Body missing opening tag %q before %q:\n%s", open, marker, body)
	}
	end := strings.Index(body[markerIndex:], ">")
	if end < 0 {
		t.Fatalf("Body missing tag close after %q:\n%s", marker, body)
	}
	return body[start : markerIndex+end+1]
}
