package web

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/8linkz-sec/packmon/internal/domain"
)

func TestF375AggregateCacheCachesUntilExpiration(t *testing.T) {
	t.Parallel()

	cache := NewAggregateCache[int](time.Minute)
	calls := 0
	load := func(context.Context) (int, error) {
		calls++
		return calls, nil
	}

	for range 2 {
		value, err := cache.Get(context.Background(), load)
		if err != nil {
			t.Fatalf("Get(cached): %v", err)
		}
		if value != 1 {
			t.Fatalf("Get(cached) = %d, want first loaded value 1", value)
		}
	}
	if calls != 1 {
		t.Fatalf("loader calls before expiration = %d, want 1", calls)
	}

	cache.mu.Lock()
	cache.expires = time.Now().Add(-time.Second)
	cache.mu.Unlock()
	value, err := cache.Get(context.Background(), load)
	if err != nil {
		t.Fatalf("Get(expired): %v", err)
	}
	if value != 2 || calls != 2 {
		t.Fatalf("Get(expired) = %d with %d loader calls, want 2 and 2", value, calls)
	}
}

func TestF381PackageHelpersCoverCorrelationAndGenericFallback(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("lookup failed")
	attrs := packageLogArgs(packageLogContext{
		path:           "/package/npm/example",
		nameLength:     7,
		versionPresent: true,
		correlationID:  "corr-123",
	}, "npm", wantErr)
	foundCorrelation := false
	for i := 0; i+1 < len(attrs); i += 2 {
		if attrs[i] == "correlation_id" && attrs[i+1] == "corr-123" {
			foundCorrelation = true
			break
		}
	}
	if !foundCorrelation {
		t.Fatalf("packageLogArgs correlation attrs = %#v", attrs)
	}
	if label := packageFindingFallbackResourceLabel(domain.Finding{}); label != "Finding advisory" {
		t.Fatalf("generic fallback label = %q, want Finding advisory", label)
	}
}

func TestF383RendererCoversPartialLoadAndPartialParseFailures(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	err := NewRendererWithLayoutLinks(fstest.MapFS{}, false, LayoutLinks{}).
		RenderPartial(&out, "missing.html", "fragment", nil)
	if err == nil || !strings.Contains(err.Error(), "render partial missing.html/fragment") || !strings.Contains(err.Error(), "read layout") {
		t.Fatalf("RenderPartial(missing page) error = %v", err)
	}

	for _, tc := range []struct {
		name    string
		partial *fstest.MapFile
		want    string
	}{
		{name: "read", partial: &fstest.MapFile{Mode: fs.ModeDir | 0o755}, want: "read partial"},
		{name: "parse", partial: &fstest.MapFile{Data: []byte(`{{define`)}, want: "parse partial"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fsys := fstest.MapFS{
				"templates/layout.html":       {Data: []byte(`{{define "layout"}}{{template "content" .}}{{end}}`)},
				"templates/partials/bad.html": tc.partial,
				"templates/page.html":         {Data: []byte(`{{define "content"}}ok{{end}}`)},
			}
			err := NewRendererWithLayoutLinks(fsys, true, LayoutLinks{}).Render(&out, "page.html", nil)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Render(%s partial) error = %v, want %q", tc.name, err, tc.want)
			}
		})
	}
}

func TestF383RendererHelperBoundaries(t *testing.T) {
	t.Parallel()

	needs := detectLayoutAssetNeeds(`<div hx-get="/feeds" aria-busy="false"></div>`)
	if !needs.HTMX || !needs.HelperScript {
		t.Fatalf("detectLayoutAssetNeeds(HTMX busy region) = %+v, want both assets", needs)
	}

	funcs := defaultFuncMapWithAssets(LayoutLinks{
		PrivacyURL: "/privacy",
		LegalURL:   "/legal",
		TermsURL:   "/terms",
		HideAdmin:  true,
	}, nil)
	if got := funcs["privacyURL"].(func() string)(); got != "/privacy" {
		t.Fatalf("privacyURL() = %q", got)
	}
	if got := funcs["legalURL"].(func() string)(); got != "/legal" {
		t.Fatalf("legalURL() = %q", got)
	}
	if got := funcs["termsURL"].(func() string)(); got != "/terms" {
		t.Fatalf("termsURL() = %q", got)
	}
	if funcs["layoutNeedsHTMX"].(func() bool)() || funcs["layoutNeedsHelperScript"].(func() bool)() || funcs["adminNavEnabled"].(func() bool)() {
		t.Fatal("default layout closures did not preserve their false/hidden defaults")
	}

	assets := newStaticAssetVersions(fstest.MapFS{})
	if got := assets.URL("../private"); got != "../private" {
		t.Fatalf("URL(invalid path) = %q, want original path", got)
	}
	if got := (*staticAssetVersions)(nil).version("static/app.css"); got != "" {
		t.Fatalf("nil asset versions returned %q", got)
	}
	if got := assets.version("../private"); got != "" {
		t.Fatalf("version(invalid path) = %q", got)
	}
	if got, ok := normalizeStaticAssetFSPath("static/../private"); ok || got != "" {
		t.Fatalf("normalizeStaticAssetFSPath(static escape) = (%q, %v)", got, ok)
	}

	var nilDir *string
	for name, data := range map[string]any{
		"missing map value": map[string]any{},
		"nil map pointer":   map[string]any{"LayoutDir": nilDir},
		"non-string field":  struct{ LayoutDir int }{LayoutDir: 1},
	} {
		if got := layoutDirValue(data); got != "" {
			t.Errorf("%s layoutDirValue = %q, want empty", name, got)
		}
	}

	for input, want := range map[string]string{
		"self":        "Self-managed",
		"external":    "External",
		"custom.mode": "Custom mode",
	} {
		if got := feedModeLabel(input); got != want {
			t.Errorf("feedModeLabel(%q) = %q, want %q", input, got, want)
		}
	}
	if got := readableTokenLabel("---"); got != "Unknown" {
		t.Fatalf("readableTokenLabel(separators) = %q", got)
	}

	success := adminAlertViewFor(map[string]any{"Variant": "success", "Dismissible": true})
	if !success.Success || !success.Dismissible || success.ContainerClass != "pm-alert-success" {
		t.Fatalf("success alert = %+v", success)
	}
	info := adminAlertViewFor(map[string]any{"Variant": "info"})
	if !info.Info || info.IconClass != "pm-alert-icon-info" {
		t.Fatalf("info alert = %+v", info)
	}
	var nilBool *bool
	if adminAlertBoolValue(map[string]any{"Icon": nilBool}, "Icon") {
		t.Fatal("adminAlertBoolValue(typed nil) = true")
	}

	if got := advisoryURL("not-an-advisory"); got != "" {
		t.Fatalf("advisoryURL(unknown) = %q", got)
	}
	if got := advisoryURL("CVE-2026-1234"); !strings.Contains(got, "CVE-2026-1234") {
		t.Fatalf("advisoryURL(CVE) = %q", got)
	}
	if got := truncate("abcd", 2); got != "ab" {
		t.Fatalf("truncate(short maximum) = %q", got)
	}
	if got := findingTypeLabels(" , vulnerability, custom "); len(got) != 2 || got[0] != "Vulnerability" || got[1] != "custom" {
		t.Fatalf("findingTypeLabels = %#v", got)
	}
}

func TestF384NotFoundRenderFailureAndEncodingParameterBoundaries(t *testing.T) {
	t.Parallel()

	recorder := httptest.NewRecorder()
	renderNotFoundPage(
		recorder,
		httptest.NewRequest(http.MethodGet, "/missing", nil),
		NewRendererWithLayoutLinks(fstest.MapFS{}, false, LayoutLinks{}),
		slog.New(slog.DiscardHandler),
		NotFoundData{},
		"public, max-age=60",
	)
	if recorder.Code != http.StatusInternalServerError || recorder.Body.String() != "internal server error\n" {
		t.Fatalf("renderNotFoundPage(render failure) = %d %q", recorder.Code, recorder.Body.String())
	}
	if got := recorder.Header().Get("Cache-Control"); got != "" {
		t.Fatalf("render failure Cache-Control = %q, want empty", got)
	}

	if !encodingQualityZero("invalid; q=0") {
		t.Fatal("encodingQualityZero ignored a later valid q=0 parameter")
	}
	if reservedPublicFallbackPath("/") {
		t.Fatal("reservedPublicFallbackPath(/) = true")
	}
}

func TestF386SearchHelperNeutralAndOverflowBoundaries(t *testing.T) {
	t.Parallel()

	if got := (PackageSearchResult{}).VulnerabilityIDItems(); got != nil {
		t.Fatalf("VulnerabilityIDItems(empty) = %#v, want nil", got)
	}
	if got := packageSearchResultQuery(PackageSearchResult{}, "https://example.test/search"); got != "" {
		t.Fatalf("packageSearchResultQuery(neutral) = %q", got)
	}
	if got := searchTextSegments("", "query"); got != nil {
		t.Fatalf("searchTextSegments(empty text) = %#v, want nil", got)
	}

	maxPage := int(^uint(0)>>1) / searchResultLimit
	if got := parseSearchPage(strconv.Itoa(maxPage + 1)); got != maxPage {
		t.Fatalf("parseSearchPage(overflowing offset) = %d, want %d", got, maxPage)
	}
	if got := validateSearchReturnTo("%"); got != "" {
		t.Fatalf("validateSearchReturnTo(invalid escape) = %q", got)
	}
}
