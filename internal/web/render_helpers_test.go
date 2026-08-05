package web

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"
	"time"
	"unicode/utf8"

	"github.com/8linkz-sec/packmon/internal/db"
)

func TestRenderHelperFunctions(t *testing.T) {
	fixed := time.Date(2026, 5, 30, 12, 34, 0, 0, time.FixedZone("CEST", 2*60*60))
	if got := formatTime(time.Time{}); got != "-" {
		t.Fatalf("formatTime(zero) = %q, want -", got)
	}
	if got := formatTime(fixed); got != "2026-05-30 10:34 UTC" {
		t.Fatalf("formatTime() = %q, want UTC rendering", got)
	}

	now := time.Date(2026, 5, 30, 12, 0, 0, 0, time.UTC)
	agoTests := []struct {
		name string
		when time.Time
		want string
	}{
		{"zero", time.Time{}, "never"},
		{"seconds", now.Add(-5 * time.Second), "just now"},
		{"one minute", now.Add(-1 * time.Minute), "1 minute ago"},
		{"minutes", now.Add(-5 * time.Minute), "5 minutes ago"},
		{"one hour", now.Add(-1 * time.Hour), "1 hour ago"},
		{"hours", now.Add(-5 * time.Hour), "5 hours ago"},
		{"one day", now.Add(-24 * time.Hour), "1 day ago"},
		{"days", now.Add(-72 * time.Hour), "3 days ago"},
		{"future minute", now.Add(2 * time.Minute), "in 2 minutes"},
		{"future hour", now.Add(2 * time.Hour), "in 2 hours"},
	}
	for _, tt := range agoTests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatTimeAgoAt(tt.when, now); got != tt.want {
				t.Fatalf("formatTimeAgoAt() = %q, want %q", got, tt.want)
			}
		})
	}

	fixedTests := map[string]string{
		"":       "",
		" 1.2.3": ">= 1.2.3",
		">= 2":   ">= 2",
		"< 3":    "< 3",
		"= 4":    "= 4",
	}
	for input, want := range fixedTests {
		if got := formatFixedIn(input); got != want {
			t.Fatalf("formatFixedIn(%q) = %q, want %q", input, got, want)
		}
	}

	for _, severity := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "unknown"} {
		if got := severityClass(severity); got == "" {
			t.Fatalf("severityClass(%q) returned empty class", severity)
		}
	}
	for _, status := range []string{"healthy", "warning", "error", "configured", "running", "pending", "disabled", "unknown"} {
		if got := statusClass(status); got == "" {
			t.Fatalf("statusClass(%q) returned empty class", status)
		}
	}

	truncateTests := map[string]string{
		"abc":       "abc",
		"abcdef|3":  "abc",
		"abcdef|4":  "a...",
		"abcdef|10": "abcdef",
	}
	if got := truncate("abc", 10); got != truncateTests["abc"] {
		t.Fatalf("truncate short = %q", got)
	}
	if got := truncate("abcdef", 3); got != truncateTests["abcdef|3"] {
		t.Fatalf("truncate max 3 = %q", got)
	}
	if got := truncate("abcdef", 4); got != truncateTests["abcdef|4"] {
		t.Fatalf("truncate max 4 = %q", got)
	}
	if got := truncate("abcdef", 10); got != truncateTests["abcdef|10"] {
		t.Fatalf("truncate max 10 = %q", got)
	}
	if got := truncate("ääääää", 4); got != "ä..." || !utf8.ValidString(got) {
		t.Fatalf("truncate UTF-8 = %q valid=%v, want %q", got, utf8.ValidString(got), "ä...")
	}
	if got := seq(4); !reflect.DeepEqual(got, []int{0, 1, 2, 3}) {
		t.Fatalf("seq(4) = %#v", got)
	}
	if got := findingTypeLabels("supply_chain_risk, malicious, vulnerability, lifecycle, unknown"); !reflect.DeepEqual(got, []string{"Supply-chain risk", "Malicious package", "Vulnerability", "Lifecycle", "unknown"}) {
		t.Fatalf("findingTypeLabels() = %#v", got)
	}
	if got := feedModeLabel("self"); got != "Self-managed" {
		t.Fatalf("feedModeLabel(self) = %q, want Self-managed", got)
	}
	if got := feedModeLabel("external"); got != "External" {
		t.Fatalf("feedModeLabel(external) = %q, want External", got)
	}
	if got := feedModeLabel("custom_mode"); got != "Custom mode" {
		t.Fatalf("feedModeLabel(custom_mode) = %q, want Custom mode", got)
	}
}

func TestDefaultFuncMapIncludesTemplateHelpers(t *testing.T) {
	funcs := defaultFuncMap(LayoutLinks{PrivacyURL: "/privacy", LegalURL: "/legal", TermsURL: "/terms"})
	if funcs["formatTime"] == nil || funcs["formatTimeAgo"] == nil || funcs["statusClass"] == nil || funcs["findingLabels"] == nil || funcs["feedModeLabel"] == nil || funcs["dict"] == nil || funcs["layoutDir"] == nil || funcs["adminAlert"] == nil || funcs["assetURL"] == nil || funcs["t"] == nil || funcs["word"] == nil {
		t.Fatalf("defaultFuncMap missing expected helper: %#v", funcs)
	}
	messageFn, ok := funcs["t"].(func(string, ...any) string)
	if !ok {
		t.Fatalf("t helper has unexpected type %T", funcs["t"])
	}
	if got := messageFn("nav.search"); got != "Search" {
		t.Fatalf("t(nav.search) = %q, want Search", got)
	}
	if got := messageFn("link.new_tab.aria_label", "Advisory"); got != "Advisory opens in a new tab" {
		t.Fatalf("t(link.new_tab.aria_label) = %q, want interpolated message", got)
	}
	if got := messageFn("missing.key"); got != "missing.key" {
		t.Fatalf("t(missing.key) = %q, want fallback key", got)
	}
	wordFn, ok := funcs["word"].(func(int, string, string) string)
	if !ok {
		t.Fatalf("word helper has unexpected type %T", funcs["word"])
	}
	if got := wordFn(2, "result", "results"); got != "results" {
		t.Fatalf("word helper = %q, want results", got)
	}
	dictFn, ok := funcs["dict"].(func(...any) (map[string]any, error))
	if !ok {
		t.Fatalf("dict helper has unexpected type %T", funcs["dict"])
	}
	dict, err := dictFn("Variant", "warning", "Icon", true)
	if err != nil {
		t.Fatalf("dict helper error = %v", err)
	}
	if dict["Variant"] != "warning" || dict["Icon"] != true {
		t.Fatalf("dict helper = %#v, want populated map", dict)
	}
	if _, err := dictFn("odd"); err == nil {
		t.Fatal("dict helper odd argument count error = nil, want error")
	}
	if _, err := dictFn(3, "bad"); err == nil {
		t.Fatal("dict helper non-string key error = nil, want error")
	}
	if got := funcs["add"].(func(int, int) int)(2, 3); got != 5 {
		t.Fatalf("add helper = %d, want 5", got)
	}
	if got := funcs["sub"].(func(int, int) int)(7, 4); got != 3 {
		t.Fatalf("sub helper = %d, want 3", got)
	}
	if got := funcs["privacyURL"].(func() string)(); got != "/privacy" {
		t.Fatalf("privacyURL helper = %q, want /privacy", got)
	}
	if got := funcs["legalURL"].(func() string)(); got != "/legal" {
		t.Fatalf("legalURL helper = %q, want /legal", got)
	}
	if got := funcs["termsURL"].(func() string)(); got != "/terms" {
		t.Fatalf("termsURL helper = %q, want /terms", got)
	}
	assetURLFn, ok := funcs["assetURL"].(func(string) string)
	if !ok {
		t.Fatalf("assetURL helper has unexpected type %T", funcs["assetURL"])
	}
	if got := assetURLFn("/static/style.css"); !strings.HasPrefix(got, "/static/style.css?v=") {
		t.Fatalf("assetURL(/static/style.css) = %q, want versioned static URL", got)
	}
	layoutDirFn, ok := funcs["layoutDir"].(func(any) string)
	if !ok {
		t.Fatalf("layoutDir helper has unexpected type %T", funcs["layoutDir"])
	}
	if got := layoutDirFn(map[string]any{"LayoutDir": "rtl"}); got != "rtl" {
		t.Fatalf("layoutDir(map rtl) = %q, want rtl", got)
	}
	if got := layoutDirFn(struct{ LayoutDir string }{LayoutDir: "auto"}); got != "auto" {
		t.Fatalf("layoutDir(struct auto) = %q, want auto", got)
	}
	if got := layoutDirFn(map[string]any{"LayoutDir": "sideways"}); got != "ltr" {
		t.Fatalf("layoutDir(invalid) = %q, want ltr", got)
	}
}

func TestPublicShellSearchAndFeedTemplatesUseMessageKeys(t *testing.T) {
	t.Parallel()

	cases := []struct {
		path string
		want []string
	}{
		{
			path: "templates/layout.html",
			want: []string{
				`{{t "a11y.skip_to_main"}}`,
				`aria-label="{{t "nav.primary"}}"`,
				`{{t "nav.dashboard"}}`,
				`{{t "nav.search"}}`,
				`{{t "nav.feeds"}}`,
				`{{t "nav.admin"}}`,
				`{{t "footer.product"}}`,
				`{{t "footer.privacy"}}`,
				`{{t "footer.legal"}}`,
				`{{t "footer.terms"}}`,
			},
		},
		{
			path: "templates/search.html",
			want: []string{
				`{{t "page.search.title"}}`,
				`{{t "search.heading"}}`,
				`{{t "search.input.label"}}`,
				`{{t "search.status.ready"}}`,
				`{{t "search.empty.initial"}}`,
				`{{t "search.table.label"}}`,
			},
		},
		{
			path: "templates/feeds.html",
			want: []string{
				`{{t "page.feeds.title"}}`,
				`{{t "feeds.heading"}}`,
				`{{t "feeds.refresh.auto_label"}}`,
				`{{t "feeds.status.updated_count"`,
				`{{t "feeds.table.label"}}`,
				`{{t "feeds.empty"}}`,
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			t.Parallel()

			body := readTextFile(t, tc.path)
			for _, want := range tc.want {
				if !strings.Contains(body, want) {
					t.Fatalf("%s missing message key marker %q:\n%s", tc.path, want, body)
				}
			}
		})
	}
}

func TestRemainingPublicTemplatesUseMessageKeys(t *testing.T) {
	t.Parallel()

	cases := []struct {
		path string
		want []string
	}{
		{
			path: "templates/dashboard.html",
			want: []string{
				`{{t "page.dashboard.title"}}`,
				`{{t "dashboard.table.version"}}`,
				`{{t "dashboard.table.ecosystem"}}`,
				`{{t "dashboard.recent_vulnerabilities.heading"}}`,
				`{{t "dashboard.recent_vulnerabilities.empty"}}`,
			},
		},
		{
			path: "templates/package.html",
			want: []string{
				`{{t "package.breadcrumb.search"}}`,
				`{{t "package.version.label"}}`,
				`{{t "package.action.check_version"}}`,
				`{{t "package.malicious.heading"`,
				`{{t "package.vulnerabilities.empty"}}`,
				`{{t "package.lifecycle.empty_version_required"}}`,
			},
		},
		{
			path: "templates/partials/package_risk_finding_table.html",
			want: []string{
				`{{t "package.table.severity"}}`,
				`{{t "package.table.advisory"}}`,
				`{{t "package.table.risk_type"}}`,
				`{{t "package.table.resources"}}`,
			},
		},
		{
			path: "templates/scans.html",
			want: []string{
				`{{t "page.scans.title"}}`,
				`{{t "scans.heading"}}`,
				`{{t "scans.activity.heading"}}`,
				`{{t "scans.recent.empty"}}`,
			},
		},
		{
			path: "templates/privacy.html",
			want: []string{
				`{{t "page.privacy.title"}}`,
				`{{t "privacy.heading"}}`,
				`{{t "privacy.session.heading"}}`,
				`{{t "privacy.operator_notice.heading"}}`,
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			t.Parallel()

			body := readTextFile(t, tc.path)
			for _, want := range tc.want {
				if !strings.Contains(body, want) {
					t.Fatalf("%s missing message key marker %q:\n%s", tc.path, want, body)
				}
			}
		})
	}
}

func TestAdminOperationTemplatesUseMessageKeys(t *testing.T) {
	t.Parallel()

	cases := []struct {
		path string
		want []string
	}{
		{
			path: "templates/admin/settings.html",
			want: []string{
				`{{t "page.admin.settings.title"}}`,
				`(t "admin.settings.heading")`,
				`{{t "admin.settings.runtime.heading"}}`,
				`data-submit-lock-label="{{t "admin.settings.system.saving"}}`,
				`{{t "admin.settings.system.save"}}`,
				`{{t "admin.settings.password.heading"}}`,
				`data-password-mismatch-message="{{t "admin.settings.password.mismatch"}}`,
				`{{t "admin.settings.password.change"}}`,
			},
		},
		{
			path: "templates/admin/keys.html",
			want: []string{
				`{{t "page.admin.keys.title"}}`,
				`(t "admin.keys.heading")`,
				`{{t "admin.keys.created_notice"}}`,
				`aria-label="{{t "admin.keys.copy_aria"}}`,
				`data-submit-lock-label="{{t "admin.keys.create.saving"}}`,
				`{{t "admin.keys.create.submit"}}`,
				`aria-label="{{t "admin.keys.action.revoke_aria" .Key.Name .Key.ID}}"`,
				`data-submit-lock-label="{{t "admin.keys.action.revoking"}}`,
				`{{t "admin.keys.action.confirm_revoke"}}`,
			},
		},
		{
			path: "templates/admin/advisories.html",
			want: []string{
				`{{t "page.admin.advisories.title"}}`,
				`(t "admin.advisories.heading")`,
				`{{if .IsEditing}}{{t "admin.advisories.form.edit_heading"}}{{else}}{{t "admin.advisories.form.create_heading"}}{{end}}`,
				`data-submit-lock-label="{{t "admin.advisories.form.saving"}}`,
				`{{if .IsEditing}}{{t "admin.advisories.form.save"}}{{else}}{{t "admin.advisories.form.create"}}{{end}}`,
				`aria-label="{{t "admin.advisories.action.delete_aria" .Advisory.ID .Advisory.Ecosystem .Advisory.Name}}"`,
				`data-submit-lock-label="{{t "admin.advisories.action.deleting"}}`,
				`{{t "admin.advisories.action.confirm_delete"}}`,
			},
		},
		{
			path: "templates/admin/queue.html",
			want: []string{
				`{{t "page.admin.queue.title"}}`,
				`(t "admin.queue.heading")`,
				`aria-label="{{t "admin.queue.row.actions_aria" $job.ID $job.Ecosystem $job.Name}}"`,
				`data-submit-lock-label="{{t "admin.queue.row.priority.saving"}}`,
				`aria-label="{{t "admin.queue.row.priority.save_aria" $job.ID $job.Ecosystem $job.Name}}"`,
				`{{t "admin.queue.row.priority.save"}}`,
				`aria-label="{{t "admin.queue.bulk.purge_aria"}}`,
				`data-submit-lock-label="{{t "admin.queue.bulk.purging"}}`,
				`{{t "admin.queue.bulk.confirm_purge"}}`,
			},
		},
		{
			path: "templates/admin/feeds.html",
			want: []string{
				`{{t "page.admin.feeds.title"}}`,
				`(t "admin.feeds.heading")`,
				`{{t "admin.feeds.runtime.heading"}}`,
				`{{$configEnabledLabel := t "admin.feeds.status.disabled"}}{{if .ConfigEnabled}}{{$configEnabledLabel = t "admin.feeds.status.enabled"}}{{end}}`,
				`(t "admin.feeds.status.sync" .SyncIntervalStr)`,
				`(t "admin.feeds.status.key" .APIKeyState)`,
				`data-submit-lock-label="{{t "admin.feeds.form.saving"}}`,
				`aria-label="{{t "admin.feeds.form.save_aria" .FeedName}}"`,
				`data-feed-sync-label="{{t "admin.feeds.sync.button"}}`,
				`data-feed-sync-busy-label="{{t "admin.feeds.sync.busy"}}`,
				`data-submit-lock-label="{{t "admin.feeds.reset.saving"}}`,
				`aria-label="{{t "admin.feeds.reset.aria" .FeedName}}"`,
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			t.Parallel()

			body := readTextFile(t, tc.path)
			for _, want := range tc.want {
				if !strings.Contains(body, want) {
					t.Fatalf("%s missing admin operation message key marker %q:\n%s", tc.path, want, body)
				}
			}
		})
	}
}

func TestPublicHandlersUseMessageCatalogForAlertText(t *testing.T) {
	t.Parallel()

	cases := []struct {
		path string
		want []string
	}{
		{
			path: "dashboard.go",
			want: []string{
				`webMessage(webMessageKey("dashboard.error.stats"))`,
				`webMessage(webMessageKey("dashboard.error.recent_vulnerabilities"))`,
			},
		},
		{
			path: "search.go",
			want: []string{
				`webMessage(webMessageKey("search.error.query_too_long")`,
				`webMessage(webMessageKey("search.error.query_too_short")`,
				`webMessage(webMessageKey("search.error.failed"))`,
				`webMessage(webMessageKey("search.error.invalid_filter")`,
			},
		},
		{
			path: "package.go",
			want: []string{
				`webMessage(webMessageKey("package.error.version_too_long")`,
				`webMessage(webMessageKey("package.error.vulnerabilities"))`,
				`webMessage(webMessageKey("package.error.malicious"))`,
				`webMessage(webMessageKey("package.error.reputation"))`,
				`webMessage(webMessageKey("package.error.lifecycle"))`,
			},
		},
		{
			path: "feeds.go",
			want: []string{
				`webMessage(webMessageKey("feeds.error.load_status"))`,
			},
		},
		{
			path: "scans.go",
			want: []string{
				`webMessage(webMessageKey("scans.error.activity"))`,
				`webMessage(webMessageKey("scans.error.recent"))`,
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			t.Parallel()

			source := readTextFile(t, tc.path)
			for _, want := range tc.want {
				if !strings.Contains(source, want) {
					t.Fatalf("%s missing handler message marker %q:\n%s", tc.path, want, source)
				}
			}
		})
	}
}

func TestAdminAlertViewDerivesVariantPresentation(t *testing.T) {
	alert := adminAlertViewFor(map[string]any{
		"Variant": "error",
		"Icon":    true,
		"Live":    true,
	})
	if alert.Variant != "error" || !alert.Icon || !alert.Live {
		t.Fatalf("adminAlertViewFor preserved fields = %+v, want error/icon/live", alert)
	}
	if alert.Role != "alert" || alert.AriaLive != "assertive" {
		t.Fatalf("adminAlertViewFor live attrs = role %q aria-live %q, want alert/assertive", alert.Role, alert.AriaLive)
	}
	if alert.ContainerClass != "pm-alert-error" || alert.IconClass != "pm-alert-icon-error" {
		t.Fatalf("adminAlertViewFor classes = container %q icon %q, want semantic error classes", alert.ContainerClass, alert.IconClass)
	}

	warning := adminAlertViewFor(map[string]any{"Variant": "warning", "Live": true})
	if warning.Role != "status" || warning.AriaLive != "polite" {
		t.Fatalf("warning live attrs = role %q aria-live %q, want status/polite", warning.Role, warning.AriaLive)
	}
	if warning.ContainerClass != "pm-alert-warning" || warning.IconClass != "pm-alert-icon-warning" {
		t.Fatalf("warning classes = container %q icon %q, want semantic warning classes", warning.ContainerClass, warning.IconClass)
	}

	fallback := adminAlertViewFor(map[string]any{"Variant": "custom"})
	if fallback.Variant != "custom" || fallback.ContainerClass != "pm-alert-default" || fallback.IconClass != "pm-alert-icon-default" {
		t.Fatalf("fallback alert = %+v, want custom variant with semantic default classes", fallback)
	}
}

func TestDetectLayoutAssetNeedsLoadsHelperForAdminFlashAlerts(t *testing.T) {
	t.Parallel()

	needs := detectLayoutAssetNeeds(`{{template "admin-flash-alerts" .}}`)
	if !needs.HelperScript {
		t.Fatalf("detectLayoutAssetNeeds(admin flash partial) HelperScript = false, want true")
	}
	if needs.HTMX {
		t.Fatalf("detectLayoutAssetNeeds(admin flash partial) HTMX = true, want false")
	}
}

func TestSharedLayoutSupportsExplicitDirectionAndDynamicViewport(t *testing.T) {
	t.Parallel()

	layout := readTextFile(t, "templates", "layout.html")
	for _, want := range []string{
		`<html lang="en" dir="{{layoutDir .}}" data-pm-theme="system">`,
		`min-h-dvh`,
	} {
		if !strings.Contains(layout, want) {
			t.Fatalf("layout missing %q:\n%s", want, layout)
		}
	}
	oldViewportClass := "min-h-" + "screen"
	if strings.Contains(layout, oldViewportClass) {
		t.Fatalf("layout still uses %s instead of dynamic viewport height:\n%s", oldViewportClass, layout)
	}

	renderer := testRenderer()
	var out strings.Builder
	if err := renderer.Render(&out, "not_found.html", map[string]any{"LayoutDir": "rtl"}); err != nil {
		t.Fatalf("Render(rtl) error = %v", err)
	}
	if body := out.String(); !strings.Contains(body, `<html lang="en" dir="rtl" data-pm-theme="system">`) {
		t.Fatalf("rendered layout missing explicit rtl dir:\n%s", body)
	}

	out.Reset()
	if err := renderer.Render(&out, "not_found.html", nil); err != nil {
		t.Fatalf("Render(default) error = %v", err)
	}
	if body := out.String(); !strings.Contains(body, `<html lang="en" dir="ltr" data-pm-theme="system">`) {
		t.Fatalf("rendered layout missing default ltr dir:\n%s", body)
	}
}

func TestRenderHelperFutureAndBoundaryBranches(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 30, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		when time.Time
		want string
	}{
		{"future less than minute", now.Add(30 * time.Second), "in less than a minute"},
		{"future one minute", now.Add(time.Minute + time.Second), "in 1 minute"},
		{"future one hour", now.Add(time.Hour + time.Minute), "in 1 hour"},
		{"future one day", now.Add(24*time.Hour + time.Minute), "in 1 day"},
		{"future days", now.Add(72*time.Hour + time.Minute), "in 3 days"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatTimeAgoAt(tt.when, now); got != tt.want {
				t.Fatalf("formatTimeAgoAt() = %q, want %q", got, tt.want)
			}
		})
	}
	if got := seq(0); len(got) != 0 {
		t.Fatalf("seq(0) = %#v, want empty", got)
	}
}

func TestRendererCacheAndParseErrorBranches(t *testing.T) {
	t.Parallel()

	okFS := fstest.MapFS{
		"templates/layout.html": {Data: []byte(`{{define "layout"}}<main>{{template "content" .}}</main>{{end}}`)},
		"templates/page.html":   {Data: []byte(`{{define "content"}}{{.Name}}{{end}}`)},
	}
	renderer := NewRendererWithLayoutLinks(okFS, false, LayoutLinks{})
	var out strings.Builder
	if err := renderer.Render(&out, "page.html", map[string]string{"Name": "first"}); err != nil {
		t.Fatalf("Render(first) error = %v", err)
	}
	if err := renderer.Render(&out, "page.html", map[string]string{"Name": "second"}); err != nil {
		t.Fatalf("Render(cached) error = %v", err)
	}
	if len(renderer.cache) != 1 {
		t.Fatalf("cache len = %d, want 1", len(renderer.cache))
	}

	err := NewRendererWithLayoutLinks(fstest.MapFS{}, false, LayoutLinks{}).Render(&out, "page.html", nil)
	if err == nil || !strings.Contains(err.Error(), "read layout") {
		t.Fatalf("Render(missing layout) error = %v", err)
	}
	err = NewRendererWithLayoutLinks(fstest.MapFS{
		"templates/layout.html": {Data: []byte(`{{define`)},
		"templates/page.html":   {Data: []byte(`{{define "content"}}ok{{end}}`)},
	}, true, LayoutLinks{}).Render(&out, "page.html", nil)
	if err == nil || !strings.Contains(err.Error(), "parse layout") {
		t.Fatalf("Render(bad layout) error = %v", err)
	}
	err = NewRendererWithLayoutLinks(fstest.MapFS{
		"templates/layout.html": {Data: []byte(`{{define "layout"}}{{template "content" .}}{{end}}`)},
		"templates/page.html":   {Data: []byte(`{{define`)},
	}, true, LayoutLinks{}).Render(&out, "page.html", nil)
	if err == nil || !strings.Contains(err.Error(), "parse page") {
		t.Fatalf("Render(bad page) error = %v", err)
	}
}

func TestRendererReturnsTemplateErrors(t *testing.T) {
	renderer := testRenderer()

	var out strings.Builder
	if err := renderer.Render(&out, "missing.html", nil); err == nil || !strings.Contains(err.Error(), "read page") {
		t.Fatalf("Render(missing) error = %v, want read page error", err)
	}
	if err := renderer.RenderPartial(&out, "feeds.html", "missing-block", nil); err == nil || !strings.Contains(err.Error(), "missing-block") {
		t.Fatalf("RenderPartial(missing block) error = %v, want missing block error", err)
	}
}

func TestAssetURLFingerprintComesFromRendererFilesystem(t *testing.T) {
	t.Parallel()

	const assetBody = "body{color:#123456}"
	sum := sha256.Sum256([]byte(assetBody))
	want := "/static/app.css?v=" + hex.EncodeToString(sum[:])[:16]
	renderer := NewRendererWithLayoutLinks(fstest.MapFS{
		"templates/layout.html": {Data: []byte(`{{define "layout"}}<link href="{{assetURL "/static/app.css"}}">{{template "content" .}}{{end}}`)},
		"templates/page.html":   {Data: []byte(`{{define "content"}}ok{{end}}`)},
		"static/app.css":        {Data: []byte(assetBody)},
	}, false, LayoutLinks{})

	var out strings.Builder
	if err := renderer.Render(&out, "page.html", nil); err != nil {
		t.Fatalf("Render(page) error = %v", err)
	}
	if body := out.String(); !strings.Contains(body, want) {
		t.Fatalf("rendered asset URL = %q, want content fingerprint %q", body, want)
	}
}

func TestHandleDashboardTemplateErrorReturnsCleanFallback(t *testing.T) {
	renderer := NewRendererWithLayoutLinks(fstest.MapFS{
		"templates/layout.html":    {Data: []byte(`{{define "layout"}}leaked dashboard prefix{{dict "odd"}}{{end}}`)},
		"templates/dashboard.html": {Data: []byte(`{{define "content"}}dashboard{{end}}`)},
	}, true, LayoutLinks{})
	handler := HandleDashboard(&mockStore{}, renderer, discardLogger())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%q", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if strings.Contains(body, "leaked dashboard prefix") {
		t.Fatalf("response leaked partial template output before fallback:\n%s", body)
	}
	if body != "internal server error\n" {
		t.Fatalf("body = %q, want clean fallback", body)
	}
}

func TestRenderPartialTemplateErrorDoesNotWritePartialOutput(t *testing.T) {
	renderer := NewRendererWithLayoutLinks(fstest.MapFS{
		"templates/layout.html":  {Data: []byte(`{{define "layout"}}{{template "content" .}}{{end}}`)},
		"templates/partial.html": {Data: []byte(`{{define "content"}}ok{{end}}{{define "broken-partial"}}leaked partial prefix{{dict "odd"}}{{end}}`)},
	}, true, LayoutLinks{})

	var out strings.Builder
	err := renderer.RenderPartial(&out, "partial.html", "broken-partial", nil)
	if err == nil {
		t.Fatal("RenderPartial() error = nil, want template execution error")
	}
	if strings.Contains(out.String(), "leaked partial prefix") {
		t.Fatalf("RenderPartial leaked output on template error: %q", out.String())
	}
	if out.String() != "" {
		t.Fatalf("RenderPartial output = %q, want empty output on template error", out.String())
	}
}

func TestSortStringsOrdersInPlace(t *testing.T) {
	values := []string{"osv", "ghsa", "reversinglabs", "cisa"}
	sortStrings(values)
	if !reflect.DeepEqual(values, []string{"cisa", "ghsa", "osv", "reversinglabs"}) {
		t.Fatalf("sortStrings() = %#v", values)
	}

	sortStrings(nil)
	sortStrings([]string{"only"})
}

type scansStore struct {
	*mockStore
	daily []db.DailyScanStats
	scans []db.ScanLogEntry
}

func (s scansStore) CountScansByDay(_ context.Context, days int) ([]db.DailyScanStats, error) {
	if days != 7 {
		panic("unexpected days")
	}
	return s.daily, nil
}

func (s scansStore) ListRecentScans(_ context.Context, limit, offset int) ([]db.ScanLogEntry, error) {
	if limit != recentScansPageSize+1 {
		panic("unexpected limit")
	}
	if offset != 0 {
		panic("unexpected offset")
	}
	return s.scans, nil
}

func TestHandleScansRendersTrendsAndRecentScans(t *testing.T) {
	now := time.Now().UTC()
	fullScanID := "scan-1234567890abcdef1234567890abcdef"
	store := scansStore{
		mockStore: &mockStore{},
		daily: []db.DailyScanStats{
			{Date: now.AddDate(0, 0, -1), ScanCount: 2, FindingsCount: 0},
			{Date: now, ScanCount: 3, FindingsCount: 10},
			{Date: now.AddDate(0, 0, -2), ScanCount: 1, FindingsCount: 1},
		},
		scans: []db.ScanLogEntry{
			{ScanID: fullScanID, RepoName: "student-repo-secret", ScannedAt: now, PackagesCount: 4, FindingsCount: 2, DurationMs: 123},
		},
	}
	handler := HandleScans(store, testRenderer(), discardLogger())

	req := httptest.NewRequest(http.MethodGet, "/scans", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("HandleScans status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"Scan Activity",
		"Recent Scans",
		"Date (UTC)",
		"Relative findings",
		`<progress value="100" max="100"`,
		`class="scan-findings-meter scan-findings-meter--risk"`,
		`aria-label="10 findings; relative bar 100% of the highest finding day in this table"`,
		fullScanID,
		`title="` + fullScanID + `"`,
		"break-all",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("HandleScans response missing %q:\n%s", want, body)
		}
	}
	for _, notWant := range []string{"student-repo-secret", ">Repo<", `<th class="pb-2"></th>`} {
		if strings.Contains(body, notWant) {
			t.Fatalf("HandleScans response contains %q:\n%s", notWant, body)
		}
	}
	if strings.Contains(body, "scan-1234...") {
		t.Fatalf("HandleScans response contains truncated scan ID:\n%s", body)
	}
}

func TestHandleScansStoreErrorsRenderLoadErrors(t *testing.T) {
	handler := HandleScans(&mockStore{
		dailyErr: errors.New("daily unavailable"),
		scansErr: errors.New("scans unavailable"),
	}, testRenderer(), discardLogger())

	req := httptest.NewRequest(http.MethodGet, "/scans", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("HandleScans error status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"Scan activity could not be loaded",
		"Recent scans could not be loaded",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("HandleScans error response missing %q:\n%s", want, body)
		}
	}
	for _, notWant := range []string{
		"No scan activity yet.",
		"No scans recorded yet.",
	} {
		if strings.Contains(body, notWant) {
			t.Fatalf("HandleScans error response rendered empty state %q:\n%s", notWant, body)
		}
	}
}
