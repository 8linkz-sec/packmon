package web

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestTailwindV4AssetsAreConfiguredAndGenerated(t *testing.T) {
	t.Parallel()

	packageJSON := readTextFile(t, "..", "..", "package.json")
	var pkg struct {
		Scripts         map[string]string `json:"scripts"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal([]byte(packageJSON), &pkg); err != nil {
		t.Fatalf("parse package.json: %v", err)
	}

	if got := pkg.DevDependencies["tailwindcss"]; !strings.HasPrefix(got, "4.") {
		t.Fatalf("tailwindcss dependency = %q, want v4", got)
	}
	if got := pkg.DevDependencies["@tailwindcss/cli"]; !strings.HasPrefix(got, "4.") {
		t.Fatalf("@tailwindcss/cli dependency = %q, want v4", got)
	}
	if got := pkg.Scripts["build:web:css"]; !strings.Contains(got, "tailwindcss ") || strings.Contains(got, "npx") {
		t.Fatalf("build:web:css = %q, want lockfile-managed local tailwindcss binary", got)
	}

	inputCSS := readTextFile(t, "static", "tailwind.input.css")
	for _, want := range []string{
		`@import "tailwindcss" source(none);`,
		`@config "../../../tailwind.config.js";`,
		`@source "../templates";`,
		`@source "../*.go";`,
	} {
		if !strings.Contains(inputCSS, want) {
			t.Fatalf("tailwind.input.css missing %q:\n%s", want, inputCSS)
		}
	}

	outputCSS := readTextFile(t, "static", "tailwind.css")
	for _, want := range []string{
		".rounded{",
		".shadow{",
		".space-y-4>",
		".flex-wrap{",
		".min-h-11{",
		".border-gray-200{",
		".bg-blue-600{",
		".hover\\:bg-blue-700:hover",
		".focus\\:ring-blue-500:focus",
	} {
		if !strings.Contains(outputCSS, want) {
			t.Fatalf("tailwind.css missing generated selector %q", want)
		}
	}
}

func TestCustomStylesHonorReducedMotion(t *testing.T) {
	t.Parallel()

	styleCSS := readTextFile(t, "static", "style.css")
	for _, want := range []string{
		"@media (prefers-reduced-motion: reduce)",
		"transition: none !important",
		"animation-duration: 0.01ms !important",
		"scroll-behavior: auto !important",
	} {
		if !strings.Contains(styleCSS, want) {
			t.Fatalf("style.css missing reduced-motion rule %q:\n%s", want, styleCSS)
		}
	}
}

func TestCustomStylesUseSafeWrappingAndPrintRules(t *testing.T) {
	t.Parallel()

	styleCSS := readTextFile(t, "static", "style.css")
	for _, want := range []string{
		"overflow-wrap: anywhere",
		"word-break: normal",
		"@media print",
		"form[action=\"/admin/logout\"]",
		"overflow: visible !important",
		"break-inside: avoid",
		"background: #dc2626",
		"background: #16a34a",
	} {
		if !strings.Contains(styleCSS, want) {
			t.Fatalf("style.css missing safe wrapping/print/progress marker %q:\n%s", want, styleCSS)
		}
	}
	if strings.Contains(styleCSS, "word-break: break-all") {
		t.Fatalf("style.css still applies break-all to every code element:\n%s", styleCSS)
	}
}

func TestCustomStylesProvideForcedColorsFocusFallback(t *testing.T) {
	t.Parallel()

	styleCSS := readTextFile(t, "static", "style.css")
	for _, want := range []string{
		"@media (forced-colors: active)",
		"outline: 2px solid CanvasText",
		"outline-offset: 2px",
		"box-shadow: none !important",
	} {
		if !strings.Contains(styleCSS, want) {
			t.Fatalf("style.css missing forced-colors focus fallback %q:\n%s", want, styleCSS)
		}
	}
}

func TestCustomStylesSuppressNoPrintContent(t *testing.T) {
	t.Parallel()

	styleCSS := readTextFile(t, "static", "style.css")
	for _, want := range []string{
		"@media print",
		".no-print",
		"[data-no-print]",
		"display: none !important",
	} {
		if !strings.Contains(styleCSS, want) {
			t.Fatalf("style.css missing no-print rule %q:\n%s", want, styleCSS)
		}
	}
}

func TestWebTemplatesAvoidLowContrastTokens(t *testing.T) {
	t.Parallel()

	for _, path := range allTemplateFiles(t) {
		body := readTextFile(t, path)
		for _, blocked := range []string{
			"text-gray-400",
			"text-yellow-600",
			"bg-gray-100 text-gray-500",
			"border-green-600 bg-green-600 text-white",
			"opacity-50",
		} {
			if strings.Contains(body, blocked) {
				t.Fatalf("%s still uses low-contrast token %q", path, blocked)
			}
		}
	}
}

func TestWebTemplatesUseContrastSafeControlBorders(t *testing.T) {
	t.Parallel()

	for _, path := range allTemplateFiles(t) {
		body := readTextFile(t, path)
		if strings.Contains(body, "border-gray-300") {
			t.Fatalf("%s still uses low-contrast border-gray-300", path)
		}
	}
}

func TestAdminFeedConfigurationControlsUseFocusToken(t *testing.T) {
	t.Parallel()

	body := readTextFile(t, "templates", "admin", "feeds.html")
	for _, want := range []string{
		`name="enabled" {{if .Enabled}}checked{{end}} class="rounded border-gray-500 text-blue-600 focus:ring-2 focus:ring-blue-500 focus:ring-offset-2"`,
		`name="mode" class="w-full border border-gray-500 rounded-md px-3 py-2 text-sm bg-white focus:border-blue-500 focus:outline-none focus:ring-2 focus:ring-blue-500"`,
		`name="sync_interval"`,
		`class="w-full border border-gray-500 rounded-md px-3 py-2 text-sm focus:border-blue-500 focus:outline-none focus:ring-2 focus:ring-blue-500"`,
		`name="api_key"`,
		`name="clear_api_key" aria-describedby="feed-{{.FeedKey}}-clear-key-help" class="h-4 w-4 rounded border-gray-500 text-blue-600 focus:ring-2 focus:ring-blue-500 focus:ring-offset-2"`,
		`name="confirm_clear_api_key" class="h-4 w-4 rounded border-red-300 text-red-600 focus:ring-2 focus:ring-red-500 focus:ring-offset-2"`,
		`aria-label="Save {{.FeedName}} feed settings" class="bg-blue-600 text-white px-4 py-2 rounded-md text-sm font-medium hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2"`,
		`aria-label="Sync {{.FeedName}} now"`,
		`class="border border-blue-300 text-blue-700 px-4 py-2 rounded-md text-sm font-medium hover:bg-blue-50 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2"`,
		`name="confirm_reset" class="rounded border-red-300 text-red-600 focus:ring-2 focus:ring-red-500 focus:ring-offset-2"`,
		`aria-label="Reset {{.FeedName}} feed settings" class="border border-gray-500 text-gray-700 px-4 py-2 rounded-md text-sm font-medium hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("admin feed template missing focus token fragment %q", want)
		}
	}
}

func TestAdminFeedConfigurationEditorsAreCollapsedByDefault(t *testing.T) {
	t.Parallel()

	body := readTextFile(t, "templates", "admin", "feeds.html")
	for _, want := range []string{
		`<details class="border border-gray-200 rounded-lg" data-feed-key="{{.FeedKey}}">`,
		`<summary class="flex cursor-pointer list-none flex-col gap-2 p-4 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:ring-offset-2 sm:flex-row sm:items-start sm:justify-between">`,
		`<div class="border-t border-gray-200 p-4">`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("admin feed template missing collapsed editor fragment %q", want)
		}
	}
	if strings.Contains(body, `<div class="border border-gray-200 rounded-lg p-4" data-feed-key="{{.FeedKey}}">`) {
		t.Fatal("admin feed template still renders every editor as an expanded card")
	}
}

func TestAdminLogoutButtonsAreTouchTargets(t *testing.T) {
	t.Parallel()

	logoutForm := regexp.MustCompile(`(?s)<form action="/admin/logout"[^>]*>.*?</form>`)
	for _, path := range allTemplateFiles(t) {
		body := readTextFile(t, path)
		for _, form := range logoutForm.FindAllString(body, -1) {
			for _, want := range []string{
				`inline-flex`,
				`min-h-11`,
				`rounded-md`,
				`px-3`,
				`py-2`,
				`focus:ring-2`,
			} {
				if !strings.Contains(form, want) {
					t.Fatalf("%s logout form missing touch/focus target fragment %q:\n%s", path, want, form)
				}
			}
			if strings.Contains(form, `underline`) {
				t.Fatalf("%s logout form still uses undersized text-link styling:\n%s", path, form)
			}
		}
	}
}

func TestAdminFeedDestructiveKeyControlsAreLargeAndContextual(t *testing.T) {
	t.Parallel()

	body := readTextFile(t, "templates", "admin", "feeds.html")
	for _, want := range []string{
		`Vendor API usage may be billed or rate limited by the provider.`,
		`class="mt-2 flex min-h-11 items-center gap-2 rounded-md px-2 py-2 text-sm text-gray-700 hover:bg-gray-50"`,
		`name="clear_api_key" aria-describedby="feed-{{.FeedKey}}-clear-key-help" class="h-4 w-4 rounded border-gray-500 text-blue-600 focus:ring-2 focus:ring-blue-500 focus:ring-offset-2"`,
		`class="mt-1 flex min-h-11 items-center gap-2 rounded-md px-2 py-2 text-sm text-red-700 hover:bg-red-50"`,
		`name="confirm_clear_api_key" class="h-4 w-4 rounded border-red-300 text-red-600 focus:ring-2 focus:ring-red-500 focus:ring-offset-2"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("admin feed template missing destructive key control/context fragment %q", want)
		}
	}
}

func TestFilledActionButtonsUseSharedFocusRing(t *testing.T) {
	t.Parallel()

	filledButton := regexp.MustCompile(`(?s)<button\b[^>]*class="([^"]*\b(?:bg-blue-600|bg-red-600|bg-red-700|bg-green-700)\b[^"]*)"`)
	for _, path := range allTemplateFiles(t) {
		body := readTextFile(t, path)
		for _, match := range filledButton.FindAllStringSubmatch(body, -1) {
			classes := match[1]
			for _, want := range []string{
				`focus:outline-none`,
				`focus:ring-2`,
				`focus:ring-offset-2`,
			} {
				if !strings.Contains(classes, want) {
					t.Fatalf("%s filled action button missing %q:\n%s", path, want, match[0])
				}
			}
		}
	}
}

func TestHTMXFeedbackRegionsExposeLiveAndBusySemantics(t *testing.T) {
	t.Parallel()

	publicFeeds := readTextFile(t, "templates", "feeds.html")
	for _, want := range []string{
		`data-auto-refresh-status role="status" aria-live="polite" aria-atomic="true"`,
		`id="feed-status-container" aria-live="polite" aria-busy="false"`,
	} {
		if !strings.Contains(publicFeeds, want) {
			t.Fatalf("feeds.html missing HTMX live/busy marker %q", want)
		}
	}

	adminFeeds := readTextFile(t, "templates", "admin", "feeds.html")
	for _, want := range []string{
		`id="admin-feed-flash" aria-live="polite" aria-atomic="true"`,
		`data-auto-refresh-status role="status" aria-live="polite" aria-atomic="true"`,
		`id="admin-feed-runtime" aria-live="polite" aria-busy="false"`,
		`data-feed-sync-now`,
	} {
		if !strings.Contains(adminFeeds, want) {
			t.Fatalf("admin/feeds.html missing HTMX live/busy marker %q", want)
		}
	}
	if strings.Contains(adminFeeds, `setTimeout`) || strings.Contains(adminFeeds, `_syncFlashTimer`) {
		t.Fatal("admin feed sync button still uses timer-based success feedback instead of the persistent flash region")
	}

	search := readTextFile(t, "templates", "search.html")
	if !strings.Contains(search, `id="search-results" aria-live="polite" aria-busy="false"`) {
		t.Fatal("search.html search-results target missing live/busy semantics")
	}

	script := readTextFile(t, "static", "auto-refresh.js")
	for _, want := range []string{
		`initFeedSyncButtons`,
		`htmx:beforeRequest`,
		`htmx:afterRequest`,
		`htmx:responseError`,
		`aria-busy`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("auto-refresh.js missing HTMX busy-state behavior %q", want)
		}
	}
}

func TestWebTemplatesAvoidInlineScriptAndStyleDependencies(t *testing.T) {
	t.Parallel()

	layout := readTextFile(t, "templates", "layout.html")
	for _, want := range []string{
		`<meta name="htmx-config"`,
		`"includeIndicatorStyles":false`,
		`"allowEval":false`,
		`"allowScriptTags":false`,
		`"historyEnabled":false`,
		`<link rel="stylesheet" href="/static/tailwind.css">`,
		`<script src="/static/htmx.min.js" defer></script>`,
	} {
		if !strings.Contains(layout, want) {
			t.Fatalf("layout.html missing htmx CSP-safe config marker %q:\n%s", want, layout)
		}
	}
	if strings.Index(layout, `<script src="/static/htmx.min.js" defer></script>`) < strings.Index(layout, `<link rel="stylesheet" href="/static/style.css">`) {
		t.Fatalf("layout.html loads htmx before stylesheets:\n%s", layout)
	}

	forbiddenAttr := regexp.MustCompile(`(?i)\s(?:style|on[a-z]+|hx-on::[a-z-]+)=`)
	err := filepath.WalkDir(filepath.Join("templates"), func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".html") {
			return nil
		}
		body, err := os.ReadFile(path) //nolint:gosec // test walks only repository template fixtures.
		if err != nil {
			return err
		}
		if match := forbiddenAttr.Find(body); match != nil {
			t.Fatalf("%s contains inline script/style dependency %q", path, string(match))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk templates: %v", err)
	}

	script := readTextFile(t, "static", "auto-refresh.js")
	for _, want := range []string{
		`initCopyButtons`,
		`initSelectOnFocusInputs`,
		`initFeedSyncButtons`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("auto-refresh.js missing externalized inline behavior %q", want)
		}
	}
}

func TestAdminAlertsUseSharedPartialAndDecorativeIcons(t *testing.T) {
	t.Parallel()

	partial := readTextFile(t, "templates", "partials", "admin_alert.html")
	for _, want := range []string{
		`{{define "admin-alert-start"}}`,
		`{{define "admin-alert-icon"}}`,
		`{{define "admin-alert"}}`,
		`{{define "admin-flash-alerts"}}`,
		`data-alert-variant="{{.Variant}}"`,
		`aria-hidden="true"`,
		`data-alert-icon="{{.Variant}}"`,
	} {
		if !strings.Contains(partial, want) {
			t.Fatalf("admin alert partial missing %q:\n%s", want, partial)
		}
	}

	for _, path := range []string{
		filepath.Join("templates", "admin", "advisories.html"),
		filepath.Join("templates", "admin", "keys.html"),
		filepath.Join("templates", "admin", "queue.html"),
		filepath.Join("templates", "admin", "settings.html"),
	} {
		body := readTextFile(t, path)
		if !strings.Contains(body, `{{template "admin-flash-alerts" .}}`) {
			t.Fatalf("%s does not use shared admin flash alerts partial", path)
		}
	}

	feeds := readTextFile(t, "templates", "admin", "feeds.html")
	if !strings.Contains(feeds, `{{template "admin-flash-alerts" .}}`) {
		t.Fatal("admin feeds flash partial does not delegate to shared admin flash alerts")
	}

	for _, path := range allTemplateFiles(t) {
		body := readTextFile(t, path)
		for _, blocked := range []string{
			`bg-green-50 border border-green-200 text-green-800 rounded-md px-4 py-3 text-sm`,
			`bg-red-50 border border-red-200 text-red-700 rounded-md px-4 py-3 text-sm`,
			`bg-red-50 border border-red-200 text-red-800 rounded-md px-4 py-3 text-sm`,
			`bg-yellow-50 border border-yellow-200 rounded-md p-4 text-sm text-yellow-800`,
			`bg-red-50 text-red-700 text-sm border-b border-red-100`,
		} {
			if strings.Contains(body, blocked) {
				t.Fatalf("%s still implements alert markup directly with %q", path, blocked)
			}
		}
	}

	bootstrap := readTextFile(t, "templates", "partials", "admin_bootstrap.html")
	if strings.Contains(bootstrap, `>!</div>`) || strings.Contains(bootstrap, `text-xl mr-3">!</div>`) {
		t.Fatalf("admin bootstrap warning still uses a bare text glyph:\n%s", bootstrap)
	}
	for _, want := range []string{
		`{{template "admin-alert-start" dict "Variant" "warning" "Icon" true}}`,
		`{{template "admin-alert-end" .}}`,
	} {
		if !strings.Contains(bootstrap, want) {
			t.Fatalf("admin bootstrap warning missing shared alert marker %q:\n%s", want, bootstrap)
		}
	}
}

func TestAdminNavigationUsesSharedPartial(t *testing.T) {
	t.Parallel()

	partial := readTextFile(t, "templates", "partials", "admin_nav.html")
	for _, want := range []string{
		`{{define "admin-page-header"}}`,
		`{{define "admin-nav"}}`,
		`{{define "admin-nav-link"}}`,
		`aria-label="Admin"`,
		`aria-current="page"`,
		`/admin/advisories`,
		`/admin/settings`,
	} {
		if !strings.Contains(partial, want) {
			t.Fatalf("admin_nav.html missing %q:\n%s", want, partial)
		}
	}

	for _, path := range []string{
		filepath.Join("templates", "admin", "dashboard.html"),
		filepath.Join("templates", "admin", "feeds.html"),
		filepath.Join("templates", "admin", "queue.html"),
		filepath.Join("templates", "admin", "keys.html"),
		filepath.Join("templates", "admin", "audit.html"),
		filepath.Join("templates", "admin", "advisories.html"),
		filepath.Join("templates", "admin", "settings.html"),
	} {
		body := readTextFile(t, path)
		if !strings.Contains(body, `{{template "admin-page-header"`) {
			t.Fatalf("%s does not use shared admin page header partial", path)
		}
		if strings.Contains(body, `<!-- Admin nav tabs -->`) ||
			strings.Contains(body, `<nav aria-label="Admin"`) {
			t.Fatalf("%s still contains copied admin nav markup", path)
		}
	}
}

func TestActiveNavigationExposesAriaCurrent(t *testing.T) {
	t.Parallel()

	layout := readTextFile(t, "templates", "layout.html")
	if !strings.Contains(layout, `<nav aria-label="Primary"`) {
		t.Fatal("layout public nav missing Primary aria-label")
	}
	for _, want := range []string{
		`{{if eq .ActiveNav "dashboard"}}aria-current="page"{{end}}`,
		`{{if eq .ActiveNav "search"}}aria-current="page"{{end}}`,
		`{{if eq .ActiveNav "feeds"}}aria-current="page"{{end}}`,
		`{{if eq .ActiveNav "admin"}}aria-current="page"{{end}}`,
	} {
		if !strings.Contains(layout, want) {
			t.Fatalf("layout public nav missing active state %q", want)
		}
	}

	adminNav := readTextFile(t, "templates", "partials", "admin_nav.html")
	for _, want := range []string{
		`<nav aria-label="Admin"`,
		`{{if eq .Section .Active}}aria-current="page"{{end}}`,
	} {
		if !strings.Contains(adminNav, want) {
			t.Fatalf("admin_nav.html missing active-state marker %q:\n%s", want, adminNav)
		}
	}

	for _, tc := range []struct {
		path    string
		section string
	}{
		{filepath.Join("templates", "admin", "dashboard.html"), `"Section" "overview"`},
		{filepath.Join("templates", "admin", "feeds.html"), `"Section" "feeds"`},
		{filepath.Join("templates", "admin", "queue.html"), `"Section" "queue"`},
		{filepath.Join("templates", "admin", "keys.html"), `"Section" "keys"`},
		{filepath.Join("templates", "admin", "audit.html"), `"Section" "audit"`},
		{filepath.Join("templates", "admin", "advisories.html"), `"Section" "advisories"`},
		{filepath.Join("templates", "admin", "settings.html"), `"Section" "settings"`},
	} {
		body := readTextFile(t, tc.path)
		if !strings.Contains(body, `{{template "admin-page-header"`) ||
			!strings.Contains(body, tc.section) {
			t.Fatalf("%s missing shared admin page header section %s:\n%s", tc.path, tc.section, body)
		}
	}
}

func TestScrollableTableRegionsAreFocusableAndNamed(t *testing.T) {
	t.Parallel()

	scrollRegion := regexp.MustCompile(`<div\b[^>]*class="[^"]*\boverflow-x-auto\b[^"]*"[^>]*>`)
	for _, path := range allTemplateFiles(t) {
		body := readTextFile(t, path)
		for _, tag := range scrollRegion.FindAllString(body, -1) {
			for _, want := range []string{
				`tabindex="0"`,
				`role="region"`,
				`aria-label=`,
				`focus:ring-2`,
				`focus:ring-offset-2`,
			} {
				if !strings.Contains(tag, want) {
					t.Fatalf("%s scroll region missing %q:\n%s", path, want, tag)
				}
			}
		}
	}
}

func allTemplateFiles(t *testing.T) []string {
	t.Helper()

	templateFiles, err := filepath.Glob(filepath.Join("templates", "*.html"))
	if err != nil {
		t.Fatalf("glob page templates: %v", err)
	}
	adminFiles, err := filepath.Glob(filepath.Join("templates", "admin", "*.html"))
	if err != nil {
		t.Fatalf("glob admin templates: %v", err)
	}
	return append(templateFiles, adminFiles...)
}

func TestAutoRefreshPreservesTableScrollPosition(t *testing.T) {
	t.Parallel()

	publicFeeds := readTextFile(t, "templates", "feeds.html")
	for _, want := range []string{
		`id="feed-status-container"`,
		`data-preserve-scroll-container`,
		`data-preserve-scroll="feed-status-table"`,
	} {
		if !strings.Contains(publicFeeds, want) {
			t.Fatalf("feeds.html missing scroll-preservation hook %q", want)
		}
	}

	adminFeeds := readTextFile(t, "templates", "admin", "feeds.html")
	for _, want := range []string{
		`id="admin-feed-runtime"`,
		`data-preserve-scroll-container`,
		`data-preserve-scroll="admin-feed-runtime-table"`,
	} {
		if !strings.Contains(adminFeeds, want) {
			t.Fatalf("admin/feeds.html missing scroll-preservation hook %q", want)
		}
	}

	script := readTextFile(t, "static", "auto-refresh.js")
	for _, want := range []string{
		`htmx:beforeSwap`,
		`htmx:afterSwap`,
		`data-preserve-scroll`,
		`scrollLeft`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("auto-refresh.js missing scroll-preservation behavior %q", want)
		}
	}
}

func readTextFile(t *testing.T, path ...string) string {
	t.Helper()

	content, err := os.ReadFile(filepath.Join(path...)) //nolint:gosec // test reads static repository asset paths.
	if err != nil {
		t.Fatalf("read %s: %v", filepath.Join(path...), err)
	}
	return string(content)
}
