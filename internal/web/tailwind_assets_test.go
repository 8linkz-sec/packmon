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
		`@source "../templates";`,
		`@source "../render.go";`,
		`@theme {`,
		`--color-surface:`,
		`--container-shell: 1700px;`,
		`[data-pm-theme="dark"] {`,
	} {
		if !strings.Contains(inputCSS, want) {
			t.Fatalf("tailwind.input.css missing %q:\n%s", want, inputCSS)
		}
	}
	for _, blocked := range []string{
		`@source "../*.go";`,
		`@source "../**/*.go";`,
		`@source "../**/*_test.go";`,
	} {
		if strings.Contains(inputCSS, blocked) {
			t.Fatalf("tailwind.input.css scans non-production Go sources with %q:\n%s", blocked, inputCSS)
		}
	}

	// Tokens live in CSS since the Tailwind v4 migration. A reintroduced JS
	// config would split the source of truth for design tokens in two.
	if strings.Contains(inputCSS, "@config") {
		t.Fatalf("tailwind.input.css must not load a JS config:\n%s", inputCSS)
	}
	if _, err := os.Stat(filepath.Join("..", "..", "tailwind.config.js")); err == nil {
		t.Fatal("tailwind.config.js exists; design tokens belong in tailwind.input.css @theme")
	}
	if got := pkg.Scripts["build:web:css"]; strings.Contains(got, "tailwind.config.js") {
		t.Fatalf("build:web:css = %q, want no -c JS config flag", got)
	}

	outputCSS := readTextFile(t, "static", "tailwind.css")
	for _, want := range []string{
		".rounded{",
		".shadow{",
		".space-y-4>",
		".flex-wrap{",
		".min-h-11{",
		".min-h-dvh{",
		".border-border{",
		".bg-accent{",
		".text-muted{",
		".max-w-shell{",
		".ms-auto{",
		".pe-4{",
		".text-start{",
		".text-end{",
		// Base reset so table headers align to the start edge instead of the
		// browser default center; the text-end utility still overrides it.
		"th{text-align:start}",
		".pm-focus-ring{",
		".pm-scroll-region{",
		".pm-surface{",
	} {
		if !strings.Contains(outputCSS, want) {
			t.Fatalf("tailwind.css missing generated selector %q", want)
		}
	}
	for _, blocked := range []string{
		".border-gray-300{",
		".text-yellow-600{",
		".opacity-50{",
	} {
		if strings.Contains(outputCSS, blocked) {
			t.Fatalf("tailwind.css contains test-only generated selector %q", blocked)
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

func TestCustomStylesProvideGenericDisabledState(t *testing.T) {
	t.Parallel()

	styleCSS := readTextFile(t, "static", "style.css")
	for _, want := range []string{
		":disabled",
		"fieldset:disabled",
		"[aria-disabled=\"true\"]",
		"cursor: not-allowed",
		"opacity: 0.6",
		"pointer-events: none",
	} {
		if !strings.Contains(styleCSS, want) {
			t.Fatalf("style.css missing generic disabled-state marker %q:\n%s", want, styleCSS)
		}
	}
}

func TestCustomStylesUseTailwindColorTokens(t *testing.T) {
	t.Parallel()

	styleCSS := readTextFile(t, "static", "style.css")
	if matches := regexp.MustCompile(`#[0-9a-fA-F]{3,8}\b`).FindAllString(styleCSS, -1); len(matches) > 0 {
		t.Fatalf("style.css contains raw hex colors %v; use Tailwind color variables instead", matches)
	}
	for _, want := range []string{
		"var(--color-fg)",
		"var(--color-bg)",
		"var(--color-surface-2)",
		"var(--color-danger)",
		"var(--color-success)",
	} {
		if !strings.Contains(styleCSS, want) {
			t.Fatalf("style.css missing semantic color token %q:\n%s", want, styleCSS)
		}
	}
	// Raw palette variables bypass the [data-pm-theme] override in
	// tailwind.input.css and would stay light in dark mode.
	for _, blocked := range []string{
		"var(--color-gray-",
		"var(--color-blue-",
		"var(--color-red-",
		"var(--color-green-",
		"var(--color-white)",
	} {
		if strings.Contains(styleCSS, blocked) {
			t.Fatalf("style.css uses raw palette variable %q; use a semantic token:\n%s", blocked, styleCSS)
		}
	}
}

func TestAdminConfigurationQueueFormsUseSubmitLocks(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name  string
		path  []string
		wants []string
	}{
		{
			name: "feeds",
			path: []string{"templates", "admin", "feeds.html"},
			wants: []string{
				`<form action="/admin/feeds/save" method="POST" class="space-y-4" data-submit-lock data-submit-lock-label="{{t "admin.feeds.form.saving"}}">`,
				`<button type="submit" data-submit-lock-button aria-label="{{t "admin.feeds.form.save_aria" .FeedName}}"`,
				`<form action="/admin/feeds/reset" method="POST" class="flex justify-start" data-submit-lock data-submit-lock-label="{{t "admin.feeds.reset.saving"}}">`,
				`<button type="submit" data-submit-lock-button aria-label="{{t "admin.feeds.reset.aria" .FeedName}}"`,
			},
		},
		{
			name: "settings",
			path: []string{"templates", "admin", "settings.html"},
			wants: []string{
				`<form action="/admin/settings/system" method="POST" class="max-w-3xl" data-submit-lock data-submit-lock-label="{{t "admin.settings.system.saving"}}">`,
				`data-submit-lock-button`,
			},
		},
		{
			name: "queue",
			path: []string{"templates", "admin", "queue.html"},
			wants: []string{
				`<form action="/admin/queue/priority" method="POST" class="inline-flex items-center gap-2" data-submit-lock data-submit-lock-label="{{t "admin.queue.row.priority.saving"}}">`,
				`aria-label="{{t "admin.queue.row.priority.save_aria" $job.ID $job.Ecosystem $job.Name}}"`,
				`{{t "admin.queue.row.priority.save"}}</button>`,
				`<form action="/admin/queue/purge" method="POST" class="inline-flex w-full sm:w-auto" data-submit-lock data-submit-lock-label="{{t "admin.queue.bulk.purging"}}">`,
				`<form action="/admin/queue/clear" method="POST" class="inline-flex w-full sm:w-auto" data-submit-lock data-submit-lock-label="{{t "admin.queue.bulk.clearing"}}">`,
				`data-submit-lock-button`,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			body := readTextFile(t, tc.path...)
			for _, want := range tc.wants {
				if !strings.Contains(body, want) {
					t.Fatalf("%s missing submit-lock fragment %q", strings.Join(tc.path, string(os.PathSeparator)), want)
				}
			}
			if strings.Contains(body, `>Save</button>`) {
				t.Fatalf("%s still renders a generic Save action", strings.Join(tc.path, string(os.PathSeparator)))
			}
		})
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
		".package-finding-print-table",
		".package-finding-print-cell",
		"min-width: 0 !important",
		"white-space: normal !important",
		`a[href^="https://"]::after`,
		`a[href^="http://"]::after`,
		`content: " (" attr(href) ")"`,
		`details[data-print-open]:not([open]) > :not(summary)`,
		"display: block !important",
		"background: var(--pm-meter-risk)",
		"background: var(--pm-meter-clean)",
	} {
		if !strings.Contains(styleCSS, want) {
			t.Fatalf("style.css missing safe wrapping/print/progress marker %q:\n%s", want, styleCSS)
		}
	}
	if strings.Contains(styleCSS, "word-break: break-all") {
		t.Fatalf("style.css still applies break-all to every code element:\n%s", styleCSS)
	}
}

// Dark mode is driven by design tokens keyed off [data-pm-theme], not by
// !important overrides on utility classes. The theme itself is asserted in
// tailwind.input.css; style.css only carries what tokens cannot express.
func TestCustomStylesProvideSystemDarkTheme(t *testing.T) {
	t.Parallel()

	inputCSS := readTextFile(t, "static", "tailwind.input.css")
	for _, want := range []string{
		`[data-pm-theme="dark"] {`,
		"@media (prefers-color-scheme: dark)",
		`[data-pm-theme="system"] {`,
		"color-scheme: dark",
	} {
		if !strings.Contains(inputCSS, want) {
			t.Fatalf("tailwind.input.css missing theme rule %q:\n%s", want, inputCSS)
		}
	}

	styleCSS := readTextFile(t, "static", "style.css")
	for _, want := range []string{
		`[data-pm-theme="dark"] .shadow`,
		`[data-pm-theme="system"] .shadow`,
	} {
		if !strings.Contains(styleCSS, want) {
			t.Fatalf("style.css missing dark elevation rule %q:\n%s", want, styleCSS)
		}
	}
	// Ignore comments: the block below documents the removed override hack.
	withoutComments := regexp.MustCompile(`(?s)/\*.*?\*/`).ReplaceAllString(styleCSS, "")
	if regexp.MustCompile(`\.text-gray-\d+\s*[,{]`).MatchString(withoutComments) {
		t.Fatalf("style.css still overrides raw utility classes for dark mode:\n%s", styleCSS)
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

func TestCustomStylesOnlyKeepBackedCustomHooks(t *testing.T) {
	t.Parallel()

	styleCSS := readTextFile(t, "static", "style.css")
	for _, want := range []string{
		".htmx-indicator",
		".htmx-request .htmx-indicator",
		".scan-findings-meter--risk::-webkit-progress-value",
		".scan-findings-meter--risk::-moz-progress-bar",
		".scan-findings-meter--clean::-webkit-progress-value",
		".scan-findings-meter--clean::-moz-progress-bar",
	} {
		if !strings.Contains(styleCSS, want) {
			t.Fatalf("style.css missing backed custom hook rule %q:\n%s", want, styleCSS)
		}
	}

	for _, path := range []string{
		filepath.Join("templates", "feeds.html"),
		filepath.Join("templates", "admin", "feeds.html"),
	} {
		body := readTextFile(t, path)
		if !strings.Contains(body, "htmx-indicator") || !strings.Contains(body, "hx-indicator=") {
			t.Fatalf("%s does not back the htmx indicator custom CSS hook", path)
		}
	}

	scans := readTextFile(t, "templates", "scans.html")
	for _, want := range []string{
		"scan-findings-meter--risk",
		"scan-findings-meter--clean",
	} {
		if !strings.Contains(scans, want) {
			t.Fatalf("scans.html missing findings meter state hook %q", want)
		}
	}
}

func TestCustomStylesHonorPrefersContrastPreference(t *testing.T) {
	t.Parallel()

	styleCSS := readTextFile(t, "static", "style.css")
	for _, want := range []string{
		"@media (prefers-contrast: more)",
		"border-color: black !important",
		"box-shadow: none !important",
		"text-decoration-thickness: 0.12em",
		"outline: 3px solid black",
	} {
		if !strings.Contains(styleCSS, want) {
			t.Fatalf("style.css missing prefers-contrast rule %q:\n%s", want, styleCSS)
		}
	}
}

func TestCustomStylesUseLogicalInlinePositioning(t *testing.T) {
	t.Parallel()

	styleCSS := readTextFile(t, "static", "style.css")
	if !strings.Contains(styleCSS, "inset-inline-start: var(--pm-space-3)") {
		t.Fatalf("style.css missing logical skip-link inline positioning:\n%s", styleCSS)
	}
	for _, blocked := range []string{
		"\n  left:",
		"\n  right:",
	} {
		if strings.Contains(styleCSS, blocked) {
			t.Fatalf("style.css still uses physical inline positioning %q:\n%s", blocked, styleCSS)
		}
	}
}

func TestWebTemplatesUseLogicalInlineUtilities(t *testing.T) {
	t.Parallel()

	blocked := regexp.MustCompile(`(?:^|[\s"])((?:[a-z0-9-]+:)*(?:m[lr]-[^\s"]+|p[lr]-[^\s"]+|text-(?:left|right)|border-[lr](?:-[^\s"]*)?|rounded-[lr](?:-[^\s"]*)?|left-[^\s"]+|right-[^\s"]+|inset-[lr](?:-[^\s"]*)?|space-x(?:-[^\s"]*)?|divide-x(?:-[^\s"]*)?|float-(?:left|right)|clear-(?:left|right)|origin-(?:left|right)|translate-x-[^\s"]+))(?:$|[\s"])`)
	for _, path := range allWebTemplateFiles(t) {
		body := readTextFile(t, path)
		if match := blocked.FindStringSubmatch(body); match != nil {
			t.Fatalf("%s uses physical inline utility %q; use logical inline utilities instead", path, match[1])
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
		// bg-gray-100/text-gray-500 used to be the low-contrast pair guarded here.
		// The semantic tokens replace it: muted on surface-2 is 4.84:1 (WCAG AA).
		// Raw palette classes are now forbidden outright by design_tokens_test.go.
		for _, blocked := range []string{
			"text-gray-400",
			"text-yellow-600",
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
		`name="enabled" {{if .Enabled}}checked{{end}} class="rounded border-muted text-accent pm-focus-ring"`,
		`name="mode" class="pm-form-control"`,
		`name="sync_interval"`,
		`class="pm-form-control"`,
		`name="api_key"`,
		`aria-label="{{t "admin.feeds.sync.aria" .FeedName}}"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("admin feed template missing focus token fragment %q", want)
		}
	}
	for _, tc := range []struct {
		name   string
		marker string
		wants  []string
	}{
		{
			name:   "clear API key checkbox",
			marker: `name="clear_api_key"`,
			wants: []string{
				`aria-describedby="feed-{{.FeedKey}}-clear-key-help"`,
				`border-muted`,
				`pm-focus-ring`,
			},
		},
		{
			name:   "confirm clear API key checkbox",
			marker: `name="confirm_clear_api_key"`,
			wants: []string{
				`border-danger`,
				`text-danger`,
				`pm-focus-ring`,
				`pm-focus-ring-danger`,
			},
		},
		{
			name:   "confirm reset checkbox",
			marker: `name="confirm_reset"`,
			wants: []string{
				`border-danger`,
				`text-danger`,
				`pm-focus-ring`,
				`pm-focus-ring-danger`,
			},
		},
		{
			name:   "save button",
			marker: `aria-label="{{t "admin.feeds.form.save_aria" .FeedName}}"`,
			wants: []string{
				`data-submit-lock-button`,
				`inline-flex`,
				`min-h-11`,
				`justify-center`,
				`pm-focus-ring`,
			},
		},
		{
			name:   "sync button",
			marker: `aria-label="{{t "admin.feeds.sync.aria" .FeedName}}"`,
			wants: []string{
				`inline-flex`,
				`min-h-11`,
				`justify-center`,
				`pm-focus-ring`,
			},
		},
		{
			name:   "reset button",
			marker: `aria-label="{{t "admin.feeds.reset.aria" .FeedName}}"`,
			wants: []string{
				`data-submit-lock-button`,
				`inline-flex`,
				`min-h-11`,
				`justify-center`,
				`pm-focus-ring`,
			},
		},
	} {
		tag := openingTagContaining(t, body, tc.marker)
		for _, want := range tc.wants {
			if !tagContainsDirectOrAdminPrimaryClass(tag, want) {
				t.Fatalf("admin feed %s missing focus token %q:\n%s", tc.name, want, tag)
			}
		}
	}
}

func TestWebTemplatesUseSemanticFocusRingTokens(t *testing.T) {
	t.Parallel()

	for _, path := range allTemplateFiles(t) {
		body := readTextFile(t, path)
		for _, forbidden := range []string{
			"focus:ring-blue-500",
			"focus:ring-red-500",
			"focus:ring-red-600",
			"focus:ring-yellow-600",
			"focus:ring-yellow-700",
			"focus-visible:ring-blue-500",
		} {
			if strings.Contains(body, forbidden) {
				t.Fatalf("%s still uses primitive focus ring token %q", path, forbidden)
			}
		}
	}
}

func TestWebTemplatesUseSemanticFormControlTokens(t *testing.T) {
	t.Parallel()

	for _, path := range allTemplateFiles(t) {
		body := readTextFile(t, path)
		for _, forbidden := range []string{
			"w-full min-h-11 border border-muted rounded-md px-3 py-2 text-sm",
			"min-h-11 border border-muted rounded-md px-3 py-2 text-sm",
			"min-h-11 w-full rounded-md border border-muted px-3 py-2 text-sm",
		} {
			if strings.Contains(body, forbidden) {
				t.Fatalf("%s still uses primitive form-control bundle %q", path, forbidden)
			}
		}
	}
}

func TestAdminAPIKeyCreateFormPreservesSafeValuesAndConstrainsExpiration(t *testing.T) {
	t.Parallel()

	body := readTextFile(t, "templates", "admin", "keys.html")
	for _, want := range []string{
		`name="name"`,
		`value="{{.APIKeyCreateName}}"`,
		`name="expires_in_days"`,
		`data-reveal-target="#key-expires-custom-wrap"`,
		`data-reveal-value="custom"`,
		`name="expires_custom_days"`,
		`max="{{.APIKeyExpiryMaxDays}}"`,
		`value="{{.APIKeyCustomDaysValue}}"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("admin keys template missing API key create form fragment %q", want)
		}
	}
	if strings.Contains(body, `name="current_password"`+"\n"+`          value=`) {
		t.Fatalf("admin keys template must not render a current_password value")
	}
}

func TestAdminFeedConfigurationEditorsAreCollapsedByDefault(t *testing.T) {
	t.Parallel()

	body := readTextFile(t, "templates", "admin", "feeds.html")
	for _, want := range []string{
		`<details id="feed-{{.FeedKey}}" class="border border-border rounded-lg" data-feed-key="{{.FeedKey}}"`,
		`<div class="border-t border-border p-4">`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("admin feed template missing collapsed editor fragment %q", want)
		}
	}
	summary := openingTagContaining(t, body, `sm:justify-between`)
	for _, want := range []string{
		`flex`,
		`cursor-pointer`,
		`list-none`,
		`pm-focus-ring`,
		`sm:flex-row`,
		`sm:items-start`,
		`sm:justify-between`,
	} {
		if !strings.Contains(summary, want) {
			t.Fatalf("admin feed collapsed editor summary missing %q:\n%s", want, summary)
		}
	}
	if strings.Contains(body, `<div class="border border-border rounded-lg p-4" data-feed-key="{{.FeedKey}}">`) {
		t.Fatal("admin feed template still renders every editor as an expanded card")
	}
}

func TestAdminFeedConfigurationEditorOpensForScopedErrors(t *testing.T) {
	t.Parallel()

	body := readTextFile(t, "templates", "admin", "feeds.html")
	for _, want := range []string{
		`id="feed-{{.FeedKey}}"`,
		`{{if eq $.ActiveFeedKey .FeedKey}}open{{end}}`,
		`data-feed-error-target="{{if eq $.ActiveFeedKey .FeedKey}}true{{else}}false{{end}}"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("admin feed template missing scoped error editor marker %q:\n%s", want, body)
		}
	}
}

func TestAdminFeedSyncIntervalInputHasBrowserConstraints(t *testing.T) {
	t.Parallel()

	body := readTextFile(t, "templates", "admin", "feeds.html")
	input := openingTagContaining(t, body, `name="sync_interval"`)
	for _, want := range []string{
		`pattern=`,
		`title=`,
		`aria-describedby="feed-{{.FeedKey}}-sync-interval-help"`,
		`id="feed-{{.FeedKey}}-sync-interval"`,
	} {
		if !strings.Contains(input, want) {
			t.Fatalf("admin feed sync interval input missing browser constraint %q:\n%s", want, input)
		}
	}
	if !strings.Contains(body, `id="feed-{{.FeedKey}}-sync-interval-help"`) {
		t.Fatalf("admin feed template missing sync interval hint target:\n%s", body)
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
		`{{.APIKeyHelp}}`,
		`class="mt-2 flex min-h-11 cursor-pointer items-center gap-2 rounded-md px-2 py-2 text-sm text-fg`,
		`class="mt-1 flex min-h-11 cursor-pointer items-center gap-2 rounded-md px-2 py-2 text-sm text-danger-fg`,
		`{{t "admin.feeds.form.api_key.clear_label" .FeedName}}`,
		`{{t "admin.feeds.form.api_key.clear_confirm" .FeedName}}`,
		`{{t "admin.feeds.form.api_key.clear_help" .FeedName}}`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("admin feed template missing destructive key control/context fragment %q", want)
		}
	}
	confirmClear := openingTagContaining(t, body, `name="confirm_clear_api_key"`)
	for _, want := range []string{
		`border-danger`,
		`text-danger`,
		`pm-focus-ring`,
		`pm-focus-ring-danger`,
	} {
		if !strings.Contains(confirmClear, want) {
			t.Fatalf("admin feed confirm-clear checkbox missing %q:\n%s", want, confirmClear)
		}
	}
	clearKey := openingTagContaining(t, body, `name="clear_api_key"`)
	for _, want := range []string{
		`aria-describedby="feed-{{.FeedKey}}-clear-key-help"`,
		`border-muted`,
		`text-accent`,
		`pm-focus-ring`,
	} {
		if !strings.Contains(clearKey, want) {
			t.Fatalf("admin feed clear-key checkbox missing %q:\n%s", want, clearKey)
		}
	}
}

func TestAdminFeedCredentialCheckboxRowsExposePointerHoverAndFocusWithin(t *testing.T) {
	t.Parallel()

	body := readTextFile(t, "templates", "admin", "feeds.html")
	for _, tc := range []struct {
		name   string
		marker string
	}{
		{name: "clear key", marker: `name="clear_api_key"`},
		{name: "confirm clear key", marker: `name="confirm_clear_api_key"`},
		{name: "enabled", marker: `name="enabled"`},
		{name: "confirm reset", marker: `name="confirm_reset"`},
	} {
		label := ancestorOpeningTagContaining(t, body, "<label", tc.marker)
		for _, want := range []string{
			`min-h-11`,
			`cursor-pointer`,
			`hover:bg-`,
			`focus-within:ring-2`,
			`focus-within:ring-offset-2`,
		} {
			if !strings.Contains(label, want) {
				t.Fatalf("admin feed %s checkbox row missing %q:\n%s", tc.name, want, label)
			}
		}
	}
}

func TestAdminFeedDestructiveConfirmCheckboxesAreBrowserRequiredAndAccessible(t *testing.T) {
	t.Parallel()

	body := readTextFile(t, "templates", "admin", "feeds.html")

	confirmClear := openingTagContaining(t, body, `name="confirm_clear_api_key"`)
	for _, want := range []string{
		`aria-describedby="feed-{{.FeedKey}}-clear-key-help feed-{{.FeedKey}}-confirm-clear-key-help"`,
		`data-required-when-checked="clear_api_key"`,
		`data-required-message="{{t "admin.feeds.form.api_key.clear_required"}}"`,
	} {
		if !strings.Contains(confirmClear, want) {
			t.Fatalf("admin feed confirm-clear checkbox missing %q:\n%s", want, confirmClear)
		}
	}
	if !strings.Contains(body, `id="feed-{{.FeedKey}}-confirm-clear-key-help"`) {
		t.Fatalf("admin feed template missing confirm-clear accessible help text:\n%s", body)
	}

	confirmReset := openingTagContaining(t, body, `name="confirm_reset"`)
	for _, want := range []string{
		`required`,
		`aria-describedby="feed-{{.FeedKey}}-confirm-reset-help"`,
	} {
		if !strings.Contains(confirmReset, want) {
			t.Fatalf("admin feed confirm-reset checkbox missing %q:\n%s", want, confirmReset)
		}
	}
	if !strings.Contains(body, `id="feed-{{.FeedKey}}-confirm-reset-help"`) {
		t.Fatalf("admin feed template missing confirm-reset accessible help text:\n%s", body)
	}
	for _, want := range []string{
		`{{t "admin.feeds.reset.confirm" .FeedName}}`,
		`{{t "admin.feeds.reset.help" .FeedName}}`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("admin feed reset confirmation missing credential-loss copy %q:\n%s", want, body)
		}
	}
}

func TestConditionalRequiredCheckboxesOnlyRequireWhenTriggerChecked(t *testing.T) {
	t.Parallel()

	script := readTextFile(t, "static", "form-actions.js")
	for _, want := range []string{
		`function setupConditionalRequiredCheckbox(checkbox)`,
		`checkbox.dataset.requiredWhenChecked`,
		`trigger.checked`,
		`checkbox.required = trigger.checked;`,
		`checkbox.setCustomValidity(checkbox.checked ? "" : checkbox.dataset.requiredMessage || "Confirm this action before saving.");`,
		`checkbox.removeAttribute("required");`,
		`document.querySelectorAll("[data-required-when-checked]").forEach(setupConditionalRequiredCheckbox);`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("form-actions.js missing conditional required checkbox behavior %q:\n%s", want, script)
		}
	}
}

func TestSelectRequiredCheckboxesOnlyRequireForMatchingValue(t *testing.T) {
	t.Parallel()

	script := readTextFile(t, "static", "form-actions.js")
	for _, want := range []string{
		`function setupSelectRequiredCheckbox(checkbox)`,
		`checkbox.dataset.requiredWhenSelect`,
		`checkbox.dataset.requiredValue || ""`,
		`var required = select.value === requiredValue;`,
		`checkbox.required = required;`,
		`checkbox.setAttribute("aria-required", required ? "true" : "false");`,
		`checkbox.setCustomValidity(checkbox.checked ? "" : message);`,
		`document.querySelectorAll("[data-required-when-select]").forEach(setupSelectRequiredCheckbox);`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("form-actions.js missing select-required checkbox behavior %q:\n%s", want, script)
		}
	}
}

func TestManualFeedSyncButtonKeepsQueuedRunningStateAfterAcceptedRequest(t *testing.T) {
	t.Parallel()

	adminFeeds := readTextFile(t, "templates", "admin", "feeds.html")
	button := openingTagContaining(t, adminFeeds, `data-feed-sync-now`)
	for _, want := range []string{
		`data-feed-sync-running-label="{{t "admin.feeds.sync.running"}}"`,
		`data-feed-sync-error-reset="true"`,
	} {
		if !strings.Contains(button, want) {
			t.Fatalf("admin feed sync button missing durable running marker %q:\n%s", want, button)
		}
	}

	script := readTextFile(t, "static", "form-actions.js")
	for _, want := range []string{
		`var runningLabel = button.dataset.feedSyncRunningLabel || busyLabel || defaultLabel;`,
		`function markRunning()`,
		`button.dataset.feedSyncState = "running";`,
		`button.textContent = runningLabel;`,
		`button.setAttribute("aria-disabled", "true");`,
		`if (event.detail && event.detail.successful) {`,
		`markRunning();`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("form-actions.js missing durable feed-sync running behavior %q:\n%s", want, script)
		}
	}
}

func TestManualAdvisoryFormUsesUnsavedChangeGuard(t *testing.T) {
	t.Parallel()

	body := readTextFile(t, "templates", "admin", "advisories.html")
	form := openingTagContaining(t, body, `action="/admin/advisories/create"`)
	for _, want := range []string{
		`data-unsaved-guard`,
		`data-submit-lock`,
		`data-submit-lock-label="{{t "admin.advisories.form.saving"}}"`,
	} {
		if !strings.Contains(form, want) {
			t.Fatalf("manual advisory form missing unsaved-change guard marker %q:\n%s", want, form)
		}
	}
}

func TestManualAdvisoryFormFieldsExposeConstraintCues(t *testing.T) {
	t.Parallel()

	body := readTextFile(t, "templates", "admin", "advisories.html")
	cases := []struct {
		name   string
		marker string
		wants  []string
	}{
		{
			name:   "finding type",
			marker: `id="adv-finding-type"`,
			wants:  []string{`required`, `aria-describedby="adv-finding-type-help`},
		},
		{
			name:   "ecosystem",
			marker: `id="adv-ecosystem"`,
			wants:  []string{`required`, `aria-describedby="adv-ecosystem-help`},
		},
		{
			name:   "package name",
			marker: `id="adv-name"`,
			wants:  []string{`required`, `maxlength="{{.ManualAdvisoryNameMaxLength}}"`, `aria-describedby="adv-name-help`},
		},
		{
			name:   "severity",
			marker: `id="adv-severity"`,
			wants:  []string{`required`, `aria-describedby="adv-severity-help`},
		},
		{
			name:   "risk type",
			marker: `id="adv-risk-type"`,
			wants:  []string{`name="risk_type"`, `aria-describedby="adv-risk-type-help"`},
		},
		{
			name:   "summary",
			marker: `id="adv-summary"`,
			wants:  []string{`required`, `maxlength="{{.ManualAdvisorySummaryMaxLength}}"`, `aria-describedby="adv-summary-help`},
		},
		{
			name:   "description",
			marker: `id="adv-description"`,
			wants:  []string{`maxlength="{{.ManualAdvisoryDescriptionMaxLength}}"`, `aria-describedby="adv-description-help`},
		},
	}
	for _, tc := range cases {
		tag := openingTagContaining(t, body, tc.marker)
		for _, want := range tc.wants {
			if !strings.Contains(tag, want) {
				t.Fatalf("manual advisory %s field missing %q:\n%s", tc.name, want, tag)
			}
		}
	}

	for _, want := range []string{
		`id="adv-ecosystem-help"`,
		`Required. Select the package ecosystem Packmon scans for this advisory.`,
		`id="adv-name-help"`,
		`Required. Maximum {{.ManualAdvisoryNameMaxLength}} characters.`,
		`id="adv-severity-help"`,
		`Required. Vulnerability blocking follows the configured threshold; malicious findings still block.`,
		`id="adv-risk-type-help"`,
		`Risk type classifies malicious manual advisories; it does not change blocking behavior.`,
		`id="adv-summary-help"`,
		`Required. Maximum {{.ManualAdvisorySummaryMaxLength}} characters.`,
		`id="adv-description-help"`,
		`Optional. Maximum {{.ManualAdvisoryDescriptionMaxLength}} characters.`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("manual advisory form missing constraint cue %q:\n%s", want, body)
		}
	}
}

func TestAdminPasswordConfirmationUsesProgressiveConstraintValidation(t *testing.T) {
	t.Parallel()

	body := readTextFile(t, "templates", "admin", "settings.html")
	form := openingTagContaining(t, body, `action="/admin/settings/password"`)
	if !strings.Contains(form, `data-password-confirm-form`) {
		t.Fatalf("password form missing confirmation behavior marker:\n%s", form)
	}

	newPassword := openingTagContaining(t, body, `id="new-password"`)
	for _, want := range []string{`autocomplete="new-password"`, `aria-describedby="password-length-help password-confirm-help"`, `data-password-confirm-source`} {
		if !strings.Contains(newPassword, want) {
			t.Fatalf("new password field missing %q:\n%s", want, newPassword)
		}
	}

	confirmPassword := openingTagContaining(t, body, `id="confirm-password"`)
	for _, want := range []string{`autocomplete="new-password"`, `aria-describedby="password-length-help password-confirm-help"`, `data-password-confirm-target`, `data-password-mismatch-message="{{t "admin.settings.password.mismatch"}}"`} {
		if !strings.Contains(confirmPassword, want) {
			t.Fatalf("confirm password field missing %q:\n%s", want, confirmPassword)
		}
	}
	if !strings.Contains(body, `id="password-confirm-help"`) {
		t.Fatalf("password form missing accessible confirmation help text:\n%s", body)
	}

	script := readTextFile(t, "static", "form-actions.js")
	for _, want := range []string{
		`function setupPasswordConfirmation(form)`,
		`form.querySelector("[data-password-confirm-source]")`,
		`form.querySelector("[data-password-confirm-target]")`,
		`target.setCustomValidity(source.value && target.value && source.value !== target.value ? message : "");`,
		`target.reportValidity();`,
		`document.querySelectorAll("[data-password-confirm-form]").forEach(setupPasswordConfirmation);`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("form-actions.js missing password confirmation behavior %q:\n%s", want, script)
		}
	}
}

func TestUnsavedChangeGuardTracksFormChangesAndNavigation(t *testing.T) {
	t.Parallel()

	script := readTextFile(t, "static", "form-actions.js")
	for _, want := range []string{
		`function setupUnsavedGuard(form)`,
		`form.dataset.unsavedGuardReady === "true"`,
		`form.querySelectorAll("input, select, textarea")`,
		`form.dataset.unsavedDirty = dirty ? "true" : "false";`,
		`window.addEventListener("beforeunload"`,
		`event.preventDefault();`,
		`event.returnValue = "";`,
		`target.closest("a[href]")`,
		`isLocalNavigationLink(link)`,
		`window.confirm(unsavedChangesMessage)`,
		`form.addEventListener("submit", function ()`,
		`clearUnsavedGuard(form);`,
		`document.querySelectorAll("[data-unsaved-guard]").forEach(setupUnsavedGuard);`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("form-actions.js missing unsaved-change guard behavior %q:\n%s", want, script)
		}
	}
}

func TestAdminGuidanceTextForAuditFeedsAndManualAdvisories(t *testing.T) {
	t.Parallel()

	audit := readTextFile(t, "templates", "admin", "audit.html")
	for _, want := range []string{
		`id="audit-integrity-help"`,
		`Integrity badges verify each row in the audit hash chain.`,
		`aria-describedby="audit-integrity-help"`,
		`aria-label="Audit integrity {{.IntegrityLabel}}"`,
	} {
		if !strings.Contains(audit, want) {
			t.Fatalf("admin audit template missing integrity guidance marker %q:\n%s", want, audit)
		}
	}

	feeds := readTextFile(t, "templates", "admin", "feeds.html")
	for _, want := range []string{
		`aria-describedby="feed-{{.FeedKey}}-mode-help"`,
		`id="feed-{{.FeedKey}}-mode-help"`,
		`{{t "admin.feeds.form.mode_external_help"}}`,
	} {
		if !strings.Contains(feeds, want) {
			t.Fatalf("admin feeds template missing mode guidance marker %q:\n%s", want, feeds)
		}
	}

	advisories := readTextFile(t, "templates", "admin", "advisories.html")
	for _, want := range []string{
		`aria-describedby="adv-finding-type-help{{if $findingTypeError}} adv-finding-type-error{{end}}"`,
		`id="adv-finding-type-help"`,
		`Malicious advisories always block scans; vulnerabilities block according to the configured severity threshold.`,
		`aria-describedby="adv-risk-type-help"`,
		`id="adv-risk-type-help"`,
		`Risk type classifies malicious manual advisories; it does not change blocking behavior.`,
	} {
		if !strings.Contains(advisories, want) {
			t.Fatalf("admin advisories template missing type guidance marker %q:\n%s", want, advisories)
		}
	}
}

func TestPrivacyNoticeMatchesAdminAuditMetadata(t *testing.T) {
	t.Parallel()

	privacy := privacyNoticeStaticContent(t)
	for _, want := range []string{
		`action names, timestamps, and client address metadata`,
		`Scan history and scan metadata can contain package names`,
		`client IP, API key ID/name, correlation ID`,
		`finding IDs and severities, feed status and versions, request and result digests`,
		`employee-monitoring or`,
	} {
		if !strings.Contains(privacy, want) {
			t.Fatalf("privacy notice missing metadata marker %q:\n%s", want, privacy)
		}
	}
	if strings.Contains(strings.ToLower(privacy), "user-agent metadata") {
		t.Fatalf("privacy notice claims admin audit stores user-agent metadata:\n%s", privacy)
	}
}

func TestPrivacyNoticeDisclosesOutboundPackageAndWebhookRecipients(t *testing.T) {
	t.Parallel()

	privacy := privacyNoticeStaticContent(t)
	for _, want := range []string{
		`Optional third-party feed recipients`,
		`Socket.dev and ReversingLabs integrations are disabled unless configured by the operator.`,
		`package coordinates such as ecosystem`,
		`package name, version, or package URL`,
		`Operators can suppress configured`,
		`Webhook recipients`,
		`canonical scan result payload to an operator-configured`,
		`package names, versions, advisory and finding IDs`,
		`repository name unless repository metadata`,
	} {
		if !strings.Contains(privacy, want) {
			t.Fatalf("privacy notice missing outbound recipient marker %q:\n%s", want, privacy)
		}
	}
}

func TestPrivacyNoticeIncludesGDPRAndCCPARightsDisclosures(t *testing.T) {
	t.Parallel()

	privacy := privacyNoticeStaticContent(t)
	for _, want := range []string{
		`Last updated: 2026-06-29`,
		`Controller and contact`,
		`PACKMON_WEB_LEGAL_URL`,
		`Legal basis`,
		`legitimate interests`,
		`legal obligations`,
		`Data categories, sources, purposes, and retention`,
		`Identifiers such as client IP addresses`,
		`directly from admins, CI clients, CLI/API users`,
		`business purposes`,
		`Rights and requests`,
		`right to access`,
		`right to erasure`,
		`right to rectification`,
		`right to data portability`,
		`right to object`,
		`supervisory authority`,
		`California privacy rights`,
		`CCPA/CPRA`,
		`right to know`,
		`right to delete`,
		`right to correct`,
		`Do Not Sell or Share`,
		`Global Privacy Control`,
		`non-discrimination`,
	} {
		if !strings.Contains(privacy, want) {
			t.Fatalf("privacy notice missing GDPR/CCPA marker %q:\n%s", want, privacy)
		}
	}
}

func TestPrivacyNoticeDistinguishesPreAuthSessionCookieRetention(t *testing.T) {
	t.Parallel()

	privacy := privacyNoticeStaticContent(t)
	for _, blocked := range []string{
		"expires with the configured admin session lifetime",
	} {
		if strings.Contains(privacy, blocked) {
			t.Fatalf("privacy notice still has inaccurate session retention text %q:\n%s", blocked, privacy)
		}
	}
	for _, want := range []string{
		"Authenticated admin session cookies use the configured admin session lifetime",
		"configured admin idle timeout",
		"Login-form CSRF sessions are short-lived pre-authentication sessions and",
		"expire after at most 15 minutes.",
	} {
		if !strings.Contains(privacy, want) {
			t.Fatalf("privacy notice missing session retention marker %q:\n%s", want, privacy)
		}
	}
}

func privacyNoticeStaticContent(t *testing.T) string {
	t.Helper()

	keys := []webMessageKey{
		webMessageKey("page.privacy.title"),
		webMessageKey("privacy.heading"),
		webMessageKey("privacy.last_updated"),
		webMessageKey("privacy.session.heading"),
		webMessageKey("privacy.session.body_intro"),
		webMessageKey("privacy.session.body_after_cookie"),
		webMessageKey("privacy.session.body_after_scope"),
		webMessageKey("privacy.controller.heading"),
		webMessageKey("privacy.controller.body_intro"),
		webMessageKey("privacy.legal_basis.heading"),
		webMessageKey("privacy.legal_basis.body"),
		webMessageKey("privacy.operational_metadata.heading"),
		webMessageKey("privacy.operational_metadata.audit"),
		webMessageKey("privacy.operational_metadata.scan_logs"),
		webMessageKey("privacy.operational_metadata.retention"),
		webMessageKey("privacy.data_categories.heading"),
		webMessageKey("privacy.data_categories.categories"),
		webMessageKey("privacy.data_categories.sources"),
		webMessageKey("privacy.data_categories.retention"),
		webMessageKey("privacy.third_party.heading"),
		webMessageKey("privacy.third_party.body"),
		webMessageKey("privacy.webhook.heading"),
		webMessageKey("privacy.webhook.body"),
		webMessageKey("privacy.rights.heading"),
		webMessageKey("privacy.rights.body"),
		webMessageKey("privacy.california.heading"),
		webMessageKey("privacy.california.rights"),
		webMessageKey("privacy.california.gpc"),
		webMessageKey("privacy.operator_notice.heading"),
		webMessageKey("privacy.operator_notice.body"),
		webMessageKey("privacy.legal_notice.prefix"),
		webMessageKey("privacy.legal_notice.link"),
		webMessageKey("privacy.legal_notice.suffix"),
	}

	var content strings.Builder
	content.WriteString(readTextFile(t, "templates", "privacy.html"))
	for _, key := range keys {
		content.WriteByte('\n')
		content.WriteString(webMessage(key))
	}
	return content.String()
}

func TestAdminQueueStatusFiltersExposeActiveState(t *testing.T) {
	t.Parallel()

	queue := readTextFile(t, "templates", "admin", "queue.html")
	for _, want := range []string{
		`{{if .Active}}aria-current="page"{{end}}`,
		`{{if .Active}}border-info bg-info-bg text-accent{{else}}border-muted text-fg hover:bg-surface-2{{end}}`,
		`{{if .QueueStatusWarning}}`,
		`{{template "admin-alert" dict "Variant" "warning" "Icon" true "Message" .QueueStatusWarning}}`,
	} {
		if !strings.Contains(queue, want) {
			t.Fatalf("admin queue template missing active filter state marker %q:\n%s", want, queue)
		}
	}
}

func TestDashboardMetricCardsExposeLabelValueAndInteractionStates(t *testing.T) {
	t.Parallel()

	// Lifecycle, scans and feed health are operator numbers: admin dashboard only.
	for _, tc := range []struct {
		name     string
		path     []string
		template string
		labels   []string
		hrefs    []string
	}{
		{
			name:     "public dashboard",
			path:     []string{"templates", "dashboard.html"},
			template: "dashboard.html",
			labels:   []string{"Packages Tracked", "Vulnerabilities", "Malicious Packages", "Supply-chain Risks"},
			hrefs: []string{
				`href="/search?finding=vulnerability"`,
				`href="/search?finding=malicious"`,
				`href="/search?finding=supply_chain_risk"`,
			},
		},
		{
			name:     "admin dashboard",
			path:     []string{"templates", "admin", "dashboard.html"},
			template: "admin/dashboard.html",
			labels: []string{
				"Packages Tracked", "Vulnerabilities", "Malicious Packages",
				"Supply-chain Risks", "Lifecycle Findings", "Scans (7d)", "Feeds Healthy",
			},
			hrefs: []string{
				`href="/search?finding=vulnerability"`,
				`href="/search?finding=malicious"`,
				`href="/search?finding=supply_chain_risk"`,
				`href="/search?finding=lifecycle"`,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			body := renderDashboardTemplateForStaticTest(t, tc.template)
			for _, label := range tc.labels {
				if !strings.Contains(body, `<dt class="text-sm`) || !strings.Contains(body, ">"+label+"</dt>") {
					t.Fatalf("%s metric %q is not rendered as a label/value definition pair:\n%s", strings.Join(tc.path, string(os.PathSeparator)), label, body)
				}
			}
			if tc.name == "public dashboard" && strings.Contains(body, "Lifecycle Findings") {
				t.Fatalf("public dashboard must not show operator-only lifecycle card:\n%s", body)
			}
			for _, href := range tc.hrefs {
				tag := openingTagContaining(t, body, href)
				for _, want := range []string{
					`pm-focus-ring`,
					`active:bg-`,
				} {
					if !strings.Contains(tag, want) {
						t.Fatalf("%s dashboard KPI link %s missing %q:\n%s", strings.Join(tc.path, string(os.PathSeparator)), href, want, tag)
					}
				}
			}
		})
	}
}

func TestDashboardHoverControlsUseExplicitTransitionUtilities(t *testing.T) {
	t.Parallel()

	broadTransition := regexp.MustCompile(`(?:^|[\s"])transition(?:[\s"]|$)`)
	for _, tc := range []struct {
		name     string
		path     []string
		template string
	}{
		{name: "public dashboard", path: []string{"templates", "dashboard.html"}, template: "dashboard.html"},
		{name: "admin dashboard", path: []string{"templates", "admin", "dashboard.html"}, template: "admin/dashboard.html"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			body := renderDashboardTemplateForStaticTest(t, tc.template)
			hrefs := []string{
				`href="/search?finding=vulnerability"`,
				`href="/search?finding=malicious"`,
				`href="/search?finding=supply_chain_risk"`,
			}
			if tc.name == "admin dashboard" {
				hrefs = append(hrefs, `href="/search?finding=lifecycle"`)
			}
			for _, href := range hrefs {
				tag := openingTagContaining(t, body, href)
				if broadTransition.MatchString(tag) {
					t.Fatalf("%s dashboard KPI link %s uses broad transition utility:\n%s", strings.Join(tc.path, string(os.PathSeparator)), href, tag)
				}
				for _, want := range []string{`transition-colors`, `duration-150`, `ease-out`, `hover:shadow-md`, `active:shadow-sm`} {
					if !strings.Contains(tag, want) {
						t.Fatalf("%s dashboard KPI link %s missing explicit transition/interaction token %q:\n%s", strings.Join(tc.path, string(os.PathSeparator)), href, want, tag)
					}
				}
			}
		})
	}

	publicDashboard := renderDashboardTemplateForStaticTest(t, "dashboard.html")
	for _, href := range []string{
		`href="/search?severity=CRITICAL"`,
		`href="/search?severity=HIGH"`,
		`href="/search?severity=MEDIUM"`,
		`href="/search?severity=LOW"`,
	} {
		tag := openingTagContaining(t, publicDashboard, href)
		if broadTransition.MatchString(tag) {
			t.Fatalf("public dashboard severity filter %s uses broad transition utility:\n%s", href, tag)
		}
		for _, want := range []string{`transition-[filter]`, `duration-150`, `ease-out`, `hover:brightness-95`} {
			if !strings.Contains(tag, want) {
				t.Fatalf("public dashboard severity filter %s missing explicit transition/interaction token %q:\n%s", href, want, tag)
			}
		}
	}
}

func TestPackageVisualsUseConsistentRiskAndControlScale(t *testing.T) {
	t.Parallel()

	body := readTextFile(t, "templates", "package.html")
	riskTable := readTextFile(t, "templates", "partials", "package_risk_finding_table.html")
	packageTemplates := body + "\n" + riskTable

	versionInput := openingTagContaining(t, body, `name="version"`)
	for _, want := range []string{`pm-form-control`} {
		if !strings.Contains(versionInput, want) {
			t.Fatalf("package version input missing established control token %q:\n%s", want, versionInput)
		}
	}
	checkButton := openingTagContaining(t, body, `>{{t "package.action.check_version"}}</button>`)
	for _, want := range []string{`min-h-11`, `rounded-md`, `active:bg-accent-hover`} {
		if !strings.Contains(checkButton, want) {
			t.Fatalf("package version submit button missing established control token %q:\n%s", want, checkButton)
		}
	}

	if !strings.Contains(riskTable, `<tr class="{{$.RowClass}}">`) ||
		!strings.Contains(body, `"RowClass" "border-b border-border bg-warning-bg hover:bg-warning-bg"`) {
		t.Fatalf("package supply-chain rows must use amber risk hue through the shared risk table partial:\n%s\n%s", body, riskTable)
	}
	if strings.Contains(packageTemplates, `bg-orange-50`) || strings.Contains(packageTemplates, `hover:bg-orange-100`) {
		t.Fatalf("package supply-chain rows still use orange drift classes:\n%s", packageTemplates)
	}

	for _, blocked := range []string{
		`font-mono text-xs align-top min-w-[13rem]`,
		`font-mono text-xs align-top whitespace-nowrap min-w-[13rem]`,
		`text-xs align-top whitespace-nowrap package-finding-print-cell">
              {{if .Version}}`,
		`text-xs align-top whitespace-nowrap package-finding-print-cell">
              {{if .FixedVersion}}`,
	} {
		if strings.Contains(packageTemplates, blocked) {
			t.Fatalf("package finding primary cells still downscale to text-xs via %q:\n%s", blocked, packageTemplates)
		}
	}
}

func TestAdminVisualHierarchySpacingMarkers(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		path []string
		want string
	}{
		{
			name: "advisories empty state",
			path: []string{"templates", "admin", "advisories.html"},
			want: `<div class="pm-empty-state">`,
		},
		{
			name: "feeds empty state",
			path: []string{"templates", "admin", "feeds.html"},
			want: `<div class="pm-empty-state">`,
		},
		{
			name: "queue empty state",
			path: []string{"templates", "admin", "queue.html"},
			want: `<div class="pm-empty-state">`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			body := readTextFile(t, tc.path...)
			if !strings.Contains(body, tc.want) {
				t.Fatalf("%s missing shared empty-state spacing marker %q", strings.Join(tc.path, string(os.PathSeparator)), tc.want)
			}
		})
	}

	advisories := readTextFile(t, "templates", "admin", "advisories.html")
	for _, blocked := range []string{
		`<th scope="col" class="px-4 py-2">`,
		`<td class="px-4 py-2`,
		`<td class="no-print px-4 py-2"`,
		`<dt class="text-xs uppercase text-muted">`,
	} {
		if strings.Contains(advisories, blocked) {
			t.Fatalf("admin advisories template still uses old hierarchy/spacing marker %q", blocked)
		}
	}
	for _, want := range []string{
		`<th scope="col" class="px-5 py-2">ID</th>`,
		`<td class="px-5 py-2 font-mono text-xs"><bdi dir="auto">{{.ID}}</bdi></td>`,
		`<dt class="text-xs font-semibold uppercase tracking-wide text-muted">Type</dt>`,
		`<dt class="text-xs font-semibold uppercase tracking-wide text-muted">Risk Type</dt>`,
		`<dt class="text-xs font-semibold uppercase tracking-wide text-muted">Summary</dt>`,
	} {
		if !strings.Contains(advisories, want) {
			t.Fatalf("admin advisories template missing hierarchy/spacing marker %q", want)
		}
	}

	feeds := readTextFile(t, "templates", "admin", "feeds.html")
	if strings.Contains(feeds, `id="feed-{{.FeedKey}}-api-key-help" class="mt-1 block text-xs text-muted"`) {
		t.Fatal("admin feeds API-key billing disclosure still uses xs helper-text styling")
	}
	if !strings.Contains(feeds, `id="feed-{{.FeedKey}}-api-key-help" class="mt-2 block rounded-md border border-warning bg-warning-bg px-3 py-2 text-sm leading-6 text-warning-fg"`) {
		t.Fatal("admin feeds API-key billing disclosure missing emphasized disclosure panel styling")
	}

	queue := readTextFile(t, "templates", "admin", "queue.html")
	for _, blocked := range []string{
		`<dt class="text-xs uppercase text-muted">`,
		`<div class="text-2xl font-semibold {{.CountClass}}">{{.Count}}</div>`,
		`<div class="text-xs text-muted uppercase mt-1">{{.Label}}</div>`,
	} {
		if strings.Contains(queue, blocked) {
			t.Fatalf("admin queue template still uses old hierarchy/spacing marker %q", blocked)
		}
	}
	for _, want := range []string{
		`<dl class="grid grid-cols-1 gap-1">`,
		`<dt class="text-xs font-semibold uppercase tracking-wide text-muted">{{.Label}}</dt>`,
		`<dd class="text-2xl font-semibold {{.CountClass}}">{{.Count}}</dd>`,
		`<dt class="text-xs font-semibold uppercase tracking-wide text-muted">Source</dt>`,
		`<dt class="text-xs font-semibold uppercase tracking-wide text-muted">Priority</dt>`,
		`<dt class="text-xs font-semibold uppercase tracking-wide text-muted">Requested</dt>`,
		`<dt class="text-xs font-semibold uppercase tracking-wide text-muted">Error</dt>`,
	} {
		if !strings.Contains(queue, want) {
			t.Fatalf("admin queue template missing hierarchy/semantic metric marker %q", want)
		}
	}

	bootstrap := readTextFile(t, "templates", "partials", "admin_bootstrap.html")
	if strings.Contains(bootstrap, `<p class="font-semibold">Bootstrap password still active</p>`) {
		t.Fatalf("admin bootstrap warning still uses paragraph as heading:\n%s", bootstrap)
	}
	if !strings.Contains(bootstrap, `<p class="text-sm font-semibold text-warning-fg">Bootstrap password still active</p>`) {
		t.Fatalf("admin bootstrap warning missing non-heading warning label marker:\n%s", bootstrap)
	}
}

func TestPackmonSurfaceUtilitiesAreTokenized(t *testing.T) {
	t.Parallel()

	tailwindInput := readTextFile(t, "static", "tailwind.input.css")
	for _, want := range []string{
		`.pm-surface {`,
		`background: var(--color-surface);`,
		`border: 1px solid var(--color-border);`,
		`border-radius: var(--radius-lg);`,
		`.pm-scroll-region {`,
		`overflow-x: auto;`,
		`.pm-panel-header {`,
		`border-bottom: 1px solid var(--color-border);`,
		`.pm-empty-state {`,
		`text-align: center;`,
		`color: var(--color-muted);`,
	} {
		if !strings.Contains(tailwindInput, want) {
			t.Fatalf("tailwind input missing Packmon surface token %q:\n%s", want, tailwindInput)
		}
	}
}

func TestAdminAuditAndQueuePaginationUseTouchTargets(t *testing.T) {
	t.Parallel()

	audit := readTextFile(t, "templates", "admin", "audit.html")
	for _, compact := range []string{
		`inline-flex items-center rounded border border-muted px-2 py-1`,
		`rounded border px-2 py-1`,
	} {
		if strings.Contains(audit, compact) {
			t.Fatalf("templates/admin/audit.html still uses compact admin pagination links containing %q", compact)
		}
	}
	for _, tc := range []struct {
		name   string
		marker string
		wants  []string
	}{
		{name: "audit newer pagination", marker: `href="/admin/audit?offset={{.AuditPreviousOffset}}"`},
		{name: "audit older pagination", marker: `href="/admin/audit?offset={{.AuditNextOffset}}"`},
		{name: "audit out-of-range newer pagination", marker: `>Newer audit events</a>`},
	} {
		tc.wants = adminControlLinkClassTokens()
		tag := openingTagContaining(t, audit, tc.marker)
		for _, want := range tc.wants {
			if !strings.Contains(tag, want) {
				t.Fatalf("templates/admin/audit.html missing admin-control %s token %q in:\n%s", tc.name, want, tag)
			}
		}
	}
	if want := `pm-focus-ring`; !strings.Contains(audit, want) {
		t.Fatalf("templates/admin/audit.html missing audit pagination focus state %q", want)
	}

	queue := readTextFile(t, "templates", "admin", "queue.html")
	for _, compact := range []string{
		`inline-flex items-center rounded border border-muted px-2 py-1`,
		`rounded border px-2 py-1`,
	} {
		if strings.Contains(queue, compact) {
			t.Fatalf("templates/admin/queue.html still uses compact admin control links containing %q", compact)
		}
	}
	for _, tc := range []struct {
		name   string
		marker string
		wants  []string
	}{
		{
			name:   "queue previous pagination",
			marker: `href="{{.QueuePreviousURL}}"`,
			wants:  adminControlLinkClassTokens(),
		},
		{
			name:   "queue next pagination",
			marker: `href="{{.QueueNextURL}}"`,
			wants:  adminControlLinkClassTokens(),
		},
		{
			name:   "queue filters",
			marker: `{{if .Active}}border-info bg-info-bg text-accent{{else}}border-muted text-fg hover:bg-surface-2{{end}}`,
			wants: append(adminControlLinkClassTokens(),
				`border-info`,
				`bg-info-bg`,
				`text-accent`,
			),
		},
	} {
		tag := openingTagContaining(t, queue, tc.marker)
		for _, want := range tc.wants {
			if !strings.Contains(tag, want) {
				t.Fatalf("templates/admin/queue.html missing admin-control %s token %q in:\n%s", tc.name, want, tag)
			}
		}
	}
}

func adminControlLinkClassTokens() []string {
	return []string{
		`inline-flex`,
		`min-h-11`,
		`items-center`,
		`justify-center`,
		`rounded-md`,
		`border`,
		`px-3`,
		`py-2`,
		`font-medium`,
		`text-fg`,
		`hover:bg-surface-2`,
		`pm-focus-ring`,
	}
}

func TestAdminPackageLinksUsePackageDetailsAndTouchTargets(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		path    []string
		markers []string
		wants   []string
	}{
		{
			name: "manual advisories",
			path: []string{"templates", "admin", "advisories.html"},
			markers: []string{
				`<bdi dir="auto">{{.Ecosystem}}</bdi> / <bdi dir="auto">{{.Name}}</bdi>`,
			},
			wants: []string{
				`href="/package/{{.Ecosystem}}/{{.Name}}"`,
				`aria-label="View package details for {{.Ecosystem}}/{{.Name}}"`,
				`inline-flex`,
				`min-h-11`,
				`items-center`,
				`rounded-md`,
				`px-3`,
				`py-2`,
				`text-accent`,
			},
		},
		{
			name: "queue",
			path: []string{"templates", "admin", "queue.html"},
			markers: []string{
				`<bdi dir="auto">{{.Ecosystem}}</bdi>/<bdi dir="auto">{{.Name}}</bdi>`,
			},
			wants: []string{
				`href="/package/{{.Ecosystem}}/{{.Name}}"`,
				`aria-label="View package details for {{.Ecosystem}}/{{.Name}}"`,
				`inline-flex`,
				`min-h-11`,
				`items-center`,
				`rounded-md`,
				`px-3`,
				`py-2`,
				`text-accent`,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			body := readTextFile(t, tc.path...)
			for _, marker := range tc.markers {
				if got := strings.Count(body, marker); got < 2 {
					t.Fatalf("%s package link marker %q count = %d, want at least 2 for mobile and desktop:\n%s", strings.Join(tc.path, string(os.PathSeparator)), marker, got, body)
				}
				for _, tag := range ancestorOpeningTagsContaining(t, body, "<a", marker) {
					for _, want := range tc.wants {
						if !strings.Contains(tag, want) {
							t.Fatalf("%s %s package link missing %q:\n%s", strings.Join(tc.path, string(os.PathSeparator)), tc.name, want, tag)
						}
					}
				}
			}
		})
	}
}

func TestDiagnosticDisclosureSummariesUseTouchTargets(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name   string
		path   []string
		marker string
	}{
		{
			name:   "shared feed status",
			path:   []string{"templates", "partials", "feed_status.html"},
			marker: `aria-label="Show full feed ` + `error for {{$feed.FeedName}}"`,
		},
		{
			name:   "admin queue mobile",
			path:   []string{"templates", "admin", "queue.html"},
			marker: `{{truncate .Error 80}}`,
		},
		{
			name:   "admin queue desktop",
			path:   []string{"templates", "admin", "queue.html"},
			marker: `{{truncate .Error 40}}`,
		},
		{
			name:   "admin audit details",
			path:   []string{"templates", "admin", "audit.html"},
			marker: `dir="auto" class="inline-flex`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			body := readTextFile(t, tc.path...)
			summary := openingTagContaining(t, body, tc.marker)
			for _, want := range []string{
				`inline-flex`,
				`min-h-11`,
				`items-center`,
				`rounded`,
				`px-2`,
				`py-1`,
			} {
				if !strings.Contains(summary, want) {
					t.Fatalf("%s diagnostic summary missing touch-target class %q:\n%s", strings.Join(tc.path, string(os.PathSeparator)), want, summary)
				}
			}
		})
	}
}

func TestAdminDiagnosticDisclosureSummariesExposeHoverFocusAndActiveStates(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name   string
		path   []string
		marker string
	}{
		{
			name:   "admin feed runtime",
			path:   []string{"templates", "partials", "feed_status.html"},
			marker: `aria-label="Show full feed ` + `error for {{$feed.FeedName}}"`,
		},
		{
			name:   "admin queue mobile",
			path:   []string{"templates", "admin", "queue.html"},
			marker: `{{truncate .Error 80}}`,
		},
		{
			name:   "admin queue desktop",
			path:   []string{"templates", "admin", "queue.html"},
			marker: `{{truncate .Error 40}}`,
		},
		{
			name:   "manual advisory mobile summary",
			path:   []string{"templates", "admin", "advisories.html"},
			marker: `{{truncate .Summary 120}}`,
		},
		{
			name:   "manual advisory desktop summary",
			path:   []string{"templates", "admin", "advisories.html"},
			marker: `{{truncate .Summary 80}}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			body := readTextFile(t, tc.path...)
			summary := openingTagContaining(t, body, tc.marker)
			if !strings.HasPrefix(summary, "<summary") {
				summary = ancestorOpeningTagContaining(t, body, "<summary", tc.marker)
			}
			for _, want := range []string{
				`hover:bg-`,
				`pm-focus-ring`,
				`active:bg-`,
			} {
				if !strings.Contains(summary, want) {
					t.Fatalf("%s diagnostic summary missing interaction state %q:\n%s", strings.Join(tc.path, string(os.PathSeparator)), want, summary)
				}
			}
		})
	}
}

func TestDiagnosticDisclosuresArePrintExpanded(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name   string
		path   []string
		marker string
	}{
		{
			name:   "shared feed status",
			path:   []string{"templates", "partials", "feed_status.html"},
			marker: `aria-label="Show full feed ` + `error for {{$feed.FeedName}}"`,
		},
		{
			name:   "admin queue mobile",
			path:   []string{"templates", "admin", "queue.html"},
			marker: `{{truncate .Error 80}}`,
		},
		{
			name:   "admin queue desktop",
			path:   []string{"templates", "admin", "queue.html"},
			marker: `{{truncate .Error 40}}`,
		},
		{
			name:   "admin audit details",
			path:   []string{"templates", "admin", "audit.html"},
			marker: `<bdi dir="auto">{{truncate .DetailsStr 80}}</bdi>`,
		},
		{
			name:   "manual advisory mobile summary",
			path:   []string{"templates", "admin", "advisories.html"},
			marker: `{{truncate .Summary 120}}`,
		},
		{
			name:   "manual advisory desktop summary",
			path:   []string{"templates", "admin", "advisories.html"},
			marker: `{{truncate .Summary 80}}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			body := readTextFile(t, tc.path...)
			details := ancestorOpeningTagContaining(t, body, "<details", tc.marker)
			if !strings.Contains(details, "data-print-open") {
				t.Fatalf("%s diagnostic details should print expanded; missing data-print-open:\n%s", strings.Join(tc.path, string(os.PathSeparator)), details)
			}
			if strings.Contains(details, "no-print") || strings.Contains(details, "data-no-print") {
				t.Fatalf("%s diagnostic details should not inherit mutation-control print suppression:\n%s", strings.Join(tc.path, string(os.PathSeparator)), details)
			}
		})
	}
}

func TestBidiSensitiveTemplateValuesUseAutoDirection(t *testing.T) {
	t.Parallel()

	audit := readTextFile(t, "templates", "admin", "audit.html")
	for _, want := range []string{
		`<summary dir="auto"`,
		`<bdi dir="auto">{{truncate .DetailsStr 80}}</bdi>`,
		`<pre dir="auto"`,
		`<bdi dir="auto">{{.DetailsStr}}</bdi></pre>`,
		`{{else}}`,
		`<bdi dir="auto">{{.DetailsStr}}</bdi>`,
	} {
		if !strings.Contains(audit, want) {
			t.Fatalf("admin audit template missing bidi detail marker %q:\n%s", want, audit)
		}
	}

	queue := readTextFile(t, "templates", "admin", "queue.html")
	for _, want := range []string{
		`<bdi dir="auto">{{.Ecosystem}}</bdi>/<bdi dir="auto">{{.Name}}</bdi>`,
	} {
		if got := strings.Count(queue, want); got < 2 {
			t.Fatalf("admin queue template bidi package marker %q count = %d, want at least 2\n%s", want, got, queue)
		}
	}

	search := readTextFile(t, "templates", "search.html")
	for _, want := range []string{
		`id="search-input"`,
		`dir="auto"`,
		`<bdi dir="auto">{{.Name}}</bdi>`,
		`{{t "search.version.label"}} <bdi dir="auto">{{.Version}}</bdi>`,
		`<bdi dir="auto">{{.VulnerabilityIDs}}</bdi>`,
		`<bdi dir="auto">{{.Sources}}</bdi>`,
	} {
		if !strings.Contains(search, want) {
			t.Fatalf("search template missing bidi marker %q:\n%s", want, search)
		}
	}

	pkg := readTextFile(t, "templates", "package.html")
	pkgRiskTable := readTextFile(t, "templates", "partials", "package_risk_finding_table.html")
	pkgTemplates := pkg + "\n" + pkgRiskTable
	for _, want := range []string{
		`<h1 class="text-2xl font-bold break-all"><bdi dir="auto">{{.Name}}</bdi></h1>`,
		`<input type="text" name="version" value="{{.Version}}" dir="auto"`,
		`<bdi dir="auto">{{.AdvisoryID}}</bdi>`,
		`<bdi dir="auto">{{.Version}}</bdi>`,
		`<bdi dir="auto">{{.Title}}</bdi>`,
		`<bdi dir="auto">{{.Source}}</bdi>`,
		`<bdi dir="auto">{{.Label}}</bdi>`,
	} {
		if !strings.Contains(pkgTemplates, want) {
			t.Fatalf("package template missing bidi marker %q:\n%s", want, pkgTemplates)
		}
	}
}

func TestExternalLinkIndicatorsAreDirectionAware(t *testing.T) {
	t.Parallel()

	style := readTextFile(t, "static", "style.css")
	for _, want := range []string{
		`.external-link-icon`,
		`[dir="rtl"] .external-link-icon`,
		`scaleX(-1)`,
	} {
		if !strings.Contains(style, want) {
			t.Fatalf("style.css missing direction-aware external link marker %q:\n%s", want, style)
		}
	}

	for _, tc := range []struct {
		name string
		path []string
	}{
		{name: "dashboard", path: []string{"templates", "dashboard.html"}},
		{name: "package", path: []string{"templates", "package.html"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			body := readTextFile(t, tc.path...)
			for _, blocked := range []string{`&#8599;`, `↗`} {
				if strings.Contains(body, blocked) {
					t.Fatalf("%s template still uses raw external link glyph %q:\n%s", tc.name, blocked, body)
				}
			}
			for _, want := range []string{
				`{{template "external-link-icon"}}`,
				`<span class="sr-only">{{newTabSRText}}</span>`,
			} {
				if !strings.Contains(body, want) {
					t.Fatalf("%s template missing external link marker %q:\n%s", tc.name, want, body)
				}
			}
		})
	}

	partial := readTextFile(t, "templates", "partials", "external_link_icon.html")
	for _, want := range []string{
		`{{define "external-link-icon"}}`,
		`<svg`,
		`data-external-link-icon`,
		`aria-hidden="true"`,
		`focusable="false"`,
		`class="external-link-icon"`,
		`stroke="currentColor"`,
	} {
		if !strings.Contains(partial, want) {
			t.Fatalf("external_link_icon.html missing %q:\n%s", want, partial)
		}
	}
	for _, blocked := range []string{`&#8599;`, `↗`} {
		if strings.Contains(partial, blocked) {
			t.Fatalf("external_link_icon.html still uses raw external link glyph %q:\n%s", blocked, partial)
		}
	}

	for _, path := range allWebTemplateFiles(t) {
		body := readTextFile(t, path)
		for _, blocked := range []string{`&#8599;`, `↗`} {
			if strings.Contains(body, blocked) {
				t.Fatalf("%s still uses raw external link glyph %q", path, blocked)
			}
		}
	}
}

func TestFilledActionButtonsUseSharedFocusRing(t *testing.T) {
	t.Parallel()

	filledButton := regexp.MustCompile(`(?s)<button\b[^>]*class="([^"]*\b(?:bg-blue-600|bg-danger|bg-danger|bg-green-700)\b[^"]*)"`)
	for _, path := range allTemplateFiles(t) {
		body := readTextFile(t, path)
		for _, match := range filledButton.FindAllStringSubmatch(body, -1) {
			classes := match[1]
			for _, want := range []string{
				`pm-focus-ring`,
			} {
				if !strings.Contains(classes, want) {
					t.Fatalf("%s filled action button missing %q:\n%s", path, want, match[0])
				}
			}
		}
	}
}

func TestAdminPrimaryActionButtonsUseSharedTouchTargetPattern(t *testing.T) {
	t.Parallel()

	render := readTextFile(t, "render.go")
	helperAt := strings.Index(render, "func adminPrimaryButtonClass(")
	if helperAt < 0 {
		t.Fatal("render.go missing shared adminPrimaryButtonClass helper")
	}
	helperEnd := strings.Index(render[helperAt:], "\n}\n")
	if helperEnd < 0 {
		t.Fatal("adminPrimaryButtonClass helper body is not delimited")
	}
	helper := render[helperAt : helperAt+helperEnd]
	for _, want := range []string{
		`inline-flex`,
		`min-h-11`,
		`items-center`,
		`justify-center`,
		`rounded-md`,
		`bg-accent`,
		`px-4`,
		`py-2`,
		`text-sm`,
		`font-medium`,
		`text-accent-contrast`,
		`hover:bg-accent-hover`,
		`active:bg-accent-hover`,
		`pm-focus-ring`,
	} {
		if !strings.Contains(helper, want) {
			t.Fatalf("adminPrimaryButtonClass missing shared touch/style token %q:\n%s", want, helper)
		}
	}

	directPrimary := regexp.MustCompile(`(?s)<(?:a|button)\b[^>]*\bclass="[^"]*\bbg-blue-600\b[^"]*"`)
	helperCalls := 0
	for _, path := range allWebTemplateFiles(t) {
		slashPath := filepath.ToSlash(path)
		if !strings.HasPrefix(slashPath, "templates/admin/") && !strings.HasPrefix(slashPath, "templates/partials/admin_") {
			continue
		}
		body := readTextFile(t, path)
		if match := directPrimary.FindString(body); match != "" {
			t.Fatalf("%s primary action bypasses shared adminPrimaryButtonClass helper:\n%s", path, match)
		}
		helperCalls += strings.Count(body, `class="{{adminPrimaryButtonClass`)
	}
	if helperCalls == 0 {
		t.Fatal("admin templates do not use adminPrimaryButtonClass")
	}
}

func TestHTMXFeedbackRegionsExposeLiveAndBusySemantics(t *testing.T) {
	t.Parallel()

	publicFeeds := readTextFile(t, "templates", "feeds.html")
	for _, want := range []string{
		`data-auto-refresh-status role="status" aria-live="polite" aria-atomic="true"`,
		`id="feed-status-announcement" class="sr-only" role="status" aria-live="polite" aria-atomic="true"`,
	} {
		if !strings.Contains(publicFeeds, want) {
			t.Fatalf("feeds.html missing HTMX live/busy marker %q", want)
		}
	}
	assertNotLiveRegion(t, openingTagContaining(t, publicFeeds, `id="feed-status-container"`), "feed-status-container")
	assertNotLiveRegion(t, openingTagContaining(t, publicFeeds, `aria-label="{{t "feeds.table.label"}}"`), "feed status table")
	if !strings.Contains(openingTagContaining(t, publicFeeds, `id="feed-status-container"`), `aria-busy="false"`) {
		t.Fatal("feeds.html feed-status-container target missing aria-busy marker")
	}

	adminFeeds := readTextFile(t, "templates", "admin", "feeds.html")
	for _, want := range []string{
		`data-auto-refresh-status role="status" aria-live="polite" aria-atomic="true"`,
		`id="admin-feed-runtime-announcement" class="sr-only" role="status" aria-live="polite" aria-atomic="true"`,
		`data-feed-sync-now`,
	} {
		if !strings.Contains(adminFeeds, want) {
			t.Fatalf("admin/feeds.html missing HTMX live/busy marker %q", want)
		}
	}
	assertNotLiveRegion(t, openingTagContaining(t, adminFeeds, `id="admin-feed-flash"`), "admin-feed-flash")
	assertNotLiveRegion(t, openingTagContaining(t, adminFeeds, `id="admin-feed-runtime"`), "admin-feed-runtime")
	assertNotLiveRegion(t, openingTagContaining(t, adminFeeds, `aria-label="{{t "admin.feeds.runtime.table_aria"}}"`), "admin feed runtime table")
	if !strings.Contains(openingTagContaining(t, adminFeeds, `id="admin-feed-runtime"`), `aria-busy="false"`) {
		t.Fatal("admin/feeds.html admin-feed-runtime target missing aria-busy marker")
	}
	if strings.Contains(adminFeeds, `setTimeout`) || strings.Contains(adminFeeds, `_syncFlashTimer`) {
		t.Fatal("admin feed sync button still uses timer-based success feedback instead of the persistent flash region")
	}

	search := readTextFile(t, "templates", "search.html")
	searchResultsTag := openingTagContaining(t, search, `id="search-results"`)
	assertNotLiveRegion(t, searchResultsTag, "search-results")
	assertNotLiveRegion(t, openingTagContaining(t, search, `aria-label="{{t "search.table.label"}}"`), "package search results table")
	if !strings.Contains(searchResultsTag, `aria-busy="false"`) {
		t.Fatal("search.html search-results target missing aria-busy marker")
	}
	searchStatusTag := openingTagContaining(t, search, `id="search-status"`)
	for _, want := range []string{`aria-live="`, `aria-atomic="true"`} {
		if !strings.Contains(searchStatusTag, want) {
			t.Fatalf("search.html search-status missing concise live-region marker %q:\n%s", want, searchStatusTag)
		}
	}

	formScript := readTextFile(t, "static", "form-actions.js")
	for _, want := range []string{
		`initFeedSyncButtons`,
	} {
		if !strings.Contains(formScript, want) {
			t.Fatalf("form-actions.js missing feed-sync behavior %q", want)
		}
	}
	htmxScript := readTextFile(t, "static", "htmx-regions.js")
	for _, want := range []string{
		`htmx:beforeRequest`,
		`htmx:afterRequest`,
		`htmx:responseError`,
		`aria-busy`,
	} {
		if !strings.Contains(htmxScript, want) {
			t.Fatalf("htmx-regions.js missing HTMX busy-state behavior %q", want)
		}
	}
}

func TestSearchFiltersUseSharedFormControlInsets(t *testing.T) {
	t.Parallel()

	search := readTextFile(t, "templates", "search.html")
	for _, marker := range []string{
		`id="search-input"`,
		`id="severity-filter"`,
		`id="finding-filter"`,
	} {
		control := openingTagContaining(t, search, marker)
		if !strings.Contains(control, `pm-form-control`) {
			t.Fatalf("search control %q does not use shared form-control token:\n%s", marker, control)
		}
		if strings.Contains(control, `px-4 py-2`) {
			t.Fatalf("search control %q still uses wider form insets:\n%s", marker, control)
		}
	}
}

func openingTagContaining(t *testing.T, body, marker string) string {
	t.Helper()

	markerAt := strings.Index(body, marker)
	if markerAt < 0 {
		t.Fatalf("template missing marker %q", marker)
	}
	tagStart := strings.LastIndex(body[:markerAt], "<")
	if tagStart < 0 {
		t.Fatalf("marker %q is not inside an HTML tag", marker)
	}
	tagEndOffset := strings.Index(body[markerAt:], ">")
	if tagEndOffset < 0 {
		t.Fatalf("marker %q is inside an unterminated HTML tag", marker)
	}
	return body[tagStart : markerAt+tagEndOffset+1]
}

func tagContainsDirectOrAdminPrimaryClass(tag, token string) bool {
	if strings.Contains(tag, token) {
		return true
	}
	if !strings.Contains(tag, `{{adminPrimaryButtonClass`) {
		return false
	}
	return strings.Contains(adminPrimaryButtonClass("w-full"), token)
}

func ancestorOpeningTagContaining(t *testing.T, body, tagName, marker string) string {
	t.Helper()

	markerAt := strings.Index(body, marker)
	if markerAt < 0 {
		t.Fatalf("template missing marker %q", marker)
	}
	tagStart := strings.LastIndex(body[:markerAt], tagName)
	if tagStart < 0 {
		t.Fatalf("marker %q is not inside ancestor tag %q", marker, tagName)
	}
	tagEndOffset := strings.Index(body[tagStart:], ">")
	if tagEndOffset < 0 || tagStart+tagEndOffset > markerAt {
		t.Fatalf("ancestor tag %q before marker %q is malformed", tagName, marker)
	}
	return body[tagStart : tagStart+tagEndOffset+1]
}

func ancestorOpeningTagsContaining(t *testing.T, body, tagName, marker string) []string {
	t.Helper()

	var tags []string
	searchFrom := 0
	for {
		markerAt := strings.Index(body[searchFrom:], marker)
		if markerAt < 0 {
			break
		}
		markerAt += searchFrom
		tagStart := strings.LastIndex(body[:markerAt], tagName)
		if tagStart < 0 {
			t.Fatalf("marker %q is not inside ancestor tag %q", marker, tagName)
		}
		tagEndOffset := strings.Index(body[tagStart:], ">")
		if tagEndOffset < 0 || tagStart+tagEndOffset > markerAt {
			t.Fatalf("ancestor tag %q before marker %q is malformed", tagName, marker)
		}
		tags = append(tags, body[tagStart:tagStart+tagEndOffset+1])
		searchFrom = markerAt + len(marker)
	}
	if len(tags) == 0 {
		t.Fatalf("template missing marker %q", marker)
	}
	return tags
}

func assertNotLiveRegion(t *testing.T, tag, name string) {
	t.Helper()

	for _, blocked := range []string{`aria-live=`, `role="status"`, `role="alert"`} {
		if strings.Contains(tag, blocked) {
			t.Fatalf("%s should not be a live region, found %q in:\n%s", name, blocked, tag)
		}
	}
}

func TestWebTemplatesAvoidInlineScriptAndStyleDependencies(t *testing.T) {
	t.Parallel()

	layout := readTextFile(t, "templates", "layout.html")
	for _, want := range []string{
		`{{if layoutNeedsHTMX}}`,
		`<meta name="htmx-config"`,
		`"includeIndicatorStyles":false`,
		`"allowEval":false`,
		`"allowScriptTags":false`,
		`"historyEnabled":false`,
		`<link rel="stylesheet" href="{{assetURL "/static/tailwind.css"}}">`,
		`<script src="{{assetURL "/static/htmx.min.js"}}" defer></script>`,
		`{{if layoutNeedsHelperScript}}`,
		`<script src="{{assetURL "/static/auto-refresh.js"}}" defer></script>`,
		`<script src="{{assetURL "/static/form-actions.js"}}" defer></script>`,
		`<script src="{{assetURL "/static/htmx-regions.js"}}" defer></script>`,
	} {
		if !strings.Contains(layout, want) {
			t.Fatalf("layout.html missing htmx CSP-safe config marker %q:\n%s", want, layout)
		}
	}
	if strings.Index(layout, `<script src="{{assetURL "/static/htmx.min.js"}}" defer></script>`) < strings.Index(layout, `<link rel="stylesheet" href="{{assetURL "/static/style.css"}}">`) {
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

	script := readTextFile(t, "static", "form-actions.js")
	for _, want := range []string{
		`initCopyButtons`,
		`initSelectOnFocusInputs`,
		`initFeedSyncButtons`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("form-actions.js missing externalized inline behavior %q", want)
		}
	}
}

func TestLocalTimeFormattingEnhancementIsExternalized(t *testing.T) {
	t.Parallel()

	layout := readTextFile(t, "templates", "layout.html")
	if !strings.Contains(layout, `<script src="{{assetURL "/static/locale-format.js"}}" defer></script>`) {
		t.Fatalf("layout.html missing locale formatting script:\n%s", layout)
	}

	script := readTextFile(t, "static", "locale-format.js")
	for _, want := range []string{
		`document.querySelectorAll("time[datetime][data-local-time]")`,
		`document.querySelectorAll("[data-local-number]")`,
		`document.querySelectorAll("[data-local-percent]")`,
		`document.querySelectorAll("[data-local-duration-ms]")`,
		`Intl.DateTimeFormat`,
		`Intl.RelativeTimeFormat`,
		`Intl.NumberFormat`,
		`element.setAttribute("aria-label", absoluteLabel);`,
		`element.setAttribute("title", absoluteLabel);`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("locale-format.js missing browser-locale formatting marker %q:\n%s", want, script)
		}
	}

	timeTag := regexp.MustCompile(`<time\b[^>]*datetime="\{\{formatTimeISO [^}]+\}\}"[^>]*>`)
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
		for _, tag := range timeTag.FindAllString(string(body), -1) {
			if !strings.Contains(tag, `data-local-time="`) {
				t.Fatalf("%s time tag is not marked for browser-locale formatting:\n%s", path, tag)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk templates: %v", err)
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
		`{{$alert := adminAlert .}}`,
		`data-alert-variant="{{$alert.Variant}}"`,
		`aria-hidden="true"`,
		`data-alert-icon="{{.Variant}}"`,
		`data-alert-dismissible`,
		`data-alert-dismiss`,
		`aria-label="Dismiss alert"`,
		`class="min-w-0 max-w-3xl flex-1"`,
	} {
		if !strings.Contains(partial, want) {
			t.Fatalf("admin alert partial missing %q:\n%s", want, partial)
		}
	}
	for _, blocked := range []string{
		`eq .Variant`,
		`else if eq .Variant`,
	} {
		if strings.Contains(partial, blocked) {
			t.Fatalf("admin alert partial still embeds variant branch %q:\n%s", blocked, partial)
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
			`bg-success-bg border border-green-200 text-green-800 rounded-md px-4 py-3 text-sm`,
			`bg-danger-bg border border-danger text-danger-fg rounded-md px-4 py-3 text-sm`,
			`bg-danger-bg border border-danger text-danger-fg rounded-md px-4 py-3 text-sm`,
			`bg-warning-bg border border-yellow-200 rounded-md p-4 text-sm text-yellow-800`,
			`bg-danger-bg text-danger-fg text-sm border-b border-danger`,
		} {
			if strings.Contains(body, blocked) {
				t.Fatalf("%s still implements alert markup directly with %q", path, blocked)
			}
		}
	}

	bootstrap := readTextFile(t, "templates", "partials", "admin_bootstrap.html")
	oldBareGlyphClass := `text-xl ` + "m" + `r-3">!</div>`
	if strings.Contains(bootstrap, `>!</div>`) || strings.Contains(bootstrap, oldBareGlyphClass) {
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

func TestFormActionsScriptDismissesAdminFlashAlerts(t *testing.T) {
	t.Parallel()

	script := readTextFile(t, "static", "form-actions.js")
	for _, want := range []string{
		`initDismissibleAlerts`,
		`document.body.addEventListener("click"`,
		`target.closest("[data-alert-dismiss]")`,
		`button.closest("[data-alert-dismissible]")`,
		`alert.hidden = true;`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("form-actions.js missing dismissible alert behavior %q:\n%s", want, script)
		}
	}
}

func TestAdminBootstrapWarningDoesNotBreakHeadingOrder(t *testing.T) {
	t.Parallel()

	bootstrap := readTextFile(t, "templates", "partials", "admin_bootstrap.html")
	for _, blocked := range []string{"<h1", "<h2", "<h3", "<h4", "<h5", "<h6"} {
		if strings.Contains(bootstrap, blocked) {
			t.Fatalf("admin bootstrap warning must not render heading markup %q:\n%s", blocked, bootstrap)
		}
	}
	if !strings.Contains(bootstrap, `<p class="text-sm font-semibold text-warning-fg">Bootstrap password still active</p>`) {
		t.Fatalf("admin bootstrap warning missing non-heading title text:\n%s", bootstrap)
	}

	dashboard := readTextFile(t, "templates", "admin", "dashboard.html")
	if !strings.Contains(dashboard, `{{template "admin-page-header"`) {
		t.Fatalf("admin dashboard missing page header before bootstrap warning:\n%s", dashboard)
	}
}

func TestAdminFeedActionControlsUseContrastSafeBorders(t *testing.T) {
	t.Parallel()

	body := readTextFile(t, "templates", "admin", "feeds.html")
	for _, blocked := range []string{
		`name="confirm_clear_api_key" class="h-4 w-4 rounded border-danger`,
		`name="confirm_reset" class="rounded border-danger`,
		`border border-info text-accent`,
	} {
		if strings.Contains(body, blocked) {
			t.Fatalf("admin feed action control still uses low-contrast border marker %q:\n%s", blocked, body)
		}
	}
	disabledInterval := openingTagContaining(t, body, `value="{{t "admin.feeds.status.queue_driven"}}"`)
	if !strings.Contains(disabledInterval, `pm-form-control`) {
		t.Fatalf("disabled feed interval input missing shared form-control token:\n%s", disabledInterval)
	}
	confirmClear := openingTagContaining(t, body, `name="confirm_clear_api_key"`)
	for _, want := range []string{`border-danger`, `pm-focus-ring`, `pm-focus-ring-danger`} {
		if !strings.Contains(confirmClear, want) {
			t.Fatalf("feed clear-key confirmation missing %q:\n%s", want, confirmClear)
		}
	}
	syncNow := openingTagContaining(t, body, `data-feed-sync-now`)
	if !strings.Contains(syncNow, `border-accent`) {
		t.Fatalf("feed sync-now button missing contrast-safe blue border:\n%s", syncNow)
	}
	confirmReset := openingTagContaining(t, body, `name="confirm_reset"`)
	for _, want := range []string{`border-danger`, `pm-focus-ring`, `pm-focus-ring-danger`} {
		if !strings.Contains(confirmReset, want) {
			t.Fatalf("feed reset confirmation missing %q:\n%s", want, confirmReset)
		}
	}
}

func TestAdminNoneThresholdAcknowledgementUsesContrastSafeFocus(t *testing.T) {
	t.Parallel()

	body := readTextFile(t, "templates", "admin", "settings.html")
	for _, blocked := range []string{`border-yellow-300`, `border-yellow-500`, `focus:ring-yellow-600`} {
		if strings.Contains(body, blocked) {
			t.Fatalf("NONE threshold acknowledgement still uses low-contrast token %q:\n%s", blocked, body)
		}
	}
	for _, want := range []string{
		`border border-warning bg-warning-bg`,
		`id="ack-block-threshold-none"`,
		`aria-describedby="ack-block-threshold-none-help"`,
		`data-required-when-select="#block-threshold"`,
		`data-required-value="NONE"`,
		`data-required-message="{{t "admin.settings.system.none_required"}}"`,
		`class="mt-0.5 h-4 w-4 rounded border-warning text-warning-fg pm-focus-ring pm-focus-ring-warning"`,
		`id="ack-block-threshold-none-help"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("NONE threshold acknowledgement missing contrast-safe token %q:\n%s", want, body)
		}
	}
}

func TestAdminNoneThresholdWarningUsesMaliciousPackageCopy(t *testing.T) {
	t.Parallel()

	body := readTextFile(t, "templates", "admin", "settings.html")
	for _, want := range []string{
		`{{t "admin.settings.system.threshold_help"}}`,
		`{{t "admin.settings.system.none_warning"}}`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("NONE threshold warning missing malicious package copy %q:\n%s", want, body)
		}
	}
	catalog := readTextFile(t, "render.go")
	for _, want := range []string{
		`Malicious package findings always block regardless of this threshold.`,
		`NONE disables vulnerability blocking. Malicious package findings and active supply-chain risk findings still block. This acknowledgement is required before saving NONE.`,
	} {
		if !strings.Contains(catalog, want) {
			t.Fatalf("NONE threshold warning catalog missing malicious package copy %q:\n%s", want, catalog)
		}
	}
	for _, blocked := range []string{
		`Malware and active supply-chain risk findings still block`,
		`NONE disables malware`,
		`NONE disables malicious`,
	} {
		if strings.Contains(body, blocked) {
			t.Fatalf("NONE threshold warning still contains misleading copy %q:\n%s", blocked, body)
		}
	}
}

func TestAdminAPIKeyCopyHasAccessibleStatusFeedback(t *testing.T) {
	t.Parallel()

	keys := readTextFile(t, "templates", "admin", "keys.html")
	for _, want := range []string{
		`data-copy-target="#new-api-key"`,
		`data-copy-status="#new-api-key-copy-status"`,
		`aria-describedby="new-api-key-copy-status"`,
		`id="new-api-key-copy-status"`,
		`role="status"`,
		`aria-live="polite"`,
		`aria-atomic="true"`,
		`class="sr-only"`,
	} {
		if !strings.Contains(keys, want) {
			t.Fatalf("admin keys copy UI missing accessible status marker %q:\n%s", want, keys)
		}
	}

	script := readTextFile(t, "static", "form-actions.js")
	for _, want := range []string{
		`copyStatusElement`,
		`setCopyStatus`,
		`API key copied to clipboard.`,
		`Copy failed. API key selected for manual copying.`,
		`Clipboard unavailable. API key selected for manual copying.`,
		`var clipboardWrite = navigator.clipboard.writeText(target.value || "");`,
		`void Promise.resolve(clipboardWrite).then`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("form-actions.js copy behavior missing status feedback %q:\n%s", want, script)
		}
	}
}

func TestAdminNewAPIKeyFieldUsesContrastSafeBorder(t *testing.T) {
	t.Parallel()

	keys := readTextFile(t, "templates", "admin", "keys.html")
	if strings.Contains(keys, `border border-info rounded`) {
		t.Fatalf("new API key field still uses low-contrast border-info:\n%s", keys)
	}
	if !strings.Contains(keys, `class="min-w-0 flex-1 min-h-11 bg-surface border border-accent rounded`) {
		t.Fatalf("new API key field missing contrast-safe border-accent class:\n%s", keys)
	}
}

func TestAdminAPIKeyActionsExplainCredentialImpact(t *testing.T) {
	t.Parallel()

	keys := readTextFile(t, "templates", "admin", "keys.html")
	for _, want := range []string{
		`{{t "admin.keys.action.revoke_impact"}}`,
		`{{t "admin.keys.action.delete_impact"}}`,
		`{{t "admin.keys.create.submit"}}`,
		`<h2 class="text-lg font-semibold mb-3">{{t "admin.keys.create.heading"}}</h2>`,
		`{{t "admin.keys.create.current_password_help"}}`,
		`data-submit-lock-label="{{t "admin.keys.create.saving"}}"`,
		`{{t "admin.keys.created_notice"}}`,
	} {
		if !strings.Contains(keys, want) {
			t.Fatalf("admin keys template missing credential-impact copy %q:\n%s", want, keys)
		}
	}
	catalog := readTextFile(t, "render.go")
	for _, want := range []string{
		`Revoking this credential immediately prevents clients using it from authenticating to Packmon APIs.`,
		`Deleting this revoked credential hides it from active administration views and keeps it unusable for API authentication.`,
		`Create API key`,
		`Required to create a new API key.`,
		`Creating API key`,
		`API key created. Copy it now -- it will not be shown again.`,
	} {
		if !strings.Contains(catalog, want) {
			t.Fatalf("admin keys catalog missing credential-impact copy %q:\n%s", want, catalog)
		}
	}
	for _, blocked := range []string{
		`Generate New Key`,
		`Generating key`,
		`New API key generated`,
		`Required to create a new API credential`,
		`Create API Key`,
		`>Generate</button>`,
	} {
		if strings.Contains(keys, blocked) {
			t.Fatalf("admin keys template still uses stale create-flow copy %q:\n%s", blocked, keys)
		}
	}
}

func TestAdminAuthActionCopyUsesSignInAndLogOut(t *testing.T) {
	t.Parallel()

	login := readTextFile(t, "templates", "admin", "login.html")
	if !strings.Contains(login, `Sign in`) {
		t.Fatalf("admin login submit missing Sign in label:\n%s", login)
	}
	if strings.Contains(login, `>Login</button>`) {
		t.Fatalf("admin login submit still uses Login label:\n%s", login)
	}

	nav := readTextFile(t, "templates", "partials", "admin_nav.html")
	if !strings.Contains(nav, `>Log out</button>`) {
		t.Fatalf("admin nav logout button missing Log out label:\n%s", nav)
	}
	if strings.Contains(nav, `>Logout</button>`) {
		t.Fatalf("admin nav logout button still uses Logout label:\n%s", nav)
	}
}

func TestAdminFeedModeAndResetCopyUsesHumanLabels(t *testing.T) {
	t.Parallel()

	feeds := readTextFile(t, "templates", "admin", "feeds.html")
	for _, want := range []string{
		`{{feedModeLabel .ConfigMode}}`,
		`{{t "admin.feeds.form.runtime_line" $runtimeModeLabel $runtimeEnabledLabel $runtimeSyncLabel $runtimeAPIKeyLabel}}`,
		`{{feedModeLabel .Value}}`,
		`{{t "admin.feeds.form.mode_external_help"}}`,
		`{{t "admin.feeds.form.mode_self_help"}}`,
		`{{t "admin.feeds.status.database_override"}}`,
	} {
		if !strings.Contains(feeds, want) {
			t.Fatalf("admin feeds template missing human feed copy %q:\n%s", want, feeds)
		}
	}
	if strings.Contains(feeds, `DB override`) {
		t.Fatalf("admin feeds template still uses DB override copy:\n%s", feeds)
	}
	for _, blocked := range []string{
		`{{if eq .ConfigMode "self"}}`,
		`{{if eq .RuntimeMode "self"}}`,
		`{{.ConfigMode}}`,
		`{{.RuntimeMode}}`,
	} {
		if strings.Contains(feeds, blocked) {
			t.Fatalf("admin feeds template still renders raw feed mode copy %q:\n%s", blocked, feeds)
		}
	}
}

func TestAdminManualAdvisoryCopyUsesHumanLabelsAndCoverageWarning(t *testing.T) {
	t.Parallel()

	body := readTextFile(t, "templates", "admin", "advisories.html")
	for _, want := range []string{
		`<option value="vulnerability"`,
		`>Vulnerability</option>`,
		`<option value="malicious"`,
		`>Malicious package</option>`,
		`<option value="malware"`,
		`>Malware</option>`,
		`<option value="typosquatting"`,
		`>Typosquatting</option>`,
		`<option value="supply_chain"`,
		`>Supply-chain risk</option>`,
		`<option value="other"`,
		`>Other</option>`,
		`{{if .IsEditing}}{{t "admin.advisories.form.save"}}{{else}}{{t "admin.advisories.form.create"}}{{end}}`,
		`{{t "admin.advisories.action.delete_impact"}}`,
		`{{range findingLabels .FindingType}}<bdi dir="auto">{{.}}</bdi>{{end}}`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("admin manual advisory template missing copy fragment %q:\n%s", want, body)
		}
	}
	catalog := readTextFile(t, "render.go")
	if !strings.Contains(catalog, `Deleting this advisory removes manually maintained scan coverage for this package.`) {
		t.Fatalf("admin manual advisory catalog missing delete impact copy:\n%s", catalog)
	}
	for _, blocked := range []string{
		`>vulnerability</option>`,
		`>malicious</option>`,
		`>typosquatting</option>`,
		`>supply_chain</option>`,
		`{{.FindingType}}</bdi>`,
		`{{.RiskType}}</bdi>`,
		`{{if .IsEditing}}Save Advisory{{else}}Create Advisory{{end}}`,
	} {
		if strings.Contains(body, blocked) {
			t.Fatalf("admin manual advisory template still exposes raw/generic copy %q:\n%s", blocked, body)
		}
	}
}

func TestAdminActionButtonsUseTouchTargets(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		path    []string
		markers []string
	}{
		{
			name: "login",
			path: []string{"templates", "admin", "login.html"},
			markers: []string{
				`data-submit-lock-button`,
			},
		},
		{
			name: "api key copy and generate",
			path: []string{"templates", "admin", "keys.html"},
			markers: []string{
				`aria-label="{{t "admin.keys.copy_aria"}}"`,
				`data-submit-lock-button`,
			},
		},
		{
			name: "manual advisory submit",
			path: []string{"templates", "admin", "advisories.html"},
			markers: []string{
				`{{if .IsEditing}}{{t "admin.advisories.form.save"}}{{else}}{{t "admin.advisories.form.create"}}{{end}}`,
			},
		},
		{
			name: "feed save sync reset",
			path: []string{"templates", "admin", "feeds.html"},
			markers: []string{
				`aria-label="{{t "admin.feeds.form.save_aria" .FeedName}}"`,
				`aria-label="{{t "admin.feeds.sync.aria" .FeedName}}"`,
				`aria-label="{{t "admin.feeds.reset.aria" .FeedName}}"`,
			},
		},
		{
			name: "system settings and password",
			path: []string{"templates", "admin", "settings.html"},
			markers: []string{
				`{{t "admin.settings.system.save"}}</button>`,
				`{{t "admin.settings.password.change"}}</button>`,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			body := readTextFile(t, tc.path...)
			for _, marker := range tc.markers {
				tag := openingTagContaining(t, body, marker)
				for _, want := range []string{`inline-flex`, `min-h-11`, `items-center`, `justify-center`} {
					if !tagContainsDirectOrAdminPrimaryClass(tag, want) {
						t.Fatalf("%s action button %q missing %q:\n%s", strings.Join(tc.path, string(os.PathSeparator)), marker, want, tag)
					}
				}
			}
		})
	}
}

func TestAdminSharedFormActionButtonsUseActiveState(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		path    []string
		markers []string
	}{
		{
			name: "package version check",
			path: []string{"templates", "package.html"},
			markers: []string{
				`>{{t "package.action.check_version"}}</button>`,
			},
		},
		{
			name: "manual advisory submit",
			path: []string{"templates", "admin", "advisories.html"},
			markers: []string{
				`{{if .IsEditing}}{{t "admin.advisories.form.save"}}{{else}}{{t "admin.advisories.form.create"}}{{end}}`,
				`{{t "admin.advisories.action.confirm_delete_aria" .Advisory.ID .Advisory.Ecosystem .Advisory.Name}}`,
			},
		},
		{
			name: "api key actions",
			path: []string{"templates", "admin", "keys.html"},
			markers: []string{
				`aria-label="{{t "admin.keys.copy_aria"}}"`,
				`data-submit-lock-button`,
				`{{t "admin.keys.action.confirm_revoke_aria" .Key.Name .Key.ID}}`,
				`{{t "admin.keys.action.confirm_delete_aria" .Key.Name .Key.ID}}`,
			},
		},
		{
			name: "feed actions",
			path: []string{"templates", "admin", "feeds.html"},
			markers: []string{
				`data-auto-refresh-toggle`,
				`aria-label="{{t "admin.feeds.form.save_aria" .FeedName}}"`,
				`aria-label="{{t "admin.feeds.sync.aria" .FeedName}}"`,
				`aria-label="{{t "admin.feeds.reset.aria" .FeedName}}"`,
			},
		},
		{
			name: "settings actions",
			path: []string{"templates", "admin", "settings.html"},
			markers: []string{
				`{{t "admin.settings.system.save"}}`,
				`{{t "admin.settings.password.change"}}`,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			body := readTextFile(t, tc.path...)
			for _, marker := range tc.markers {
				tag := openingTagContaining(t, body, marker)
				if !tagContainsDirectOrAdminPrimaryClass(tag, `active:bg-`) {
					t.Fatalf("%s form action %q missing active background state:\n%s", strings.Join(tc.path, string(os.PathSeparator)), marker, tag)
				}
			}
		})
	}
}

func TestAdminQueueRowActionButtonsExposeFocusAndActiveStates(t *testing.T) {
	t.Parallel()

	body := readTextFile(t, "templates", "admin", "queue.html")
	for _, marker := range []string{
		`{{t "admin.queue.row.priority.save_aria" $job.ID $job.Ecosystem $job.Name}}`,
		`{{t "admin.queue.row.pause_aria" $job.ID $job.Ecosystem $job.Name}}`,
		`{{t "admin.queue.row.resume_aria" $job.ID $job.Ecosystem $job.Name}}`,
		`{{t "admin.queue.row.retry_aria" $job.ID $job.Ecosystem $job.Name}}`,
	} {
		tag := openingTagContaining(t, body, marker)
		for _, want := range []string{
			`pm-focus-ring`,
			`active:bg-`,
		} {
			if !strings.Contains(tag, want) {
				t.Fatalf("admin queue row action %q missing %q:\n%s", marker, want, tag)
			}
		}
	}
}

func TestAdminFormFieldsUseTouchHeight(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		path    []string
		markers []string
	}{
		{
			name: "login",
			path: []string{"templates", "admin", "login.html"},
			markers: []string{
				`id="username"`,
				`id="password"`,
			},
		},
		{
			name: "api keys",
			path: []string{"templates", "admin", "keys.html"},
			markers: []string{
				`id="new-api-key"`,
				`id="key-name"`,
				`id="key-expires-in"`,
				`id="key-expires-custom"`,
				`id="key-current-password"`,
			},
		},
		{
			name: "system settings",
			path: []string{"templates", "admin", "settings.html"},
			markers: []string{
				`id="block-threshold"`,
				`id="rate-limit-per-minute"`,
				`id="rate-limit-burst"`,
				`id="current-password"`,
				`id="new-password"`,
				`id="confirm-password"`,
			},
		},
		{
			name: "manual advisories",
			path: []string{"templates", "admin", "advisories.html"},
			markers: []string{
				`id="adv-finding-type"`,
				`id="adv-ecosystem"`,
				`id="adv-name"`,
				`id="adv-severity"`,
				`id="adv-risk-type"`,
				`id="adv-summary"`,
				`id="adv-description"`,
			},
		},
		{
			name: "feeds",
			path: []string{"templates", "admin", "feeds.html"},
			markers: []string{
				`name="mode"`,
				`name="sync_interval"`,
				`value="{{t "admin.feeds.status.queue_driven"}}"`,
				`id="feed-{{.FeedKey}}-api-key"`,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			body := readTextFile(t, tc.path...)
			for _, marker := range tc.markers {
				tag := openingTagContaining(t, body, marker)
				if !strings.Contains(tag, `min-h-11`) && !strings.Contains(tag, `pm-form-control`) {
					t.Fatalf("%s form field %q missing touch-height marker:\n%s", strings.Join(tc.path, string(os.PathSeparator)), marker, tag)
				}
			}
		})
	}

	tailwindInput := readTextFile(t, "static", "tailwind.input.css")
	if !strings.Contains(tailwindInput, `.pm-form-control`) || !strings.Contains(tailwindInput, `min-height: 2.75rem`) {
		t.Fatalf("pm-form-control must preserve the established min-h-11 touch height:\n%s", tailwindInput)
	}
}

func TestAdminAPIKeyCopyHandlesClipboardWriteRejections(t *testing.T) {
	t.Parallel()

	script := readTextFile(t, "static", "form-actions.js")
	writeCall := `var clipboardWrite = navigator.clipboard.writeText(target.value || "");`
	writeAt := strings.Index(script, writeCall)
	if writeAt < 0 {
		t.Fatalf("form-actions.js copy behavior missing clipboard Promise handling %q:\n%s", writeCall, script)
	}

	catchMarker := `}).catch(function () {`
	catchAt := strings.Index(script[writeAt:], catchMarker)
	if catchAt < 0 {
		t.Fatalf("form-actions.js copy behavior does not catch clipboard Promise rejections after %q:\n%s", writeCall, script)
	}

	catchStart := writeAt + catchAt
	catchEnd := strings.Index(script[catchStart:], `});`)
	if catchEnd < 0 {
		t.Fatalf("form-actions.js copy behavior has unterminated clipboard rejection handler:\n%s", script[catchStart:])
	}
	catchBlock := script[catchStart : catchStart+catchEnd]
	if !strings.Contains(catchBlock, `handleCopyFailure(status, target);`) {
		t.Fatalf("clipboard rejection handler missing shared fallback/status marker:\n%s", catchBlock)
	}

	failureAt := strings.Index(script, `function handleCopyFailure(status, target)`)
	if failureAt < 0 {
		t.Fatalf("form-actions.js copy behavior missing shared clipboard failure handler:\n%s", script)
	}
	failureEnd := strings.Index(script[failureAt:], `function setCopyStatus(status, message)`)
	if failureEnd < 0 {
		t.Fatalf("form-actions.js copy failure handler should be followed by setCopyStatus:\n%s", script[failureAt:])
	}
	failureBlock := script[failureAt : failureAt+failureEnd]
	for _, want := range []string{
		`selectCopyTargetForManualCopy(target);`,
		`setCopyStatus(status, "Copy failed. API key selected for manual copying.");`,
	} {
		if !strings.Contains(failureBlock, want) {
			t.Fatalf("clipboard failure handler missing fallback/status marker %q:\n%s", want, failureBlock)
		}
	}
}

func TestAdminAPIKeyCopyHandlesSynchronousClipboardErrors(t *testing.T) {
	t.Parallel()

	script := readTextFile(t, "static", "form-actions.js")
	for _, want := range []string{
		`function handleCopyFailure(status, target)`,
		`try {`,
		`var clipboardWrite = navigator.clipboard.writeText(target.value || "");`,
		`void Promise.resolve(clipboardWrite).then(function () {`,
		`handleCopyFailure(status, target);`,
		`} catch {`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("form-actions.js copy behavior missing robust clipboard error handling %q:\n%s", want, script)
		}
	}
}

func TestAdminAPIKeyCopyDoesNotMoveFocusToSecretInputOnClipboardAttempt(t *testing.T) {
	t.Parallel()

	script := readTextFile(t, "static", "form-actions.js")
	clickAt := strings.Index(script, `button.addEventListener("click", function () {`)
	if clickAt < 0 {
		t.Fatalf("form-actions.js copy behavior missing click handler:\n%s", script)
	}
	clickEnd := strings.Index(script[clickAt:], `});`)
	if clickEnd < 0 {
		t.Fatalf("form-actions.js copy behavior has unterminated click handler:\n%s", script[clickAt:])
	}
	clickBlock := script[clickAt : clickAt+clickEnd]
	if strings.Contains(clickBlock, `selectCopyTarget`) || strings.Contains(clickBlock, `.focus()`) {
		t.Fatalf("copy click handler must not focus/select the secret input before clipboard result:\n%s", clickBlock)
	}

	if strings.Contains(script, `function selectCopyTarget(target)`) {
		t.Fatalf("copy behavior still exposes blind target focus helper:\n%s", script)
	}
	manualAt := strings.Index(script, `function selectCopyTargetForManualCopy(target)`)
	if manualAt < 0 {
		t.Fatalf("copy behavior missing explicit manual-copy selection helper:\n%s", script)
	}
	manualEnd := strings.Index(script[manualAt:], `function setupCopyButton(button)`)
	if manualEnd < 0 {
		t.Fatalf("manual-copy helper should be defined before setupCopyButton:\n%s", script[manualAt:])
	}
	manualBlock := script[manualAt : manualAt+manualEnd]
	if !strings.Contains(manualBlock, `target.focus({ preventScroll: true });`) {
		t.Fatalf("manual-copy fallback should move focus deliberately without scroll jump:\n%s", manualBlock)
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
	if !strings.Contains(layout, `<nav aria-label="{{t "nav.primary"}}"`) {
		t.Fatal("layout public nav missing primary aria-label message key")
	}
	for _, want := range []string{
		`{{if eq .ActiveNav "dashboard"}}aria-current="page"{{end}}`,
		`{{if eq .ActiveNav "search"}}aria-current="page"{{end}}`,
		`{{if eq .ActiveNav "feeds"}}aria-current="page"{{end}}`,
		`{{if eq .ActiveNav "admin"}}aria-current="page"{{end}}`,
		`rounded-md px-3 py-2`,
	} {
		if !strings.Contains(layout, want) {
			t.Fatalf("layout public nav missing active state %q", want)
		}
	}
	if strings.Contains(layout, `rounded px-3 py-2`) {
		t.Fatalf("layout public nav still uses smaller radius than admin nav:\n%s", layout)
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

func TestScrollableTableRegionsUseSemanticSurfaceToken(t *testing.T) {
	t.Parallel()

	scrollRegion := regexp.MustCompile(`<div\b[^>]*class="[^"]*\bpm-scroll-region\b[^"]*"[^>]*>`)
	for _, path := range allTemplateFiles(t) {
		body := readTextFile(t, path)
		for _, tag := range scrollRegion.FindAllString(body, -1) {
			for _, want := range []string{
				`tabindex="0"`,
				`role="region"`,
				`aria-label=`,
			} {
				if !strings.Contains(tag, want) {
					t.Fatalf("%s scroll region missing %q:\n%s", path, want, tag)
				}
			}
		}
		if strings.Contains(body, `overflow-x-auto pm-focus-ring`) || strings.Contains(body, `pm-focus-ring md:block`) {
			t.Fatalf("%s still hardcodes scroll-region surface utilities:\n%s", path, body)
		}
	}
}

func TestAutoRefreshPausesWhileDocumentIsHidden(t *testing.T) {
	t.Parallel()

	publicFeeds := readTextFile(t, "templates", "feeds.html")
	for _, want := range []string{
		`data-auto-refresh-control`,
		`data-auto-refresh-event="feed-status-refresh"`,
		`data-auto-refresh-interval-ms="30000"`,
	} {
		if !strings.Contains(publicFeeds, want) {
			t.Fatalf("feeds.html missing auto-refresh marker %q", want)
		}
	}

	adminFeeds := readTextFile(t, "templates", "admin", "feeds.html")
	for _, want := range []string{
		`data-auto-refresh-control`,
		`data-auto-refresh-event="admin-feed-runtime-refresh"`,
		`data-auto-refresh-interval-ms="10000"`,
	} {
		if !strings.Contains(adminFeeds, want) {
			t.Fatalf("admin/feeds.html missing auto-refresh marker %q", want)
		}
	}

	script := readTextFile(t, "static", "auto-refresh.js")
	for _, want := range []string{
		`window.setInterval(dispatchAutoRefresh, intervalMs)`,
		`document.hidden`,
		`document.visibilityState === "hidden"`,
		`visibilitychange`,
		`document.addEventListener("visibilitychange"`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("auto-refresh.js missing Page Visibility behavior %q:\n%s", want, script)
		}
	}
}

func TestAutoRefreshTimerStopsWhileDocumentIsHiddenWithoutStacking(t *testing.T) {
	t.Parallel()

	script := readTextFile(t, "static", "auto-refresh.js")
	for _, want := range []string{
		`var autoRefreshIntervalID = null;`,
		`function startAutoRefreshTimer()`,
		`function stopAutoRefreshTimer()`,
		`function syncAutoRefreshTimer()`,
		`function isAutoRefreshActive()`,
		`autoRefreshIntervalID !== null`,
		`window.clearInterval(autoRefreshIntervalID);`,
		`document.addEventListener("visibilitychange", syncAutoRefreshTimer);`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("auto-refresh.js missing hidden-tab timer guardrail %q:\n%s", want, script)
		}
	}

	dispatchAt := strings.Index(script, `function dispatchAutoRefresh()`)
	if dispatchAt < 0 {
		t.Fatalf("auto-refresh.js missing dispatchAutoRefresh:\n%s", script)
	}
	dispatchEnd := strings.Index(script[dispatchAt:], `function isAutoRefreshActive()`)
	if dispatchEnd < 0 {
		t.Fatalf("auto-refresh.js dispatchAutoRefresh should be followed by isAutoRefreshActive:\n%s", script[dispatchAt:])
	}
	dispatchBlock := script[dispatchAt : dispatchAt+dispatchEnd]
	hiddenGuardAt := strings.Index(dispatchBlock, `isAutoRefreshActive()`)
	dispatchEventAt := strings.Index(dispatchBlock, `document.body.dispatchEvent`)
	if hiddenGuardAt < 0 || dispatchEventAt < 0 || hiddenGuardAt > dispatchEventAt {
		t.Fatalf("auto-refresh dispatch must check active state before dispatching:\n%s", dispatchBlock)
	}

	activeAt := strings.Index(script, `function isAutoRefreshActive()`)
	if activeAt < 0 {
		t.Fatalf("auto-refresh.js missing isAutoRefreshActive:\n%s", script)
	}
	activeEnd := strings.Index(script[activeAt:], `function startAutoRefreshTimer()`)
	if activeEnd < 0 {
		t.Fatalf("auto-refresh.js isAutoRefreshActive should be followed by startAutoRefreshTimer:\n%s", script[activeAt:])
	}
	activeBlock := script[activeAt : activeAt+activeEnd]
	for _, want := range []string{`!paused`, `!isDocumentHidden()`} {
		if !strings.Contains(activeBlock, want) {
			t.Fatalf("auto-refresh active state missing %q:\n%s", want, activeBlock)
		}
	}
}

func TestAutoRefreshTimerSkipsBusyFocusedOrExpandedControlledTargets(t *testing.T) {
	t.Parallel()

	script := readTextFile(t, "static", "auto-refresh.js")
	for _, want := range []string{
		`var controlledTarget = autoRefreshControlledTarget(toggle);`,
		`function autoRefreshControlledTarget(toggle)`,
		`toggle.getAttribute("aria-controls")`,
		`document.getElementById`,
		`function autoRefreshTargetHasFocus(target)`,
		`target.contains(document.activeElement)`,
		`function autoRefreshTargetHasOpenDetails(target)`,
		`target.querySelector("details[open]")`,
		`function autoRefreshTargetIsBusy(target)`,
		`target.getAttribute("aria-busy") === "true"`,
		`function canDispatchAutoRefresh()`,
		`function dispatchManualAutoRefresh()`,
		`refreshNow.addEventListener("click", dispatchManualAutoRefresh);`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("auto-refresh.js missing controlled-target focus/details guard marker %q:\n%s", want, script)
		}
	}

	dispatchAt := strings.Index(script, `function dispatchAutoRefresh()`)
	if dispatchAt < 0 {
		t.Fatalf("auto-refresh.js missing dispatchAutoRefresh:\n%s", script)
	}
	dispatchEnd := strings.Index(script[dispatchAt:], `function isAutoRefreshActive()`)
	if dispatchEnd < 0 {
		t.Fatalf("auto-refresh.js dispatchAutoRefresh should be followed by isAutoRefreshActive:\n%s", script[dispatchAt:])
	}
	dispatchBlock := script[dispatchAt : dispatchAt+dispatchEnd]
	guardAt := strings.Index(dispatchBlock, `canDispatchAutoRefresh()`)
	dispatchEventAt := strings.Index(dispatchBlock, `document.body.dispatchEvent`)
	if guardAt < 0 || dispatchEventAt < 0 || guardAt > dispatchEventAt {
		t.Fatalf("timer auto-refresh dispatch must check controlled target busy/focus/details before dispatching:\n%s", dispatchBlock)
	}

	canDispatchAt := strings.Index(script, `function canDispatchAutoRefresh()`)
	if canDispatchAt < 0 {
		t.Fatalf("auto-refresh.js missing canDispatchAutoRefresh:\n%s", script)
	}
	canDispatchEnd := strings.Index(script[canDispatchAt:], `function dispatchAutoRefresh()`)
	if canDispatchEnd < 0 {
		t.Fatalf("auto-refresh.js canDispatchAutoRefresh should be followed by dispatchAutoRefresh:\n%s", script[canDispatchAt:])
	}
	canDispatchBlock := script[canDispatchAt : canDispatchAt+canDispatchEnd]
	for _, want := range []string{
		`!autoRefreshTargetIsBusy(controlledTarget)`,
		`!autoRefreshTargetHasFocus(controlledTarget)`,
		`!autoRefreshTargetHasOpenDetails(controlledTarget)`,
	} {
		if !strings.Contains(canDispatchBlock, want) {
			t.Fatalf("timer auto-refresh guard missing %q:\n%s", want, canDispatchBlock)
		}
	}

	manualAt := strings.Index(script, `function dispatchManualAutoRefresh()`)
	if manualAt < 0 {
		t.Fatalf("auto-refresh.js missing manual dispatch:\n%s", script)
	}
	manualEnd := strings.Index(script[manualAt:], `function isAutoRefreshActive()`)
	if manualEnd < 0 {
		t.Fatalf("auto-refresh.js manual dispatch should be followed by isAutoRefreshActive:\n%s", script[manualAt:])
	}
	manualBlock := script[manualAt : manualAt+manualEnd]
	for _, blocked := range []string{`canDispatchAutoRefresh()`, `autoRefreshTargetIsBusy`} {
		if strings.Contains(manualBlock, blocked) {
			t.Fatalf("manual refresh should not be blocked by timer-only guard %q:\n%s", blocked, manualBlock)
		}
	}
}

func TestAutoRefreshToggleUsesStablePressedState(t *testing.T) {
	t.Parallel()

	for _, page := range []struct {
		name       string
		path       []string
		controlsID string
		statusID   string
	}{
		{
			name:       "public feeds",
			path:       []string{"templates", "feeds.html"},
			controlsID: "feed-status-container",
			statusID:   "feed-status-refresh-state",
		},
		{
			name:       "admin feeds",
			path:       []string{"templates", "admin", "feeds.html"},
			controlsID: "admin-feed-runtime",
			statusID:   "admin-feed-runtime-refresh-state",
		},
	} {
		t.Run(page.name, func(t *testing.T) {
			t.Parallel()

			body := readTextFile(t, page.path...)
			buttonTag := openingTagContaining(t, body, `data-auto-refresh-toggle`)
			for _, want := range []string{
				`aria-controls="` + page.controlsID + `"`,
				`aria-describedby="` + page.statusID + `"`,
				`aria-pressed="true"`,
				`inline-flex`,
				`min-h-11`,
				`items-center`,
				`justify-center`,
			} {
				if !strings.Contains(buttonTag, want) {
					t.Fatalf("%s auto-refresh toggle missing %q:\n%s", page.name, want, buttonTag)
				}
			}
			if !strings.Contains(body, `>Auto-refresh</button>`) &&
				!strings.Contains(body, `>{{t "feeds.refresh.auto_label"}}</button>`) &&
				!strings.Contains(body, `>{{t "admin.feeds.runtime.refresh_label"}}</button>`) {
				t.Fatalf("%s auto-refresh toggle should use a stable visible label:\n%s", page.name, body)
			}
			for _, actionLabel := range []string{">Pause auto-refresh</button>", ">Resume auto-refresh</button>"} {
				if strings.Contains(body, actionLabel) {
					t.Fatalf("%s auto-refresh toggle still uses action label %q:\n%s", page.name, actionLabel, body)
				}
			}
		})
	}

	script := readTextFile(t, "static", "auto-refresh.js")
	for _, want := range []string{
		`var toggleLabel = control.dataset.autoRefreshLabel || toggle.textContent || "";`,
		`toggle.setAttribute("aria-pressed", paused ? "false" : "true");`,
		`toggle.textContent = toggleLabel;`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("auto-refresh.js missing stable toggle state behavior %q:\n%s", want, script)
		}
	}
	for _, actionLabel := range []string{`Pause auto-refresh`, `Resume auto-refresh`} {
		if strings.Contains(script, actionLabel) {
			t.Fatalf("auto-refresh.js still switches action label %q:\n%s", actionLabel, script)
		}
	}
	for _, blocked := range []string{
		`data-feed-sync-now`,
		`data-preserve-scroll`,
		`data-required-when-checked`,
		`data-copy-target`,
		`htmx:beforeRequest`,
	} {
		if strings.Contains(script, blocked) {
			t.Fatalf("auto-refresh.js still owns unrelated behavior hook %q:\n%s", blocked, script)
		}
	}
}

func TestStaticJavaScriptStateLabelsComeFromTemplateData(t *testing.T) {
	t.Parallel()

	for scriptName, script := range map[string]string{
		"auto-refresh.js": readTextFile(t, "static", "auto-refresh.js"),
		"form-actions.js": readTextFile(t, "static", "form-actions.js"),
		"htmx-regions.js": readTextFile(t, "static", "htmx-regions.js"),
	} {
		for _, blocked := range []string{`Resume auto-refresh`, `Pause auto-refresh`, `Sync now`, `Syncing...`, `button.textContent = "Retry";`} {
			if strings.Contains(script, blocked) {
				t.Fatalf("%s still hardcodes visible state label %q:\n%s", scriptName, blocked, script)
			}
		}
	}

	for _, tt := range []struct {
		name string
		path []string
	}{
		{name: "public feeds", path: []string{"templates", "feeds.html"}},
		{name: "admin feeds", path: []string{"templates", "admin", "feeds.html"}},
		{name: "search", path: []string{"templates", "search.html"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			body := readTextFile(t, tt.path...)
			target := openingTagContaining(t, body, `data-htmx-status-target=`)
			for _, want := range []string{
				`data-htmx-error-message=`,
				`data-htmx-timeout-message=`,
				`data-htmx-swap-error-message=`,
				`data-htmx-stale-message=`,
				`data-htmx-retry-label=`,
			} {
				if !strings.Contains(target, want) {
					t.Fatalf("%s htmx target missing template-provided message %q:\n%s", tt.name, want, target)
				}
			}
		})
	}
}

func TestFeedStatusRefreshControlsExposeRefreshNowAction(t *testing.T) {
	t.Parallel()

	for _, page := range []struct {
		name  string
		path  []string
		label string
	}{
		{name: "public feeds", path: []string{"templates", "feeds.html"}, label: `{{t "feeds.refresh.now_aria"}}`},
		{name: "admin feeds", path: []string{"templates", "admin", "feeds.html"}, label: `{{t "admin.feeds.runtime.refresh_now_aria"}}`},
	} {
		t.Run(page.name, func(t *testing.T) {
			t.Parallel()

			body := readTextFile(t, page.path...)
			button := openingTagContaining(t, body, `data-auto-refresh-now`)
			for _, want := range []string{
				`type="button"`,
				`aria-controls=`,
				`aria-label="` + page.label + `"`,
				`inline-flex`,
				`min-h-11`,
			} {
				if !strings.Contains(button, want) {
					t.Fatalf("%s refresh-now button missing %q:\n%s", page.name, want, button)
				}
			}
		})
	}

	script := readTextFile(t, "static", "auto-refresh.js")
	for _, want := range []string{
		`var refreshNow = control.querySelector("[data-auto-refresh-now]");`,
		`refreshNow.addEventListener("click", dispatchManualAutoRefresh);`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("auto-refresh.js missing refresh-now behavior %q:\n%s", want, script)
		}
	}
}

func TestAutoRefreshToggleExposesVisualRunningAndPausedState(t *testing.T) {
	t.Parallel()

	for _, page := range []struct {
		name string
		path []string
	}{
		{name: "public feeds", path: []string{"templates", "feeds.html"}},
		{name: "admin feeds", path: []string{"templates", "admin", "feeds.html"}},
	} {
		t.Run(page.name, func(t *testing.T) {
			t.Parallel()

			body := readTextFile(t, page.path...)
			control := openingTagContaining(t, body, `data-auto-refresh-control`)
			for _, want := range []string{
				`data-auto-refresh-running-class=`,
				`data-auto-refresh-paused-class=`,
			} {
				if !strings.Contains(control, want) {
					t.Fatalf("%s auto-refresh control missing visual state class config %q:\n%s", page.name, want, control)
				}
			}

			button := openingTagContaining(t, body, `data-auto-refresh-toggle`)
			if !strings.Contains(button, `class="inline-flex`) {
				t.Fatalf("%s auto-refresh toggle missing styled button class:\n%s", page.name, button)
			}
		})
	}

	script := readTextFile(t, "static", "auto-refresh.js")
	for _, want := range []string{
		`var runningClasses = splitClassList(control.dataset.autoRefreshRunningClass);`,
		`var pausedClasses = splitClassList(control.dataset.autoRefreshPausedClass);`,
		`setClassList(toggle, runningClasses, !paused);`,
		`setClassList(toggle, pausedClasses, paused);`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("auto-refresh.js missing visual pressed/running state behavior %q:\n%s", want, script)
		}
	}
}

func TestAutoRefreshPausedStatePersistsPerControlWithSafeStorageFallback(t *testing.T) {
	t.Parallel()

	for _, page := range []struct {
		name       string
		path       []string
		storageKey string
	}{
		{name: "public feeds", path: []string{"templates", "feeds.html"}, storageKey: "packmon:auto-refresh:feeds"},
		{name: "admin feeds", path: []string{"templates", "admin", "feeds.html"}, storageKey: "packmon:auto-refresh:admin-feeds"},
	} {
		t.Run(page.name, func(t *testing.T) {
			t.Parallel()

			body := readTextFile(t, page.path...)
			control := openingTagContaining(t, body, `data-auto-refresh-control`)
			if !strings.Contains(control, `data-auto-refresh-storage-key="`+page.storageKey+`"`) {
				t.Fatalf("%s auto-refresh control missing per-control storage key %q:\n%s", page.name, page.storageKey, control)
			}
		})
	}

	script := readTextFile(t, "static", "auto-refresh.js")
	for _, want := range []string{
		`function readStoredAutoRefreshPaused(storageKey)`,
		`function writeStoredAutoRefreshPaused(storageKey, paused)`,
		`window.localStorage.getItem(storageKey)`,
		`window.localStorage.setItem(storageKey, paused ? "true" : "false")`,
		`} catch {`,
		`return false;`,
		`var storageKey = control.dataset.autoRefreshStorageKey || "";`,
		`var paused = readStoredAutoRefreshPaused(storageKey);`,
		`writeStoredAutoRefreshPaused(storageKey, paused);`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("auto-refresh.js missing safe persisted paused-state behavior %q:\n%s", want, script)
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

func allWebTemplateFiles(t *testing.T) []string {
	t.Helper()

	var paths []string
	err := filepath.WalkDir("templates", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".html") {
			return nil
		}
		paths = append(paths, path)
		return nil
	})
	if err != nil {
		t.Fatalf("walk templates: %v", err)
	}
	return paths
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

	script := readTextFile(t, "static", "htmx-regions.js")
	for _, want := range []string{
		`htmx:beforeSwap`,
		`htmx:afterSwap`,
		`data-preserve-scroll`,
		`scrollLeft`,
		`getLogicalScrollLeft`,
		`setLogicalScrollLeft`,
		`getComputedStyle(scroller).direction`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("htmx-regions.js missing scroll-preservation behavior %q", want)
		}
	}
}

func TestHTMXInteractionsExposeBoundedTimeoutIndicatorsAndScopedTransitions(t *testing.T) {
	t.Parallel()

	layout := readTextFile(t, "templates", "layout.html")
	for _, want := range []string{
		`"timeout":10000`,
		`"defaultSettleDelay":80`,
	} {
		if !strings.Contains(layout, want) {
			t.Fatalf("layout htmx config missing bounded interaction marker %q:\n%s", want, layout)
		}
	}

	styleCSS := readTextFile(t, "static", "style.css")
	for _, want := range []string{
		`[data-htmx-transition].htmx-swapping`,
		`[data-htmx-transition].htmx-settling`,
		`.htmx-indicator`,
		`.htmx-request .htmx-indicator`,
	} {
		if !strings.Contains(styleCSS, want) {
			t.Fatalf("style.css missing scoped htmx interaction marker %q:\n%s", want, styleCSS)
		}
	}
	if strings.Contains(styleCSS, "\n.htmx-swapping") || strings.Contains(styleCSS, "\n.htmx-settling") {
		t.Fatalf("style.css still applies global htmx transition classes:\n%s", styleCSS)
	}

	script := readTextFile(t, "static", "htmx-regions.js")
	for _, want := range []string{
		`document.body.addEventListener("htmx:timeout"`,
		`document.body.addEventListener("htmx:sendError"`,
		`target.dataset.htmxTimeoutMessage`,
		`target.dataset.htmxErrorMessage`,
		`target.dataset.htmxStatusTarget`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("htmx-regions.js missing htmx timeout/error fallback marker %q:\n%s", want, script)
		}
	}
}

func TestHTMXFailuresRenderDurableTargetErrorState(t *testing.T) {
	t.Parallel()

	script := readTextFile(t, "static", "htmx-regions.js")
	for _, want := range []string{
		`function showHTMXErrorState(target, message, retrySource)`,
		`data-htmx-error-state`,
		`panel.setAttribute("role", "alert");`,
		`panel.setAttribute("aria-live", "assertive");`,
		`target.dataset.htmxRetryLabel`,
		`triggerHTMXRetry(target, retrySource);`,
		`trigger.split(",").some(function (triggerPart)`,
		`triggerPart.indexOf("changed") === -1`,
		`document.body.addEventListener("htmx:responseError"`,
		`document.body.addEventListener("htmx:sendError"`,
		`document.body.addEventListener("htmx:timeout"`,
		`document.body.addEventListener("htmx:timeoutError"`,
		`document.body.addEventListener("htmx:swapError"`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("htmx-regions.js missing durable htmx target error state marker %q:\n%s", want, script)
		}
	}
}

func TestHTMXLiveRegionsUseVisibleIndicators(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		path  []string
		wants []string
	}{
		{
			name: "public feeds",
			path: []string{"templates", "feeds.html"},
			wants: []string{
				`id="feed-status-indicator"`,
				`role="status"`,
				`aria-live="polite"`,
				`hx-indicator="#feed-status-indicator"`,
				`data-htmx-status-target="#feed-status-refresh-state"`,
				`hx-swap="innerHTML transition:true settle:80ms"`,
				`data-htmx-transition`,
			},
		},
		{
			name: "admin feeds",
			path: []string{"templates", "admin", "feeds.html"},
			wants: []string{
				`id="admin-feed-runtime-indicator"`,
				`role="status"`,
				`aria-live="polite"`,
				`hx-indicator="#admin-feed-runtime-indicator"`,
				`data-htmx-status-target="#admin-feed-runtime-refresh-state"`,
				`hx-swap="innerHTML transition:true settle:80ms"`,
				`data-htmx-transition`,
			},
		},
		{
			name: "search",
			path: []string{"templates", "search.html"},
			wants: []string{
				`id="search-results-indicator"`,
				`role="status"`,
				`aria-live="polite"`,
				`hx-indicator="#search-results-indicator"`,
				`data-htmx-status-target="#search-status-visible"`,
				`hx-swap="innerHTML transition:true settle:80ms"`,
				`data-htmx-transition`,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			body := readTextFile(t, tt.path...)
			for _, want := range tt.wants {
				if !strings.Contains(body, want) {
					t.Fatalf("%s missing visible htmx indicator/transition marker %q:\n%s", strings.Join(tt.path, string(os.PathSeparator)), want, body)
				}
			}
		})
	}
}

func TestSearchLiveSearchDoesNotAnnounceDebouncedResultCounts(t *testing.T) {
	t.Parallel()

	search := readTextFile(t, "templates", "search.html")
	visibleStatusTag := openingTagContaining(t, search, `id="search-status-visible"`)
	for _, blocked := range []string{`role="status"`, `role="alert"`, `aria-live="polite"`, `aria-live="assertive"`} {
		if strings.Contains(visibleStatusTag, blocked) {
			t.Fatalf("search visible status should not announce every debounced refresh, found %q in:\n%s", blocked, visibleStatusTag)
		}
	}
	if !strings.Contains(visibleStatusTag, `aria-live="off"`) {
		t.Fatalf("search visible status should explicitly opt out of live announcements:\n%s", visibleStatusTag)
	}

	searchStatusTag := openingTagContaining(t, search, `id="search-status"`)
	for _, blocked := range []string{`role="status"`, `aria-live="polite"`} {
		if strings.Contains(searchStatusTag, blocked) {
			t.Fatalf("search result-count status should not be a polite live region during live search, found %q in:\n%s", blocked, searchStatusTag)
		}
	}
	for _, want := range []string{`role="alert"`, `aria-live="assertive"`, `aria-atomic="true"`} {
		if !strings.Contains(searchStatusTag, want) {
			t.Fatalf("search error status should remain assertive, missing %q in:\n%s", want, searchStatusTag)
		}
	}

	searchResultsTag := openingTagContaining(t, search, `id="search-results"`)
	if !strings.Contains(searchResultsTag, `data-htmx-success-message=""`) {
		t.Fatalf("search results target should clear visual status without announcing result counts:\n%s", searchResultsTag)
	}
}

func TestSearchResultsPreserveHorizontalScrollAcrossHTMXRefresh(t *testing.T) {
	t.Parallel()

	body := readTextFile(t, "templates", "search.html")
	for _, want := range []string{
		`id="search-results"`,
		`data-preserve-scroll-container`,
		`data-preserve-scroll="search-results-table"`,
		`hx-target="#search-results"`,
		`hx-swap="innerHTML transition:true settle:80ms"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("search.html missing scroll-preservation marker %q:\n%s", want, body)
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

func renderDashboardTemplateForStaticTest(t *testing.T, name string) string {
	t.Helper()

	data := map[string]any{
		"ActiveNav":           "dashboard",
		"CSRFToken":           "csrf-token",
		"TotalScans7d":        7,
		"FeedStatusLoadError": "feed status unavailable",
		"QueueStatsLoadError": "queue unavailable",
		"Stats": map[string]any{
			"TotalPackages":        12,
			"TotalVulnerabilities": 3,
			"TotalMalicious":       2,
			"TotalSupplyChainRisk": 4,
			"TotalLifecycle":       5,
			"BySeverity": map[string]int{
				"CRITICAL": 1,
				"HIGH":     1,
				"MEDIUM":   1,
				"LOW":      1,
			},
		},
	}

	var out strings.Builder
	if err := testRenderer().Render(&out, name, data); err != nil {
		t.Fatalf("Render(%s) error = %v", name, err)
	}
	return out.String()
}
