package web

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestFeedTemplatesUseSharedStatusPartials(t *testing.T) {
	t.Parallel()

	partial := readTextFile(t, "templates", "partials", "feed_status.html")
	for _, want := range []string{
		`{{define "feed-status-badge"}}`,
		`{{define "feed-last-sync-cell"}}`,
		`{{define "feed-error-details"}}`,
	} {
		if !strings.Contains(partial, want) {
			t.Fatalf("feed status partial missing definition %q:\n%s", want, partial)
		}
	}

	for _, tc := range []struct {
		name string
		path []string
	}{
		{name: "public feeds", path: []string{"templates", "feeds.html"}},
		{name: "admin dashboard", path: []string{"templates", "admin", "dashboard.html"}},
		{name: "admin feeds", path: []string{"templates", "admin", "feeds.html"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			body := readTextFile(t, tc.path...)
			for _, want := range []string{
				`{{template "feed-status-badge" .}}`,
				`{{template "feed-last-sync-cell" .}}`,
				`{{template "feed-error-details"`,
			} {
				if !strings.Contains(body, want) {
					t.Fatalf("%s missing shared feed status partial call %q:\n%s", filepath.Join(tc.path...), want, body)
				}
			}
		})
	}
}

func TestFeedStatusHelperMarkupOnlyLivesInFeedStatusPartial(t *testing.T) {
	t.Parallel()

	partialPath := filepath.Join("templates", "partials", "feed_status.html")
	partial := readTextFile(t, partialPath)
	markers := []string{
		"statusClass " + ".Status",
		"Show full feed " + "error",
		"formatTimeAgo " + ".LastSyncAtTime",
	}
	for _, marker := range markers {
		if !strings.Contains(partial, marker) {
			t.Fatalf("%s missing shared marker %q:\n%s", partialPath, marker, partial)
		}
	}

	for _, path := range [][]string{
		{"templates", "feeds.html"},
		{"templates", "admin", "dashboard.html"},
		{"templates", "admin", "feeds.html"},
	} {
		body := readTextFile(t, path...)
		for _, marker := range markers {
			if strings.Contains(body, marker) {
				t.Fatalf("%s still implements shared feed status marker %q outside %s", filepath.Join(path...), marker, partialPath)
			}
		}
	}
}

func TestAdminFeedRuntimeUsesResponsiveScannableLayouts(t *testing.T) {
	t.Parallel()

	body := readTextFile(t, "templates", "admin", "feeds.html")
	runtimeStart := strings.Index(body, `{{define "admin-feed-runtime"}}`)
	runtimeEnd := strings.Index(body, `{{define "content"}}`)
	if runtimeStart < 0 || runtimeEnd < 0 || runtimeEnd <= runtimeStart {
		t.Fatalf("admin feed runtime template block not found:\n%s", body)
	}
	runtime := body[runtimeStart:runtimeEnd]

	if !strings.Contains(runtime, `data-admin-mobile-layout="feed-runtime"`) ||
		!strings.Contains(runtime, `class="divide-y divide-border md:hidden"`) {
		t.Fatalf("admin feed runtime missing mobile card layout marker:\n%s", runtime)
	}

	desktop := openingTagContaining(t, runtime, `data-admin-desktop-table="feed-runtime"`)
	for _, want := range []string{
		`hidden`,
		`md:block`,
		`role="region"`,
		`aria-label="{{t "admin.feeds.runtime.table_aria"}}"`,
		`data-preserve-scroll="admin-feed-runtime-table"`,
	} {
		if !strings.Contains(desktop, want) {
			t.Fatalf("admin feed runtime desktop table wrapper missing %q:\n%s", want, desktop)
		}
	}

	if got := strings.Count(runtime, `<th scope="col"`); got != 6 {
		t.Fatalf("admin feed runtime table should expose 6 prioritized desktop columns, got %d:\n%s", got, runtime)
	}
	for _, oldHeader := range []string{
		`<th class="px-5 py-2">Mode</th>`,
		`<th class="px-5 py-2">Self-sync cadence</th>`,
		`<th class="px-5 py-2">API Key</th>`,
		`<th class="px-5 py-2">Last Result</th>`,
		`<th class="px-5 py-2">Duration</th>`,
		`<th class="px-5 py-2 text-end">Synced</th>`,
		`<th class="px-5 py-2 text-end">Total</th>`,
		`<th class="px-5 py-2 text-center">Error</th>`,
	} {
		if strings.Contains(runtime, oldHeader) {
			t.Fatalf("admin feed runtime still has equal-priority header %q:\n%s", oldHeader, runtime)
		}
	}
}

func TestAdminFeedTemplateUsesSemanticBadgeViewModels(t *testing.T) {
	t.Parallel()

	body := readTextFile(t, "templates", "admin", "feeds.html")
	for _, forbidden := range []string{
		"bg-surface-2 text-fg px-2 py-0.5 rounded",
		"bg-surface-2 text-muted px-2 py-0.5 rounded",
		"bg-success-bg text-success-fg px-2 py-0.5 rounded",
		"bg-warning-bg text-yellow-800 px-2 py-0.5 rounded",
		"bg-info-bg text-accent px-2 py-0.5 rounded",
	} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("admin feeds template still hardcodes badge color bundle %q", forbidden)
		}
	}
	for _, want := range []string{
		".ConfigModeClass",
		".ConfigEnabledClass",
		".SyncIntervalClass",
		".LastSyncStatusClass",
		".APIKeyStateClass",
		".OverrideClass",
		".RuntimeMatchClass",
		".UpdatedAtClass",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("admin feeds template missing semantic badge marker %q", want)
		}
	}
}
