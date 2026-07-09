package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSelectLatestNuGetVersion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		versions []string
		want     string
	}{
		{
			name:     "empty",
			versions: nil,
			want:     "",
		},
		{
			name:     "unsorted stable versions",
			versions: []string{"1.2.0", "1.10.0", "1.3.0"},
			want:     "1.10.0",
		},
		{
			name:     "release wins over prerelease",
			versions: []string{"2.0.0-rc1", "1.9.9", "2.0.0"},
			want:     "2.0.0",
		},
		{
			name:     "highest can appear first",
			versions: []string{"3.1.0", "2.9.0", "3.0.5"},
			want:     "3.1.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := selectLatestNuGetVersion(tt.versions)
			if got != tt.want {
				t.Fatalf("selectLatestNuGetVersion(%v) = %q, want %q", tt.versions, got, tt.want)
			}
		})
	}
}

func TestOutdatedHTMLUsesReportTypeAndSpacingScales(t *testing.T) {
	htmlPath := filepath.Join(t.TempDir(), "outdated.html")
	report := outdatedReport{
		Total:       1,
		PackageWord: "package",
		Outdated: []outdatedRow{{
			Name:      "github.com/acme/pkg",
			Installed: "1.0.0",
			Latest:    "1.1.0",
			Ecosystem: "go",
			Scope:     "runtime",
			Relation:  "direct",
			LockFile:  "go.sum",
		}},
	}

	if err := writeOutdatedHTML(htmlPath, report); err != nil {
		t.Fatalf("writeOutdatedHTML: %v", err)
	}
	data, err := os.ReadFile(htmlPath) // #nosec G304 -- test reads generated report.
	if err != nil {
		t.Fatalf("read HTML: %v", err)
	}
	out := string(data)

	assertGeneratedReportHTMLDefinesScales(t, out)
	for _, want := range []string{
		`body{margin:0;background:var(--bg);color:var(--fg);font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:var(--report-type-base);`,
		`h1{font-size:var(--report-type-xl);margin:0;color:var(--heading);`,
		`.badge{border:1px solid var(--border);border-radius:var(--report-radius-md);padding:var(--report-space-1) var(--report-space-3);font-size:var(--report-type-sm);`,
		`.provenance-legend{border:1px solid var(--border);border-radius:var(--report-radius-md);background:var(--panel);padding:var(--report-space-3);margin:0 0 var(--report-space-3);color:var(--dim);font-size:var(--report-type-sm);}`,
		`.mobile-primary h2{margin:0;color:var(--heading);font-size:var(--report-type-md);`,
		`.mobile-versions dt,.detail-grid dt{color:var(--dim);font-size:var(--report-type-2xs);text-transform:uppercase;}`,
		`th{color:var(--heading);font-size:var(--report-type-xs);text-transform:uppercase;}`,
		`.empty{margin:var(--report-space-6) 0;padding:var(--report-space-3) var(--report-space-4);background:var(--success-bg);border:1px solid var(--success-border);border-radius:var(--report-radius-md);color:var(--success);font-size:var(--report-type-md);}`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("outdated HTML missing scaled CSS contract %q:\n%s", want, out)
		}
	}
	assertGeneratedReportHTMLAvoidsOffScaleMicroSpacing(t, out)
}

func TestOutdatedHTMLExposesMachineReadableReportTimeAndLanguage(t *testing.T) {
	htmlPath := filepath.Join(t.TempDir(), "outdated.html")
	report := outdatedReport{
		ScannedAt:   "2026-05-30 10:00 UTC",
		Total:       1,
		PackageWord: "package",
		Outdated: []outdatedRow{{
			Name:      "left-pad",
			Installed: "1.1.0",
			Latest:    "1.3.0",
			Ecosystem: "npm",
			Scope:     "runtime",
			Relation:  "direct",
			LockFile:  "package-lock.json",
		}},
	}

	if err := writeOutdatedHTML(htmlPath, report); err != nil {
		t.Fatalf("writeOutdatedHTML: %v", err)
	}
	data, err := os.ReadFile(htmlPath) // #nosec G304 -- test reads generated report.
	if err != nil {
		t.Fatalf("read HTML: %v", err)
	}
	out := string(data)
	for _, want := range []string{
		`<html lang="en" dir="auto">`,
		`<time datetime="2026-05-30T10:00:00Z" data-report-time="scanned-at">2026-05-30 10:00 UTC</time>`,
		`script-src 'unsafe-inline'`,
		`Intl.DateTimeFormat`,
		`Intl.NumberFormat`,
		`querySelectorAll('time[data-report-time][datetime]')`,
		`querySelectorAll('[data-report-duration][data-duration-ms]')`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("outdated HTML timing/language hook missing %q:\n%s", want, out)
		}
	}
}

func TestOutdatedHTMLTemplateUsesMessageDataForStaticReportLabels(t *testing.T) {
	for _, want := range []string{
		`{{.Messages.DocumentTitle}}`,
		`{{.Messages.Heading}}`,
		`{{.Messages.ReportType}}`,
		`{{.Messages.OutdatedLabel}}`,
		`{{.Messages.UpToDateLabel}}`,
		`{{.Messages.UnknownLabel}}`,
		`{{.Messages.ProvenanceHeading}}`,
		`{{$.Messages.ProvenanceSummary}}`,
	} {
		if !strings.Contains(outdatedHTML, want) {
			t.Fatalf("outdated template missing message field %q", want)
		}
	}
	for _, scattered := range []string{
		"<title>Outdated Packages - Packmon Report</title>",
		"<h1>Outdated Packages</h1>",
		"Packmon Outdated Report &middot;",
		"outdated</span>",
		"up to date</span>",
		"unknown</span>",
		"Package provenance.",
		"<summary>Provenance and source</summary>",
	} {
		if strings.Contains(outdatedHTML, scattered) {
			t.Fatalf("outdated template still has scattered label %q", scattered)
		}
	}
}

func TestOutdatedHTMLUsesCompactUpdateFocusedTable(t *testing.T) {
	htmlPath := filepath.Join(t.TempDir(), "outdated.html")
	report := outdatedReport{
		Total:       1,
		PackageWord: "package",
		Outdated: []outdatedRow{{
			Name:      "left-pad",
			Installed: "1.1.0",
			Latest:    "1.3.0",
			Ecosystem: "npm",
			Scope:     "runtime",
			Relation:  "transitive",
			Via:       "webpack, jest",
			Flags:     "optional, peer",
			LockFile:  "package-lock.json",
		}},
	}

	if err := writeOutdatedHTML(htmlPath, report); err != nil {
		t.Fatalf("writeOutdatedHTML: %v", err)
	}
	data, err := os.ReadFile(htmlPath) // #nosec G304 -- test reads generated report.
	if err != nil {
		t.Fatalf("read HTML: %v", err)
	}
	out := string(data)

	for _, want := range []string{
		`<th scope="col" class="name">Package</th><th scope="col" class="version">Installed</th><th scope="col" class="version">Latest</th><th scope="col" class="ecosystem">Ecosystem</th><th scope="col" class="provenance">Provenance</th><th scope="col" class="lockfile">Lockfile</th>`,
		`<td class="provenance"><dl class="table-provenance-list"><div><dt>Scope</dt><dd>runtime</dd></div><div><dt>Relation</dt><dd>transitive</dd></div><div><dt>Via</dt><dd><bdi dir="auto">webpack, jest</bdi></dd></div><div><dt>Flags</dt><dd>optional, peer</dd></div></dl></td>`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("outdated HTML missing compact update table contract %q:\n%s", want, out)
		}
	}

	for _, old := range []string{
		`table{width:100%;min-width:1600px`,
		`<th scope="col" class="short">Scope</th><th scope="col" class="short">Relation</th><th scope="col">Via</th><th scope="col" class="short">Flags</th>`,
		`<td class="short">runtime</td><td class="short">transitive</td><td>webpack, jest</td><td class="short">optional, peer</td>`,
	} {
		if strings.Contains(out, old) {
			t.Fatalf("outdated HTML still renders old wide provenance layout %q:\n%s", old, out)
		}
	}
}
