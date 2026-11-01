package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/8linkz-sec/packmon/internal/domain"
	"github.com/8linkz-sec/packmon/internal/scanner"
)

// TestRunOutdatedHTMLCarriesParseErrorWarningWithFileNamesOnly keeps a
// partially parsed inventory visible in the HTML artifact itself, not only on
// stderr: the report names the failed files by file name and never leaks the
// scan root or the relative directory layout.
func TestRunOutdatedHTMLCarriesParseErrorWarningWithFileNamesOnly(t *testing.T) {
	for _, quiet := range []bool{false, true} {
		t.Run(fmt.Sprintf("quiet=%v", quiet), func(t *testing.T) {
			dir := writeOutdatedPartialParseFixture(t)
			htmlPath := filepath.Join(t.TempDir(), "outdated.html")
			resolver := packageUpdateResolver{
				fetchLatest: func(context.Context, domain.Ecosystem, string) string { return "2.0.0" },
			}

			var err error
			captureStdout(t, func() {
				_ = captureScanStderr(t, func() {
					err = runOutdatedWithOptions([]string{dir}, outdatedOptions{
						Context:    context.Background(),
						Ecosystems: "npm",
						MaxDepth:   3,
						IncludeDev: true,
						OutputHTML: htmlPath,
						Quiet:      quiet,
						resolver:   resolver,
						Timeout:    5,
					})
				})
			})
			if code := exitCodeForError(err); code != ExitParser {
				t.Fatalf("runOutdatedWithOptions error = %v (exit %d), want parser exit %d", err, code, ExitParser)
			}
			data, readErr := os.ReadFile(htmlPath) // #nosec G304 -- test reads a generated temp-file path.
			if readErr != nil {
				t.Fatalf("read HTML: %v", readErr)
			}
			out := string(data)

			const block = `<div class="warning"><bdi dir="auto">Inventory incomplete: 1 file could not be parsed: package-lock.json</bdi></div>`
			if !strings.Contains(out, block) {
				t.Fatalf("outdated HTML missing parse-error warning block %q:\n%s", block, out)
			}
			// The block sits at the top, after the summary badges and before
			// the outdated package listing.
			summary := strings.Index(out, `<div class="summary">`)
			warning := strings.Index(out, block)
			legend := strings.Index(out, `<div id="outdated-provenance-legend"`)
			if summary < 0 || legend < 0 || summary >= warning || warning >= legend {
				t.Fatalf("warning block position summary=%d warning=%d legend=%d, want summary < warning < legend", summary, warning, legend)
			}
			if !strings.Contains(out, cliHTMLReportWarningCSS) {
				t.Fatalf("outdated HTML missing the shared .warning style:\n%s", out)
			}
			for _, leak := range []string{
				dir,
				filepath.ToSlash(dir),
				"broken/package-lock.json",
				`broken\package-lock.json`,
			} {
				if strings.Contains(out, leak) {
					t.Fatalf("outdated HTML leaks path %q:\n%s", leak, out)
				}
			}
		})
	}
}

func TestOutdatedInventoryWarningUsesSanitizedFileNamesOnly(t *testing.T) {
	t.Parallel()

	got := outdatedInventoryWarning(&scanner.PackageCollection{ParseErrors: []string{
		"/home/alice/secret-project/package-lock.json: unexpected end of JSON input",
		`C:\Users\alice\secret-project\go.sum: malformed line 3`,
		"nested/dir/bom.cdx.json: skipped SBOM component #1: missing purl",
		"nested/dir/bom.cdx.json: skipped SBOM component #2: invalid package name",
		"evil\x1b[31m.lock: bad",
		"  ",
	}})
	want := `Inventory incomplete: 4 files could not be parsed: package-lock.json, go.sum, bom.cdx.json, evil\x1B[31m.lock`
	if got != want {
		t.Fatalf("outdatedInventoryWarning = %q, want %q", got, want)
	}
	for _, leak := range []string{"alice", "secret-project", "nested", "unexpected end", "malformed", "missing purl"} {
		if strings.Contains(got, leak) {
			t.Fatalf("inventory warning leaks %q: %q", leak, got)
		}
	}

	if got := outdatedInventoryWarning(&scanner.PackageCollection{}); got != "" {
		t.Fatalf("outdatedInventoryWarning(no parse errors) = %q, want empty", got)
	}
	if got := outdatedInventoryWarning(nil); got != "" {
		t.Fatalf("outdatedInventoryWarning(nil) = %q, want empty", got)
	}
}

func TestOutdatedInventoryWarningBoundsTheFileNameList(t *testing.T) {
	t.Parallel()

	parseErrors := make([]string, 0, scanner.MaxUserFacingParseDiagnostics+3)
	for i := range scanner.MaxUserFacingParseDiagnostics + 3 {
		parseErrors = append(parseErrors, fmt.Sprintf("dir%d/package-lock.json: bad", i))
	}
	got := outdatedInventoryWarning(&scanner.PackageCollection{ParseErrors: parseErrors})
	wantPrefix := fmt.Sprintf("Inventory incomplete: %d files could not be parsed: ", scanner.MaxUserFacingParseDiagnostics+3)
	if !strings.HasPrefix(got, wantPrefix) {
		t.Fatalf("outdatedInventoryWarning = %q, want prefix %q", got, wantPrefix)
	}
	if !strings.HasSuffix(got, ", and 3 more") {
		t.Fatalf("outdatedInventoryWarning = %q, want the omitted-name suffix", got)
	}
	if n := strings.Count(got, "package-lock.json"); n != scanner.MaxUserFacingParseDiagnostics {
		t.Fatalf("outdatedInventoryWarning lists %d names, want %d", n, scanner.MaxUserFacingParseDiagnostics)
	}
}

func TestOutdatedHTMLCapsWarningsLikeListAll(t *testing.T) {
	t.Parallel()

	warnings := make([]string, 0, maxHTMLReportWarnings+2)
	for i := range maxHTMLReportWarnings + 2 {
		warnings = append(warnings, fmt.Sprintf("warning %d", i+1))
	}
	htmlPath := filepath.Join(t.TempDir(), "outdated.html")
	if err := writeOutdatedHTML(htmlPath, outdatedReport{Total: 1, UpToDate: 1, PackageWord: "package", Warnings: warnings}); err != nil {
		t.Fatalf("writeOutdatedHTML: %v", err)
	}
	data, err := os.ReadFile(htmlPath) // #nosec G304 -- test reads generated report.
	if err != nil {
		t.Fatalf("read HTML: %v", err)
	}
	out := string(data)

	if got := strings.Count(out, `<div class="warning">`); got != maxHTMLReportWarnings+1 {
		t.Fatalf("outdated HTML renders %d warning lines, want %d visible plus the omitted line:\n%s", got, maxHTMLReportWarnings+1, out)
	}
	for i := 1; i <= maxHTMLReportWarnings; i++ {
		if !strings.Contains(out, fmt.Sprintf(`<div class="warning"><bdi dir="auto">warning %d</bdi></div>`, i)) {
			t.Fatalf("outdated HTML missing visible warning %d:\n%s", i, out)
		}
	}
	if strings.Contains(out, fmt.Sprintf("warning %d<", maxHTMLReportWarnings+1)) {
		t.Fatalf("outdated HTML renders a warning beyond the cap:\n%s", out)
	}
	if !strings.Contains(out, `<div class="warning"><bdi dir="auto">2 additional warnings were omitted from the top of this report.</bdi></div>`) {
		t.Fatalf("outdated HTML missing the omitted-warnings line:\n%s", out)
	}
}

func TestOutdatedHTMLWithoutWarningsHasNoWarningBlock(t *testing.T) {
	t.Parallel()

	htmlPath := filepath.Join(t.TempDir(), "outdated.html")
	if err := writeOutdatedHTML(htmlPath, outdatedReport{Total: 1, UpToDate: 1, PackageWord: "package"}); err != nil {
		t.Fatalf("writeOutdatedHTML: %v", err)
	}
	data, err := os.ReadFile(htmlPath) // #nosec G304 -- test reads generated report.
	if err != nil {
		t.Fatalf("read HTML: %v", err)
	}
	if out := string(data); strings.Contains(out, `class="warning"`) {
		t.Fatalf("outdated HTML without warnings renders a warning block:\n%s", out)
	}
}

func TestRunOutdatedHTMLWithoutParseErrorsHasNoWarningBlock(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "package-lock.json"), `{
		"lockfileVersion": 3,
		"packages": {
			"": {"version": "1.0.0"},
			"node_modules/outdated": {"version": "1.0.0"}
		}
	}`)
	htmlPath := filepath.Join(t.TempDir(), "outdated.html")
	var err error
	captureStdout(t, func() {
		_ = captureScanStderr(t, func() {
			err = runOutdatedWithOptions([]string{dir}, outdatedOptions{
				Context:    context.Background(),
				Ecosystems: "npm",
				MaxDepth:   2,
				IncludeDev: true,
				OutputHTML: htmlPath,
				resolver: packageUpdateResolver{
					fetchLatest: func(context.Context, domain.Ecosystem, string) string { return "2.0.0" },
				},
				Timeout: 5,
			})
		})
	})
	if err != nil {
		t.Fatalf("runOutdatedWithOptions: %v", err)
	}
	data, readErr := os.ReadFile(htmlPath) // #nosec G304 -- test reads a generated temp-file path.
	if readErr != nil {
		t.Fatalf("read HTML: %v", readErr)
	}
	if out := string(data); strings.Contains(out, `class="warning"`) {
		t.Fatalf("clean outdated run renders a warning block:\n%s", out)
	}
}

// TestOutdatedLookupPhaseReportWarningsMatchListAll keeps the lookup warnings
// in the outdated HTML report worded exactly like the list-all report's.
func TestOutdatedLookupPhaseReportWarningsMatchListAll(t *testing.T) {
	t.Parallel()

	_, phase := withRegistryLookupPhase(context.Background(), 0)
	phase.recordRefusal()
	phase.recordOversized()
	for range registryBreakerThreshold {
		phase.recordRefusal()
	}
	phase.recordSkipped()

	listAll := listAllPackageReport{}
	appendLookupPhaseWarnings(&listAll, phase, false)
	got := outdatedLookupPhaseReportWarnings(phase, false)
	if len(got) != 3 {
		t.Fatalf("outdated lookup warnings = %#v, want refused, oversized and breaker warnings", got)
	}
	if !reflect.DeepEqual(got, listAll.Warnings) {
		t.Fatalf("outdated lookup warnings = %#v, want the list-all wording %#v", got, listAll.Warnings)
	}

	if got := outdatedLookupPhaseReportWarnings(phase, true); len(got) != 0 {
		t.Fatalf("canceled lookup phase warnings = %#v, want none", got)
	}
	_, clean := withRegistryLookupPhase(context.Background(), 0)
	if got := outdatedLookupPhaseReportWarnings(clean, false); len(got) != 0 {
		t.Fatalf("clean lookup phase warnings = %#v, want none", got)
	}
}

func TestOutdatedReportWarningsPutTheParseErrorLineFirst(t *testing.T) {
	t.Parallel()

	got := outdatedReportWarnings(
		&scanner.PackageCollection{ParseErrors: []string{"a/package-lock.json: bad"}},
		[]string{"lookup warning"},
	)
	want := []string{"Inventory incomplete: 1 file could not be parsed: package-lock.json", "lookup warning"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("outdatedReportWarnings = %#v, want %#v", got, want)
	}
	if got := outdatedReportWarnings(&scanner.PackageCollection{}, nil); len(got) != 0 {
		t.Fatalf("outdatedReportWarnings(clean) = %#v, want none", got)
	}
}
