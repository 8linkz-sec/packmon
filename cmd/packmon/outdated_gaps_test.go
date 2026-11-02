package main

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/8linkz-sec/packmon/internal/domain"
)

func TestCollectOutdatedPackagesHandlesNilCollection(t *testing.T) {
	t.Parallel()

	packages, err := collectOutdatedPackages(nil)
	if err != nil {
		t.Fatalf("collectOutdatedPackages(nil) error = %v", err)
	}
	if packages != nil {
		t.Fatalf("collectOutdatedPackages(nil) = %#v, want nil", packages)
	}
}

func TestRunOutdatedReportsNoPackagesForParsedEmptyInventory(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "package-lock.json"), `{"lockfileVersion":3,"packages":{"":{"version":"1.0.0"}}}`)
	opts := outdatedOptions{
		Context:    context.Background(),
		Ecosystems: "npm",
		MaxDepth:   2,
		IncludeDev: true,
	}

	collection, err := collectOutdatedPackageCollection(dir, opts)
	if err != nil {
		t.Fatalf("collectOutdatedPackageCollection: %v", err)
	}
	if collection.LockFiles != 1 || len(collection.Entries) != 0 || len(collection.ParseErrors) != 0 || len(collection.FatalParseErrors) != 0 {
		t.Fatalf("empty parsed inventory = {LockFiles:%d Entries:%d ParseErrors:%d FatalParseErrors:%d}, want 1/0/0/0",
			collection.LockFiles, len(collection.Entries), len(collection.ParseErrors), len(collection.FatalParseErrors))
	}

	var lookedUp atomic.Bool
	opts.resolver.fetchLatest = func(context.Context, domain.Ecosystem, string) string {
		lookedUp.Store(true)
		return "2.0.0"
	}
	var runErr error
	stderr := captureScanStderr(t, func() {
		output := captureStdout(t, func() {
			runErr = runOutdatedWithOptions([]string{dir}, opts)
		})
		if output != "No packages found.\n" {
			t.Fatalf("outdated output = %q, want exact empty-inventory line", output)
		}
	})
	if runErr != nil {
		t.Fatalf("runOutdatedWithOptions(empty parsed inventory) = %v", runErr)
	}
	if stderr != "" {
		t.Fatalf("outdated stderr = %q, want empty", stderr)
	}
	if lookedUp.Load() {
		t.Fatal("empty parsed inventory performed a latest-version lookup")
	}
}

func TestRunOutdatedPropagatesHTMLOutputOpenFailure(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "package-lock.json"), `{"lockfileVersion":3,"packages":{"":{"version":"1.0.0"},"node_modules/example":{"version":"1.0.0"}}}`)
	outputDirectory := filepath.Join(t.TempDir(), "prepared-output")
	if err := os.Mkdir(outputDirectory, 0o750); err != nil {
		t.Fatalf("create prepared output directory: %v", err)
	}

	var runErr error
	output := captureStdout(t, func() {
		runErr = runOutdatedWithOptions([]string{dir}, outdatedOptions{
			Context:    context.Background(),
			Ecosystems: "npm",
			MaxDepth:   2,
			IncludeDev: true,
			OutputHTML: outputDirectory,
			Quiet:      true,
			resolver: packageUpdateResolver{
				fetchLatest: func(context.Context, domain.Ecosystem, string) string { return "1.0.0" },
			},
		})
	})
	if runErr == nil || exitCodeForError(runErr) != ExitOperational {
		t.Fatalf("runOutdatedWithOptions(unopenable HTML) = %v (exit %d), want operational exit %d", runErr, exitCodeForError(runErr), ExitOperational)
	}
	if !strings.Contains(runErr.Error(), "html: create file "+outputDirectory) {
		t.Fatalf("unopenable HTML error = %q, want create/open context", runErr)
	}
	if strings.Contains(output, "HTML report written to:") {
		t.Fatalf("failed HTML output reported success:\n%s", output)
	}
}

func TestResolveOutdatedStatusesReportsBreakerWarningsUnlessQuietOrCanceled(t *testing.T) {
	packages := make([]outdatedPackage, registryBreakerThreshold+2)
	for i := range packages {
		packages[i] = outdatedPackage{
			Name:      string(rune('a' + i)),
			Version:   "1.0.0",
			Ecosystem: domain.EcosystemNPM,
		}
	}

	wantStderr := "Looking up latest versions for 22 packages (rate-limited, under a minute)...\n" +
		"warning: 20 registry requests were refused or failed; some latest-version data is missing. Rerun the scan, raise --timeout, or route the lookups through a mirror.\n" +
		"warning: 2 lookups were skipped after 20 consecutive registry request failures; check network connectivity and proxy settings.\n"
	wantWarnings := []string{
		"20 registry requests were refused or failed, so some latest-version data is missing and the update status of the affected rows is incomplete. A registry rate limit or a slow registry is the usual cause -- rerun the scan, raise --timeout, or route the lookups through a mirror.",
		"2 lookups were skipped after 20 consecutive registry request failures; latest-version lookups were aborted. Check network connectivity and proxy settings, then rerun the scan.",
	}

	newOptions := func(ctx context.Context, quiet bool) outdatedOptions {
		var mutate sync.Once
		return outdatedOptions{
			Context: ctx,
			Quiet:   quiet,
			resolver: packageUpdateResolver{fetchLatest: func(ctx context.Context, _ domain.Ecosystem, _ string) string {
				mutate.Do(func() {
					phase := registryLookupPhaseFrom(ctx)
					for range registryBreakerThreshold {
						phase.recordRefusal()
					}
					for range 2 {
						phase.recordSkipped()
					}
				})
				return ""
			}},
		}
	}

	t.Run("normal", func(t *testing.T) {
		var warnings []string
		stderr := captureScanStderr(t, func() {
			_, warnings = resolveOutdatedStatuses(packages, newOptions(context.Background(), false))
		})
		if stderr != wantStderr {
			t.Fatalf("normal lookup stderr = %q, want %q", stderr, wantStderr)
		}
		if !reflect.DeepEqual(warnings, wantWarnings) {
			t.Fatalf("normal lookup warnings = %#v, want %#v", warnings, wantWarnings)
		}
	})

	t.Run("quiet", func(t *testing.T) {
		var warnings []string
		stderr := captureScanStderr(t, func() {
			_, warnings = resolveOutdatedStatuses(packages, newOptions(context.Background(), true))
		})
		if stderr != "" {
			t.Fatalf("quiet lookup stderr = %q, want empty", stderr)
		}
		if !reflect.DeepEqual(warnings, wantWarnings) {
			t.Fatalf("quiet lookup warnings = %#v, want %#v", warnings, wantWarnings)
		}
	})

	t.Run("canceled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		var warnings []string
		stderr := captureScanStderr(t, func() {
			_, warnings = resolveOutdatedStatuses(packages, newOptions(ctx, true))
		})
		if stderr != "" {
			t.Fatalf("canceled lookup stderr = %q, want empty", stderr)
		}
		if warnings != nil {
			t.Fatalf("canceled lookup warnings = %#v, want nil", warnings)
		}
	})
}

func TestApplyOutdatedStatusesSortsByEcosystemThenName(t *testing.T) {
	t.Parallel()

	packages := []outdatedPackage{
		{Name: "zeta", Version: "1.0.0", Ecosystem: domain.EcosystemPyPI},
		{Name: "zeta", Version: "1.0.0", Ecosystem: domain.EcosystemNPM},
		{Name: "alpha", Version: "1.0.0", Ecosystem: domain.EcosystemNPM},
	}
	statuses := []packageLatestStatus{
		{Latest: "2.0.0", Update: "yes"},
		{Latest: "2.0.0", Update: "yes"},
		{Latest: "2.0.0", Update: "yes"},
	}
	report := applyOutdatedStatusesToReport(outdatedReport{}, packages, statuses)
	got := make([]string, 0, len(report.Outdated))
	for _, row := range report.Outdated {
		got = append(got, row.Ecosystem+"/"+row.Name)
	}
	want := []string{"npm/alpha", "npm/zeta", "pypi/zeta"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("sorted outdated rows = %#v, want %#v", got, want)
	}
}

func TestPrintOutdatedReportAlignsLongEcosystemColumn(t *testing.T) {
	report := outdatedReport{
		Total: 2,
		Outdated: []outdatedRow{
			{Name: "alpha", Installed: "1", Latest: "2", Ecosystem: "an-unusually-long-ecosystem", Scope: "runtime", Relation: "direct", LockFile: "a.lock"},
			{Name: "beta", Installed: "1", Latest: "2", Ecosystem: "npm", Scope: "runtime", Relation: "direct", LockFile: "b.lock"},
		},
	}
	output := captureStdout(t, func() { printOutdatedReport(report) })
	lines := strings.Split(output, "\n")
	if len(lines) < 4 {
		t.Fatalf("outdated table output has %d lines, want header and rows:\n%s", len(lines), output)
	}
	headerScope := strings.Index(lines[1], "SCOPE")
	longScope := strings.Index(lines[2], "runtime")
	shortScope := strings.Index(lines[3], "runtime")
	if headerScope < 0 || longScope != headerScope || shortScope != headerScope {
		t.Fatalf("ecosystem column misaligned SCOPE at header/rows %d/%d/%d:\n%s", headerScope, longScope, shortScope, output)
	}
}
