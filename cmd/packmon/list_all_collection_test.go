package main

import (
	"strings"
	"testing"

	"github.com/8linkz-sec/packmon/internal/domain"
	"github.com/8linkz-sec/packmon/internal/scanner"
)

// TestListAllPackagesFromCollectionKeepsValidInventoryAfterParseWarnings
// ensures a non-fatal lockfile parse failure does not discard inventory from
// healthy inputs. Its diagnostic is terminal-safe before it reaches stderr.
func TestListAllPackagesFromCollectionKeepsValidInventoryAfterParseWarnings(t *testing.T) {
	collection := &scanner.PackageCollection{
		Entries: []scanner.CollectedPackage{
			{
				Package:    domain.Package{Name: "left-pad", Version: "1.3.0", Ecosystem: domain.EcosystemNPM, Direct: true},
				SourceFile: "package-lock.json",
				SourceType: "package-lock.json",
			},
			{
				Package:    domain.Package{Name: "left-pad", Version: "1.3.0", Ecosystem: domain.EcosystemNPM, Direct: true},
				SourceFile: "nested/package-lock.json",
				SourceType: "package-lock.json",
			},
		},
		ParseErrors: []string{"broken/pnpm-lock.yaml: invalid byte \x1b[31mred\x1b[0m"},
	}

	var (
		packages []listAllPackage
		warnings []string
		err      error
	)
	stderr := captureStderr(t, func() {
		packages, warnings, err = listAllPackagesFromCollection(collection)
	})
	if err != nil {
		t.Fatalf("listAllPackagesFromCollection: %v", err)
	}
	if len(packages) != 1 {
		t.Fatalf("packages = %#v, want the one deduplicated healthy package", packages)
	}
	if got := packages[0]; got.Name != "left-pad" || got.Version != "1.3.0" || got.LockFile != "package-lock.json" || !got.Direct {
		t.Fatalf("package = %#v, want preserved healthy lockfile inventory", got)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "parse error in broken/pnpm-lock.yaml") {
		t.Fatalf("warnings = %#v, want retained parse warning", warnings)
	}
	if strings.Contains(stderr, "\x1b") {
		t.Fatalf("stderr retained terminal control sequence: %q", stderr)
	}
	for _, want := range []string{"warning: parse error in broken/pnpm-lock.yaml", `invalid byte \x1B[31mred\x1B[0m`} {
		if !strings.Contains(stderr, want) {
			t.Fatalf("stderr = %q, want %q", stderr, want)
		}
	}
}

// TestListAllPackagesFromCollectionRejectsFatalParseErrors keeps list-all in
// lockstep with normal scans: a fatal parse error must stop inventory output
// with the parser exit code instead of being downgraded to a warning.
func TestListAllPackagesFromCollectionRejectsFatalParseErrors(t *testing.T) {
	_, _, err := listAllPackagesFromCollection(&scanner.PackageCollection{
		FatalParseErrors: []string{"invalid SPDX document \x1b[31msecret\x1b[0m"},
	})
	if err == nil {
		t.Fatal("listAllPackagesFromCollection returned nil error for fatal parse failure")
	}
	if got := exitCodeForError(err); got != ExitParser {
		t.Fatalf("exitCodeForError = %d, want %d; err=%v", got, ExitParser, err)
	}
	if strings.Contains(err.Error(), "\x1b") {
		t.Fatalf("fatal parse error retained terminal control sequence: %q", err)
	}
	if !strings.Contains(err.Error(), `invalid SPDX document \x1B[31msecret\x1B[0m`) {
		t.Fatalf("fatal parse error = %q, want sanitized diagnostic", err)
	}
}
