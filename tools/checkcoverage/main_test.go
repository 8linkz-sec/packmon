package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCoveragePercentFromProfile(t *testing.T) {
	t.Parallel()

	path := writeCoverageProfile(t, `mode: set
github.com/8linkz-sec/packmon/a.go:1.1,1.2 2 1
github.com/8linkz-sec/packmon/b.go:1.1,1.2 3 0
`)

	got, err := coveragePercentFromProfile(path)
	if err != nil {
		t.Fatalf("coveragePercentFromProfile() error = %v", err)
	}
	if got != 40 {
		t.Fatalf("coveragePercentFromProfile() = %.1f, want 40.0", got)
	}
}

func TestCheckCoverageFailsBelowMinimum(t *testing.T) {
	t.Parallel()

	path := writeCoverageProfile(t, `mode: set
github.com/8linkz-sec/packmon/a.go:1.1,1.2 2 1
github.com/8linkz-sec/packmon/b.go:1.1,1.2 3 0
`)

	err := checkCoverage(path, 50)
	if err == nil {
		t.Fatal("checkCoverage() error = nil, want threshold failure")
	}
	if !strings.Contains(err.Error(), "40.0% is below required 50.0%") {
		t.Fatalf("checkCoverage() error = %q", err)
	}
}

func writeCoverageProfile(t *testing.T, contents string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "coverage.out")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write coverage profile: %v", err)
	}
	return path
}
