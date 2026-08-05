package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRunReportsCoverageAboveMinimum pins the success path of the gate: exit
// code 0 and a summary line naming both the measured and the required value.
func TestRunReportsCoverageAboveMinimum(t *testing.T) {
	t.Parallel()

	path := writeCoverageProfile(t, `mode: set
github.com/8linkz-sec/packmon/a.go:1.1,1.2 4 1
github.com/8linkz-sec/packmon/b.go:1.1,1.2 1 0
`)

	var stdout, stderr bytes.Buffer
	code := run([]string{"-profile", path, "-min", "79.5"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("run() = %d, want 0; stderr = %q", code, stderr.String())
	}
	if got := stdout.String(); !strings.Contains(got, "80.0%") || !strings.Contains(got, "79.5%") {
		t.Fatalf("run() stdout = %q, want the measured and required values", got)
	}
	if stderr.Len() != 0 {
		t.Fatalf("run() stderr = %q, want empty on success", stderr.String())
	}
}

// TestRunFailsBelowMinimum is the case the gate exists for. A non-zero exit code
// is what makes the build red, so it is asserted explicitly.
func TestRunFailsBelowMinimum(t *testing.T) {
	t.Parallel()

	path := writeCoverageProfile(t, `mode: set
github.com/8linkz-sec/packmon/a.go:1.1,1.2 2 1
github.com/8linkz-sec/packmon/b.go:1.1,1.2 3 0
`)

	var stdout, stderr bytes.Buffer
	code := run([]string{"-profile", path, "-min", "50"}, &stdout, &stderr)

	if code == 0 {
		t.Fatal("run() = 0, want a non-zero exit code below the minimum")
	}
	if got := stderr.String(); !strings.Contains(got, "40.0% is below required 50.0%") {
		t.Fatalf("run() stderr = %q, want the shortfall reported", got)
	}
	if stdout.Len() != 0 {
		t.Fatalf("run() stdout = %q, want no success summary on failure", stdout.String())
	}
}

// TestRunFailsOnMissingProfile guards the most likely operational mistake: a
// profile that was never generated must fail loudly rather than pass silently.
func TestRunFailsOnMissingProfile(t *testing.T) {
	t.Parallel()

	missing := filepath.Join(t.TempDir(), "absent.out")

	var stdout, stderr bytes.Buffer
	code := run([]string{"-profile", missing, "-min", "1"}, &stdout, &stderr)

	if code == 0 {
		t.Fatal("run() = 0, want a non-zero exit code for a missing profile")
	}
	if got := stderr.String(); !strings.Contains(got, "open coverage profile") {
		t.Fatalf("run() stderr = %q, want an open failure", got)
	}
}

// TestRunFailsOnEmptyProfile covers a profile that exists but measured nothing,
// which must not be reported as 0 % passing a 0 minimum.
func TestRunFailsOnEmptyProfile(t *testing.T) {
	t.Parallel()

	path := writeCoverageProfile(t, "mode: set\n")

	var stdout, stderr bytes.Buffer
	code := run([]string{"-profile", path, "-min", "0"}, &stdout, &stderr)

	if code == 0 {
		t.Fatal("run() = 0, want a non-zero exit code for a profile with no statements")
	}
	if got := stderr.String(); !strings.Contains(got, "no statements") {
		t.Fatalf("run() stderr = %q, want the empty profile reported", got)
	}
}

// TestRunRejectsUnknownFlag keeps argument handling from silently ignoring a
// typo in the gate invocation.
func TestRunRejectsUnknownFlag(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	code := run([]string{"-nope"}, &stdout, &stderr)

	if code == 0 {
		t.Fatal("run() = 0, want a non-zero exit code for an unknown flag")
	}
}

// TestRunUsesDefaultProfilePath documents that the profile flag defaults to
// coverage.out in the working directory.
func TestRunUsesDefaultProfilePath(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.WriteFile(filepath.Join(dir, "coverage.out"), []byte("mode: set\na.go:1.1,1.2 1 1\n"), 0o600); err != nil {
		t.Fatalf("write default profile: %v", err)
	}

	var stdout, stderr bytes.Buffer
	if code := run([]string{"-min", "100"}, &stdout, &stderr); code != 0 {
		t.Fatalf("run() = %d, want 0 using the default profile path; stderr = %q", code, stderr.String())
	}
}

// TestCoveragePercentFromProfileReportsReadErrors covers the scanner failure
// path: a line beyond the scanner's token limit must surface as a read error
// rather than being silently skipped, which would understate coverage.
func TestCoveragePercentFromProfileReportsReadErrors(t *testing.T) {
	t.Parallel()

	huge := "a.go:1.1,1.2 " + strings.Repeat("9", 128*1024) + " 1\n"
	path := writeCoverageProfile(t, "mode: set\n"+huge)

	if _, err := coveragePercentFromProfile(path); err == nil ||
		!strings.Contains(err.Error(), "read coverage profile") {
		t.Fatalf("coveragePercentFromProfile() error = %v, want a read failure", err)
	}
}
