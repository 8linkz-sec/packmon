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

func TestCoveragePercentFromProfileIgnoresNodeModulesGoCode(t *testing.T) {
	t.Parallel()

	path := writeCoverageProfile(t, `mode: set
github.com/8linkz-sec/packmon/a.go:1.1,1.2 2 1
github.com/8linkz-sec/packmon/node_modules/flatted/golang/pkg/flatted/flatted.go:1.1,1.2 8 0
`)

	got, err := coveragePercentFromProfile(path)
	if err != nil {
		t.Fatalf("coveragePercentFromProfile() error = %v", err)
	}
	if got != 100 {
		t.Fatalf("coveragePercentFromProfile() = %.1f, want 100.0 with node_modules Go code ignored", got)
	}
}

func TestCheckCoverageFailsBelowMinimum(t *testing.T) {
	t.Parallel()

	path := writeCoverageProfile(t, `mode: set
github.com/8linkz-sec/packmon/a.go:1.1,1.2 2 1
github.com/8linkz-sec/packmon/b.go:1.1,1.2 3 0
`)

	_, err := checkCoverage(path, 50)
	if err == nil {
		t.Fatal("checkCoverage() error = nil, want threshold failure")
	}
	if !strings.Contains(err.Error(), "40.0% is below required 50.0%") {
		t.Fatalf("checkCoverage() error = %q", err)
	}
}

func TestCheckCoverageAcceptsCoverageAtMinimum(t *testing.T) {
	t.Parallel()

	path := writeCoverageProfile(t, `mode: set
github.com/8linkz-sec/packmon/a.go:1.1,1.2 2 1
github.com/8linkz-sec/packmon/b.go:1.1,1.2 3 0
`)

	if _, err := checkCoverage(path, 40); err != nil {
		t.Fatalf("checkCoverage(at minimum) error = %v", err)
	}
}

func TestCoveragePercentFromProfileRejectsMalformedProfiles(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		content string
		want    string
	}{
		{name: "no statements", content: "mode: set\n\n", want: "no statements"},
		{name: "bad fields", content: "mode: set\nbad-line\n", want: "expected 3 fields"},
		{name: "bad statements", content: "mode: set\nfile.go:1.1,1.2 nope 1\n", want: "statement count"},
		{name: "bad count", content: "mode: set\nfile.go:1.1,1.2 1 nope\n", want: "execution count"},
		{name: "negative", content: "mode: set\nfile.go:1.1,1.2 1 -1\n", want: "negative"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := writeCoverageProfile(t, tt.content)
			if _, err := coveragePercentFromProfile(path); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("coveragePercentFromProfile() error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestParseCoverageLine(t *testing.T) {
	t.Parallel()

	statements, count, err := parseCoverageLine("file.go:1.1,1.2 12 3")
	if err != nil {
		t.Fatalf("parseCoverageLine(valid) error = %v", err)
	}
	if statements != 12 || count != 3 {
		t.Fatalf("parseCoverageLine(valid) = %d %d, want 12 3", statements, count)
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
