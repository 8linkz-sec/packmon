package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/8linkz-sec/packmon/internal/domain"
)

// TestReportTargetIsOmittedForCurrentDirectory drops the meta-line entry for
// `packmon scan .`, the most common invocation. Every other form of the path
// renders something meaningful there -- an absolute path shows the folder name,
// a relative one shows the relative path -- but "." only ever restated that the
// scan ran where the user already stood, and the report heading now carries the
// directory name anyway.
func TestReportTargetIsOmittedForCurrentDirectory(t *testing.T) {
	t.Parallel()

	for _, path := range []string{".", "./", "  .  "} {
		if got := htmlReportDisplayTarget(path); got != "" {
			t.Errorf("htmlReportDisplayTarget(%q) = %q, want an empty value so the meta line omits it", path, got)
		}
	}
}

// TestReportTargetKeepsInformativePaths guards the cases that do carry
// information, so dropping "." does not blank the field everywhere.
func TestReportTargetKeepsInformativePaths(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"sub/dir":                          "sub/dir",
		"../another-service":               "another-service",
		string(filepath.Separator) + "tmp": "",
	}
	for in, want := range cases {
		got := htmlReportDisplayTarget(in)
		if want == "" {
			if got == "" {
				t.Errorf("htmlReportDisplayTarget(%q) = %q, want a non-empty value", in, got)
			}
			continue
		}
		if got != want {
			t.Errorf("htmlReportDisplayTarget(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestRenderedReportHasNoBareDotTarget checks the rendered document rather than
// the helper, so a future template change cannot reintroduce the stray entry
// together with its separator.
func TestRenderedReportHasNoBareDotTarget(t *testing.T) {
	t.Parallel()

	htmlPath := filepath.Join(t.TempDir(), "report.html")
	report := listAllPackageReport{
		Target:            ".",
		ScannedAt:         "2026-08-04 07:29 UTC",
		ScannedAtDateTime: "2026-08-04T07:29:59Z",
		ScopeCounts:       map[string]int{},
	}
	if err := writeListAllHTML(htmlPath, "exxperts", &domain.ScanResult{Mode: "remote"}, report); err != nil {
		t.Fatalf("writeListAllHTML: %v", err)
	}
	data, err := os.ReadFile(htmlPath) //nolint:gosec // test-controlled temp path.
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	html := string(data)

	if strings.Contains(html, `<bdi dir="auto">.</bdi>`) {
		t.Error("report meta line still renders the bare \".\" target")
	}
	if !strings.Contains(html, `<bdi dir="auto">exxperts</bdi>`) {
		t.Error("report lost its heading with the scanned directory name")
	}
}
