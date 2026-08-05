package main

import "testing"

// TestReportTargetReducesAbsolutePathsRegardlessOfSeparator pins the privacy
// intent of htmlReportDisplayTarget: an absolute path must never reach the
// report, only its last segment. filepath.IsAbs alone cannot enforce that,
// because it only recognises the host platform's own convention -- a POSIX path
// on Windows (or a drive path on Linux) fell through to the relative branch and
// was rendered in full.
func TestReportTargetReducesAbsolutePathsRegardlessOfSeparator(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		`/home/user/exxperts`:        "exxperts",
		`/home/user/exxperts/`:       "exxperts",
		`E:\Github\exxperts`:         "exxperts",
		`E:/Github/exxperts`:         "exxperts",
		`C:\Users\Admin\my-service`:  "my-service",
		`\\fileserver\share\project`: "project",
	}
	for in, want := range cases {
		if got := htmlReportDisplayTarget(in); got != want {
			t.Errorf("htmlReportDisplayTarget(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestReportSourcePathReducesForeignAbsolutePaths covers the second caller.
// Inventory source paths outside the scan root go through the same reduction.
func TestReportSourcePathReducesForeignAbsolutePaths(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		`/etc/packmon/vendor.lock`: "vendor.lock",
		`E:\elsewhere\go.sum`:      "go.sum",
	}
	for in, want := range cases {
		if got := htmlReportDisplaySourcePath("repo", in); got != want {
			t.Errorf("htmlReportDisplaySourcePath(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestReportPathsKeepRelativeInputs guards the inputs that must stay untouched,
// so the cross-platform absolute check does not swallow ordinary paths.
func TestReportPathsKeepRelativeInputs(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"sub/dir":            "sub/dir",
		"../another-service": "another-service",
		".":                  "",
	}
	for in, want := range cases {
		if got := htmlReportDisplayTarget(in); got != want {
			t.Errorf("htmlReportDisplayTarget(%q) = %q, want %q", in, got, want)
		}
	}
}
