package main

import (
	"path/filepath"
	"testing"
)

// TestReportTargetReducesAbsolutePathsRegardlessOfSeparator pins the privacy
// intent of htmlReportDisplayTarget: an absolute path must never reach the
// report, only its last segment. filepath.IsAbs alone cannot enforce that,
// because it only recognises the host platform's own convention -- a POSIX path
// on Windows (or a drive path on Linux) fell through to the relative branch and
// was rendered in full.
func TestReportTargetReducesAbsolutePathsRegardlessOfSeparator(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		`/home/user/sample-app`:        "sample-app",
		`/home/user/sample-app/`:       "sample-app",
		`E:\Github\sample-app`:         "sample-app",
		`E:/Github/sample-app`:         "sample-app",
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

// TestReportSourcePathGapOneSentinels covers the display values that must not
// reveal a scan root or turn an empty value into a misleading pathname.
func TestReportSourcePathGapOneSentinels(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	rootBase := filepath.Base(root)
	cases := []struct {
		name string
		root string
		path string
		want string
	}{
		{name: "empty source", root: root, path: "", want: ""},
		{name: "whitespace source", root: root, path: " \t ", want: ""},
		{name: "empty root", root: "", path: "/private/vendor.lock", want: "vendor.lock"},
		{name: "whitespace root", root: " \t ", path: "/private/vendor.lock", want: "vendor.lock"},
		{name: "source equals root", root: root, path: root, want: rootBase},
		{name: "dot source", root: root, path: ".", want: "."},
		{name: "parent sentinel", root: root, path: "..", want: "external-file"},
		{name: "simple basename", root: root, path: "go.sum", want: "go.sum"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := htmlReportDisplaySourcePath(tc.root, tc.path); got != tc.want {
				t.Fatalf("htmlReportDisplaySourcePath(%q, %q) = %q, want %q", tc.root, tc.path, got, tc.want)
			}
		})
	}
}

func TestReportSourcePathKeepsPathsInsideScanRootRelative(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "nested", "vendor", "go.sum")

	if got := htmlReportDisplaySourcePath(root, path); got != "nested/vendor/go.sum" {
		t.Fatalf("htmlReportDisplaySourcePath(%q, %q) = %q, want relative source path", root, path, got)
	}
}

func TestReportPathLastSegmentHandlesSentinelsAndBasenames(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"basename":      "basename",
		" / ":           "",
		" C: ":          "C:",
		" /path/name/ ": "name",
	}
	for input, want := range cases {
		if got := reportPathLastSegment(input); got != want {
			t.Errorf("reportPathLastSegment(%q) = %q, want %q", input, got, want)
		}
	}

	for _, input := range []string{"/", "C:", ".."} {
		if got := safeHTMLExternalPath(input); got != "external-file" {
			t.Errorf("safeHTMLExternalPath(%q) = %q, want external-file", input, got)
		}
	}
}
