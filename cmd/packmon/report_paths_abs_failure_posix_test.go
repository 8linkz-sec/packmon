//go:build aix || darwin || dragonfly || freebsd || illumos || linux || netbsd || openbsd || solaris

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReportSourcePathReducesForeignAbsolutePathsFromLiveAbsolutePOSIXRoot(t *testing.T) {
	root, err := filepath.Abs(t.TempDir())
	if err != nil {
		t.Fatalf("resolve absolute fixture root: %v", err)
	}

	for _, source := range []string{
		`C:\Users\Alice\go.sum`,
		`C:/Users/Alice/go.sum`,
		`\\server\share\Alice\go.sum`,
		`//server/share/Alice/go.sum`,
	} {
		got := htmlReportDisplaySourcePath(root, source)
		if got != "go.sum" {
			t.Errorf("htmlReportDisplaySourcePath(%q, %q) = %q, want basename only", root, source, got)
		}
		if filepath.IsAbs(got) || strings.Contains(got, "Alice") || strings.Contains(got, "server") {
			t.Errorf("foreign absolute source leaked into report display: %q", got)
		}
	}
}

func TestHTMLReportRelativePathReportsDeletedWorkingDirectoryFailures(t *testing.T) {
	original, err := os.Getwd()
	if err != nil {
		t.Fatalf("get original working directory: %v", err)
	}
	base, err := os.MkdirTemp("", "packmon-report-deleted-cwd-")
	if err != nil {
		t.Fatalf("create deleted working-directory fixture: %v", err)
	}
	defer func() {
		_ = os.Chdir(original)
		_ = os.RemoveAll(base)
	}()
	deleted := filepath.Join(base, "deleted")
	if err := os.Mkdir(deleted, 0o755); err != nil {
		t.Fatalf("create removable working directory: %v", err)
	}
	if err := os.Chdir(deleted); err != nil {
		t.Fatalf("change to removable working directory: %v", err)
	}
	if err := os.Remove(deleted); err != nil {
		t.Fatalf("remove current working directory: %v", err)
	}

	_, rootOK := htmlReportRelativePath("repo", filepath.Join(base, "source", "go.sum"))
	_, pathOK := htmlReportRelativePath(base, filepath.Join("source", "go.sum"))
	restoreErr := os.Chdir(original)
	if restoreErr != nil {
		t.Fatalf("restore original working directory: %v", restoreErr)
	}

	if rootOK {
		t.Fatal("relative root unexpectedly resolved from a deleted working directory")
	}
	if pathOK {
		t.Fatal("relative source unexpectedly resolved from a deleted working directory")
	}
}
