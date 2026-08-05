package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestScanTargetNameUsesDirectoryNameForDot covers the most common invocation
// of all, `packmon scan .`: filepath.Base(".") is ".", which fell through to
// the literal "local". Every report generated that way was titled "local",
// so reports from different repositories were indistinguishable.
func TestScanTargetNameUsesDirectoryNameForDot(t *testing.T) {
	dir := t.TempDir()
	repoDir := filepath.Join(dir, "exxperts")
	if err := os.Mkdir(repoDir, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	t.Chdir(repoDir)

	targets, err := buildScanTargets(nil, []string{"."}, scanFlagValues{})
	if err != nil {
		t.Fatalf("buildScanTargets: %v", err)
	}
	if len(targets) != 1 {
		t.Fatalf("targets = %#v, want exactly one", targets)
	}
	if targets[0].Name != "exxperts" {
		t.Fatalf("target name = %q, want the scanned directory name %q", targets[0].Name, "exxperts")
	}
	if targets[0].Path != "." {
		t.Fatalf("target path = %q, want the caller's path to stay untouched", targets[0].Path)
	}
}

// TestScanTargetNameUsesDirectoryNameWhenNoArgGiven pins the same behaviour for
// a bare `packmon scan`, which defaults to the working directory.
func TestScanTargetNameUsesDirectoryNameWhenNoArgGiven(t *testing.T) {
	dir := t.TempDir()
	repoDir := filepath.Join(dir, "my-service")
	if err := os.Mkdir(repoDir, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	t.Chdir(repoDir)

	targets, err := buildScanTargets(nil, nil, scanFlagValues{})
	if err != nil {
		t.Fatalf("buildScanTargets: %v", err)
	}
	if targets[0].Name != "my-service" {
		t.Fatalf("target name = %q, want %q", targets[0].Name, "my-service")
	}
}

// TestScanTargetNameUsesDirectoryNameForTrailingSeparator covers `scan ./` and
// `scan repo/`, where Base also returns a value that carries no information.
func TestScanTargetNameUsesDirectoryNameForTrailingSeparator(t *testing.T) {
	dir := t.TempDir()
	repoDir := filepath.Join(dir, "trailing-repo")
	if err := os.Mkdir(repoDir, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	t.Chdir(repoDir)

	targets, err := buildScanTargets(nil, []string{"./"}, scanFlagValues{})
	if err != nil {
		t.Fatalf("buildScanTargets: %v", err)
	}
	if targets[0].Name != "trailing-repo" {
		t.Fatalf("target name = %q, want %q", targets[0].Name, "trailing-repo")
	}
}

// TestScanTargetNameKeepsExplicitDirectoryName makes sure the existing
// behaviour for a named path is untouched.
func TestScanTargetNameKeepsExplicitDirectoryName(t *testing.T) {
	t.Parallel()

	targets, err := buildScanTargets(nil, []string{filepath.Join("..", "another-service")}, scanFlagValues{})
	if err != nil {
		t.Fatalf("buildScanTargets: %v", err)
	}
	if targets[0].Name != "another-service" {
		t.Fatalf("target name = %q, want %q", targets[0].Name, "another-service")
	}
}
