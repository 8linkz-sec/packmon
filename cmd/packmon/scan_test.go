package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/8linkz/packmon/internal/domain"
	"github.com/8linkz/packmon/internal/scanner"
)

func TestAutoFallbackWarning(t *testing.T) {
	t.Parallel()

	age := 5
	cases := []struct {
		name   string
		mode   scanner.Mode
		result *domain.ScanResult
		want   string
	}{
		{"auto fallback with age", scanner.ModeAuto, &domain.ScanResult{Mode: "local", DBAgeDays: &age}, "warning: remote server unreachable, scanned against local database (5 day(s) old)"},
		{"auto fallback without age", scanner.ModeAuto, &domain.ScanResult{Mode: "local"}, "warning: remote server unreachable, scanned against local database"},
		{"auto remote success", scanner.ModeAuto, &domain.ScanResult{Mode: "remote"}, ""},
		{"explicit local mode", scanner.ModeLocal, &domain.ScanResult{Mode: "local"}, ""},
		{"nil result", scanner.ModeAuto, nil, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := autoFallbackWarning(tc.mode, tc.result); got != tc.want {
				t.Fatalf("autoFallbackWarning() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestBuildScanTargets_UsesLocalNameForRootPath(t *testing.T) {
	t.Parallel()

	targets, err := buildScanTargets(nil, []string{string(filepath.Separator)}, scanFlagValues{})
	if err != nil {
		t.Fatalf("build scan targets: %v", err)
	}
	if len(targets) != 1 {
		t.Fatalf("len(targets) = %d, want 1", len(targets))
	}
	if targets[0].Name != "local" {
		t.Fatalf("target name = %q, want %q", targets[0].Name, "local")
	}
}

func TestWriteJSONFile_CreatesParentDirWithRestrictivePermissions(t *testing.T) {
	t.Parallel()

	baseDir := t.TempDir()
	outputPath := filepath.Join(baseDir, "reports", "scan.json")

	if err := writeJSONFile(outputPath, &domain.ScanResult{}); err != nil {
		t.Fatalf("writeJSONFile: %v", err)
	}

	if _, err := os.Stat(outputPath); err != nil {
		t.Fatalf("stat output file: %v", err)
	}

	if runtime.GOOS == "windows" {
		return
	}

	dirInfo, err := os.Stat(filepath.Dir(outputPath))
	if err != nil {
		t.Fatalf("stat output dir: %v", err)
	}
	if dirInfo.Mode().Perm() != 0o750 {
		t.Fatalf("output dir perms = %o, want %o", dirInfo.Mode().Perm(), 0o750)
	}

	fileInfo, err := os.Stat(outputPath)
	if err != nil {
		t.Fatalf("stat output file: %v", err)
	}
	if fileInfo.Mode().Perm() != 0o600 {
		t.Fatalf("output file perms = %o, want %o", fileInfo.Mode().Perm(), 0o600)
	}
}
