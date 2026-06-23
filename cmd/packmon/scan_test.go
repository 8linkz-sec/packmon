package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/8linkz-sec/packmon/internal/domain"
	"github.com/8linkz-sec/packmon/internal/scanner"
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
		{"auto fallback with age", scanner.ModeAuto, &domain.ScanResult{Mode: "local", DBAgeDays: &age}, "warning: remote server unreachable, scanned against local database (5 days old)"},
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

func TestScanHelpDocumentsOutdatedPublicRegistryEgress(t *testing.T) {
	t.Parallel()

	flag := newScanCmd().Flag("outdated")
	if flag == nil {
		t.Fatal("--outdated flag missing")
	}
	usage := strings.ToLower(flag.Usage)
	for _, want := range []string{"public registr", "git remote"} {
		if !strings.Contains(usage, want) {
			t.Fatalf("--outdated usage = %q, want privacy note containing %q", flag.Usage, want)
		}
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
	skipIfPOSIXModesAreNotPreserved(t, baseDir)

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

func TestWriteJSONFileTightensExistingFilePermissions(t *testing.T) {
	t.Parallel()

	baseDir := t.TempDir()
	skipIfPOSIXModesAreNotPreserved(t, baseDir)

	outputPath := filepath.Join(baseDir, "scan.json")
	if err := os.WriteFile(outputPath, []byte("old report"), 0o644); err != nil { // #nosec G306 -- test seeds broad permissions to verify the report writer tightens them.
		t.Fatalf("seed broad report file: %v", err)
	}
	if err := os.Chmod(outputPath, 0o644); err != nil { // #nosec G302 -- test intentionally prepares a too-broad existing file.
		t.Fatalf("chmod broad report file: %v", err)
	}

	if err := writeJSONFile(outputPath, &domain.ScanResult{}); err != nil {
		t.Fatalf("writeJSONFile: %v", err)
	}

	fileInfo, err := os.Stat(outputPath)
	if err != nil {
		t.Fatalf("stat output file: %v", err)
	}
	if got := fileInfo.Mode().Perm(); got != 0o600 {
		t.Fatalf("output file perms = %o, want 0600", got)
	}
}

func TestStandaloneHTMLReportWritersTightenExistingFilePermissions(t *testing.T) {
	t.Parallel()

	baseDir := t.TempDir()
	skipIfPOSIXModesAreNotPreserved(t, baseDir)

	cases := []struct {
		name  string
		path  string
		write func(string) error
	}{
		{
			name: "list-all",
			path: filepath.Join(baseDir, "list-all.html"),
			write: func(path string) error {
				return writeListAllHTML(path, "svc", domain.SeverityCritical, &domain.ScanResult{}, listAllPackageReport{})
			},
		},
		{
			name: "outdated",
			path: filepath.Join(baseDir, "outdated.html"),
			write: func(path string) error {
				return writeOutdatedHTML(path, outdatedReport{Total: 1, PackageWord: "package"})
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(tc.path, []byte("old report"), 0o644); err != nil { // #nosec G306 -- test seeds broad permissions to verify the report writer tightens them.
				t.Fatalf("seed broad report file: %v", err)
			}
			if err := os.Chmod(tc.path, 0o644); err != nil { // #nosec G302 -- test intentionally prepares a too-broad existing file.
				t.Fatalf("chmod broad report file: %v", err)
			}

			if err := tc.write(tc.path); err != nil {
				t.Fatalf("write report: %v", err)
			}

			fileInfo, err := os.Stat(tc.path)
			if err != nil {
				t.Fatalf("stat output file: %v", err)
			}
			if got := fileInfo.Mode().Perm(); got != 0o600 {
				t.Fatalf("output file perms = %o, want 0600", got)
			}
		})
	}
}

func skipIfPOSIXModesAreNotPreserved(t *testing.T, baseDir string) {
	t.Helper()

	probeDir := filepath.Join(baseDir, "mode-probe")
	if err := os.Mkdir(probeDir, 0o750); err != nil {
		t.Fatalf("create mode probe directory: %v", err)
	}
	if err := os.Chmod(probeDir, 0o750); err != nil { // #nosec G302 -- test intentionally verifies POSIX directory mode preservation.
		t.Fatalf("chmod mode probe directory: %v", err)
	}
	probeInfo, err := os.Stat(probeDir)
	if err != nil {
		t.Fatalf("stat mode probe directory: %v", err)
	}
	if got := probeInfo.Mode().Perm(); got != 0o750 {
		t.Skipf("filesystem does not preserve POSIX directory mode bits: got %o after chmod 0750", got)
	}

	probeFile := filepath.Join(baseDir, "mode-probe.json")
	if err := os.WriteFile(probeFile, []byte("{}"), 0o600); err != nil {
		t.Fatalf("create mode probe file: %v", err)
	}
	if err := os.Chmod(probeFile, 0o600); err != nil {
		t.Fatalf("chmod mode probe file: %v", err)
	}
	fileInfo, err := os.Stat(probeFile)
	if err != nil {
		t.Fatalf("stat mode probe file: %v", err)
	}
	if got := fileInfo.Mode().Perm(); got != 0o600 {
		t.Skipf("filesystem does not preserve POSIX file mode bits: got %o after chmod 0600", got)
	}
}
