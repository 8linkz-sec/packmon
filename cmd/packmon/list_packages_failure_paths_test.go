package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunListPackagesReportsSBOMSkippedComponentsWithoutLeakingNames(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	root := t.TempDir()
	sbomPath := filepath.Join(root, "nested", "inventory.cdx.json")
	if err := os.MkdirAll(filepath.Dir(sbomPath), 0o750); err != nil {
		t.Fatal(err)
	}
	privateName := "private-client-token\x1b[31m"
	writeFile(t, sbomPath, `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "components": [
    {"type":"library","name":"kept","version":"1.0.0","purl":"pkg:npm/kept@1.0.0"},
    {"type":"library","name":"private-client-token\u001b[31m","version":"9.9.9"}
  ]
}`)

	var runErr error
	var stderr string
	stdout := captureStdout(t, func() {
		stderr = captureScanStderr(t, func() {
			runErr = runListPackagesWithSettings(scanSettings{Path: root, MaxDepth: 2, SBOMFiles: []string{sbomPath}})
		})
	})
	if runErr == nil || exitCodeForError(runErr) != ExitParser {
		t.Fatalf("error = %v, want parser exit %d", runErr, ExitParser)
	}
	for _, want := range []string{"kept", "1.0.0", "1 package found in 1 input file"} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("stdout missing %q:\n%s", want, stdout)
		}
	}
	for _, want := range []string{"nested" + string(filepath.Separator) + "inventory.cdx.json", "skipped SBOM component #1: missing purl"} {
		if !strings.Contains(stderr, want) {
			t.Fatalf("stderr missing %q: %q", want, stderr)
		}
	}
	for _, forbidden := range []string{privateName, "private-client-token", `private-client-token\u001b`, `private-client-token\x1b`, "\x1b"} {
		if strings.Contains(stdout, forbidden) || strings.Contains(stderr, forbidden) {
			t.Fatalf("output leaked private/control-bearing component %q: stdout=%q stderr=%q", forbidden, stdout, stderr)
		}
	}
}

func TestRunListPackagesCollectionFailureIsOperationalAndPrintsNoSuccessSummary(t *testing.T) {
	rootFile := filepath.Join(t.TempDir(), "root-file")
	writeFile(t, rootFile, "not a directory")
	var runErr error
	stdout := captureStdout(t, func() {
		runErr = runListPackagesWithSettings(scanSettings{Path: rootFile, MaxDepth: 2})
	})
	if runErr == nil || exitCodeForError(runErr) != ExitOperational {
		t.Fatalf("error = %v, want operational exit %d", runErr, ExitOperational)
	}
	if !strings.Contains(strings.ToLower(runErr.Error()), "walk") {
		t.Fatalf("error = %q, want collection/walk context", runErr)
	}
	for _, forbidden := range []string{"No lockfiles", "No packages", "found in"} {
		if strings.Contains(stdout, forbidden) {
			t.Fatalf("stdout contains success/empty summary %q: %q", forbidden, stdout)
		}
	}
}

func TestRunListPackagesAlignsLongestCollectableEcosystemColumn(t *testing.T) {
	if len("cocoapods") != 9 {
		t.Fatal("test contract requires cocoapods to remain 9 characters")
	}
	repoRoot := t.TempDir()
	workflowPath := filepath.Join(repoRoot, ".github", "workflows", "ci.yml")
	if err := os.MkdirAll(filepath.Dir(workflowPath), 0o750); err != nil {
		t.Fatal(err)
	}
	writeFile(t, workflowPath, "name: CI\non: [push]\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n")
	writeFile(t, filepath.Join(repoRoot, "Podfile.lock"), "PODS:\n  - podx (1.0.0)\n")

	var runErr error
	stdout := captureStdout(t, func() {
		runErr = runListPackagesWithSettings(scanSettings{
			Path: repoRoot, MaxDepth: 3, Ecosystems: []string{"cocoapods", "actions"},
		})
	})
	if runErr != nil {
		t.Fatalf("runListPackagesWithSettings() error = %v", runErr)
	}
	lines := strings.Split(stdout, "\n")
	if len(lines) < 3 {
		t.Fatalf("stdout lacks table rows: %q", stdout)
	}
	header := lines[0]
	var actionRow, cocoaRow string
	for _, line := range lines[1:] {
		switch {
		case strings.Contains(line, "actions/checkout"):
			actionRow = line
		case strings.Contains(line, "podx"):
			cocoaRow = line
		}
	}
	for _, want := range []string{"actions/checkout", "v4", "actions", filepath.ToSlash(".github/workflows/ci.yml"), "podx", "1.0.0", "cocoapods", "Podfile.lock", "2 packages found in 2 input files"} {
		if !strings.Contains(filepath.ToSlash(stdout), want) {
			t.Fatalf("stdout missing %q:\n%s", want, stdout)
		}
	}
	if strings.Contains(stdout, "github-actions") {
		t.Fatalf("stdout used parser descriptor instead of canonical ecosystem:\n%s", stdout)
	}
	lockColumn := strings.Index(header, "LOCKFILE")
	if actionRow == "" || cocoaRow == "" || lockColumn < 0 || strings.Index(filepath.ToSlash(actionRow), ".github/workflows/ci.yml") != lockColumn || strings.Index(cocoaRow, "Podfile.lock") != lockColumn {
		t.Fatalf("lockfile column is misaligned:\n%s\n%s\n%s", header, actionRow, cocoaRow)
	}
	if !strings.Contains(cocoaRow, "cocoapods  Podfile.lock") {
		t.Fatalf("cocoapods row does not retain two column separators: %q", cocoaRow)
	}
}
