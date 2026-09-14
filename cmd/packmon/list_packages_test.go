package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScanSourceDoesNotOwnListPackagesImplementation(t *testing.T) {
	scanSource, err := os.ReadFile("scan.go")
	if err != nil {
		t.Fatalf("read scan.go: %v", err)
	}
	if strings.Contains(string(scanSource), "func runListPackagesWithSettings(") {
		t.Fatal("scan.go declares runListPackagesWithSettings; keep list-packages implementation in list_packages.go")
	}

	listPackagesSource, err := os.ReadFile("list_packages.go")
	if err != nil {
		t.Fatalf("read list_packages.go: %v", err)
	}
	if !strings.Contains(string(listPackagesSource), "func runListPackagesWithSettings(") {
		t.Fatal("list_packages.go must own runListPackagesWithSettings")
	}
}

func TestRunListPackagesRetainsDevPackagesAndReportsMultipleInputs(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	projectDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectDir, "package-lock.json"), []byte(`{
  "lockfileVersion": 3,
  "packages": {
    "node_modules/dev-only": {"version": "1.2.3", "dev": true}
  }
}`), 0o600); err != nil {
		t.Fatalf("write package lock: %v", err)
	}

	sbomPath := filepath.Join(projectDir, "inventory.cdx.json")
	if err := os.WriteFile(sbomPath, []byte(`{
  "bomFormat": "CycloneDX",
  "components": [{
    "type": "library",
    "name": "requests",
    "version": "2.32.3",
    "purl": "pkg:pypi/requests@2.32.3"
  }]
}`), 0o600); err != nil {
		t.Fatalf("write SBOM: %v", err)
	}

	output := captureStdout(t, func() {
		if err := runListPackagesWithSettings(scanSettings{
			Path:       projectDir,
			Ecosystems: []string{"npm", "pypi"},
			MaxDepth:   2,
			SBOMFiles:  []string{sbomPath},
			IncludeDev: false,
		}); err != nil {
			t.Fatalf("run list packages: %v", err)
		}
	})

	for _, want := range []string{
		"dev-only  1.2.3    npm        package-lock.json",
		"requests  2.32.3   pypi       inventory.cdx.json",
		"2 packages found in 2 input files",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("list packages output missing %q:\n%s", want, output)
		}
	}
}
