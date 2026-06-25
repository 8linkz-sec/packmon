package ci

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDeveloperRequirementsAreDocumentedAndScripted(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..")
	requirementsPath := filepath.Join(root, "requirements", "packmon-tools.tsv")
	requirementsData, err := os.ReadFile(requirementsPath) //nolint:gosec // static repository fixture path.
	if err != nil {
		t.Fatalf("read requirements file: %v", err)
	}
	requirements := string(requirementsData)

	patchedGoVersion := moduleToolchainGoVersion(t)
	for _, want := range []string{
		"packmon|packmon|full|true|any|manual|",
		"go|go|agent,sbom,dev|true|" + patchedGoVersion + "|manual|",
		"node|node|web,sbom,dev|true|>=20|manual|",
		"npm|npm|web,sbom,dev|true|>=10|manual|",
		"docker|docker|server,dev|true|any|manual|",
		"cyclonedx-gomod|cyclonedx-gomod|sbom,dev|true|v1.10.0|go-install:github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@v1.10.0|",
		"cyclonedx-npm|cyclonedx-npm|sbom,dev|true|4.2.1|npm-global:@cyclonedx/cyclonedx-npm@4.2.1|",
		"cyclonedx-py|cyclonedx-py|sbom,dev|true|7.3.0|pip-user:cyclonedx-bom==7.3.0|",
		"gofumpt|gofumpt|dev|true|v0.9.2|go-install:mvdan.cc/gofumpt@v0.9.2|",
		"govulncheck|govulncheck|dev|true|v1.4.0|go-install:golang.org/x/vuln/cmd/govulncheck@v1.4.0|",
		"gosec|gosec|dev|true|v2.27.1|go-install:github.com/securego/gosec/v2/cmd/gosec@v2.27.1|",
	} {
		if !strings.Contains(requirements, want) {
			t.Fatalf("requirements/packmon-tools.tsv missing %q", want)
		}
	}
	for _, forbidden := range []string{
		"gofumpt|gofumpt|full",
		"golangci-lint|golangci-lint|full",
		"govulncheck|govulncheck|full",
		"gosec|gosec|full",
		"docker|docker|full",
	} {
		if strings.Contains(requirements, forbidden) {
			t.Fatalf("full profile must not include developer/server requirement %q", forbidden)
		}
	}

	var pkg struct {
		Engines map[string]string `json:"engines"`
	}
	packageJSON, err := os.ReadFile(filepath.Join(root, "package.json")) //nolint:gosec // static repository fixture path.
	if err != nil {
		t.Fatalf("read package.json: %v", err)
	}
	if err := json.Unmarshal(packageJSON, &pkg); err != nil {
		t.Fatalf("parse package.json: %v", err)
	}
	if !strings.Contains(requirements, "node|node|web,sbom,dev|true|"+pkg.Engines["node"]+"|manual|") {
		t.Fatalf("requirements file does not mirror package.json node engine %q", pkg.Engines["node"])
	}
	if !strings.Contains(requirements, "npm|npm|web,sbom,dev|true|"+pkg.Engines["npm"]+"|manual|") {
		t.Fatalf("requirements file does not mirror package.json npm engine %q", pkg.Engines["npm"])
	}

	readmeData, err := os.ReadFile(filepath.Join(root, "README.md")) //nolint:gosec // static repository fixture path.
	if err != nil {
		t.Fatalf("read README.md: %v", err)
	}
	readme := string(readmeData)
	for _, want := range []string{
		"REQUIREMENTS.md",
		"requirements/packmon-tools.tsv",
		"## Quick Start",
		"### Choose Your Test Path",
		"Test the server container plus an agent",
		"### Windows",
		`.\packmon.exe scan --list-all --html packmon-report.html --output-json packmon-report.json .`,
		`.\packmon.exe scan --auto-sbom --install-tools --list-all --html packmon-report.html --output-json packmon-report.json .`,
		"Release-binary users do not need them.",
		"Start the Docker stack from the Packmon source checkout",
		"http://localhost:8080/admin/keys",
		"Production `/api/v1/*` endpoints require this API key.",
		`$env:PACKMON_API_KEY = "<copied-api-key>"`,
		`.\packmon.exe scan . ` + "`",
		"--server http://localhost:8080",
		"--insecure-allow-http",
		"--require-remote",
		`.\packmon.exe db sync ` + "`",
		"scripts/bootstrap.sh --profile dev",
		`.\scripts\bootstrap.ps1 -Profile dev`,
		"macOS: Packmon Mach-O",
		"`dev`",
	} {
		if !strings.Contains(readme, want) {
			t.Fatalf("README.md missing requirements marker %q", want)
		}
	}
	quickStartStart := strings.Index(readme, "## Quick Start")
	if quickStartStart < 0 {
		t.Fatal("README.md missing Quick Start section")
	}
	quickStartEnd := strings.Index(readme, "## Source Checkout Requirements")
	if quickStartEnd < 0 {
		t.Fatal("README.md missing Source Checkout Requirements section")
	}
	if quickStartStart >= quickStartEnd {
		t.Fatal("README.md Quick Start section must appear before Source Checkout Requirements")
	}
	quickStart := readme[quickStartStart:quickStartEnd]
	for _, forbidden := range []string{
		`.\scripts\`,
		"bash scripts/",
		"go build -o packmon ./cmd/packmon",
	} {
		if strings.Contains(quickStart, forbidden) {
			t.Fatalf("release-binary Quick Start must not require source checkout helper %q", forbidden)
		}
	}

	for _, rel := range []string{
		filepath.Join("scripts", "check-requirements.sh"),
		filepath.Join("scripts", "bootstrap.sh"),
		filepath.Join("scripts", "check-requirements.ps1"),
		filepath.Join("scripts", "bootstrap.ps1"),
	} {
		data, err := os.ReadFile(filepath.Join(root, rel)) //nolint:gosec // static repository script path.
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		if !strings.Contains(string(data), "requirements/packmon-tools.tsv") &&
			!strings.Contains(string(data), `requirements\packmon-tools.tsv`) {
			t.Fatalf("%s must read requirements/packmon-tools.tsv", rel)
		}
		if !strings.Contains(string(data), "target") && !strings.Contains(string(data), "Target") {
			t.Fatalf("%s must support target-aware SBOM requirement checks", rel)
		}
	}
}
