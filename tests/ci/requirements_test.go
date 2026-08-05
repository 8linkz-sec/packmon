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
		"node|node|web,sbom,dev|true|>=24.11.0|manual|",
		"npm|npm|web,sbom,dev|true|>=10|manual|",
		"python|python|sbom,dev|true|>=3.12.0|manual|",
		"docker|docker|server,dev|true|any|manual|",
		"cyclonedx-gomod|cyclonedx-gomod|dev|true|v1.10.0|go-install:github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@v1.10.0|",
		"cyclonedx-npm|cyclonedx-npm|sbom,dev|true|5.0.0|npm-global:@cyclonedx/cyclonedx-npm@5.0.0|",
		"cyclonedx-py|cyclonedx-py|sbom,dev|true|7.3.0|pip-user:cyclonedx-bom==7.3.0|",
		"go-licenses|go-licenses|dev|true|v1.6.0|go-install:github.com/google/go-licenses@v1.6.0|",
		"gofumpt|gofumpt|dev|true|v0.9.2|go-install:mvdan.cc/gofumpt@v0.9.2|",
		"govulncheck|govulncheck|dev|true|v1.5.0|go-install:golang.org/x/vuln/cmd/govulncheck@v1.5.0|",
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
		filepath.Join("scripts", "lib", "requirements.ps1"),
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

	for _, rel := range []string{
		filepath.Join("scripts", "bootstrap.sh"),
		filepath.Join("scripts", "bootstrap.ps1"),
	} {
		data, err := os.ReadFile(filepath.Join(root, rel)) //nolint:gosec // static repository script path.
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		if !strings.Contains(string(data), "npm install --global --ignore-scripts") {
			t.Fatalf("%s must disable npm lifecycle scripts for managed npm installs", rel)
		}
	}
}

func TestAutoSBOMRequirementsDoNotAdvertiseUnsupportedLockManagersAsTargets(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..")
	data, err := os.ReadFile(filepath.Join(root, "REQUIREMENTS.md")) //nolint:gosec // static repository fixture path.
	if err != nil {
		t.Fatalf("read REQUIREMENTS.md: %v", err)
	}
	requirements := string(data)
	for _, unsupportedRow := range []string{
		"pnpm-lock.yaml` | Node.js",
		"yarn.lock` | Node.js",
		"Pipfile` | Python",
		"Pipfile.lock` | Python",
	} {
		if strings.Contains(requirements, unsupportedRow) {
			t.Fatalf("REQUIREMENTS.md still maps unsupported auto-SBOM target row %q", unsupportedRow)
		}
	}
	for _, want := range []string{"Yarn", "pnpm", "Pipenv", "not currently `--auto-sbom` generator"} {
		if !strings.Contains(requirements, want) {
			t.Fatalf("REQUIREMENTS.md missing unsupported auto-SBOM clarification %q", want)
		}
	}

	for _, rel := range []string{
		filepath.Join("scripts", "lib", "requirements.sh"),
		filepath.Join("scripts", "lib", "requirements.ps1"),
	} {
		data, err := os.ReadFile(filepath.Join(root, rel)) //nolint:gosec // static repository fixture path.
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		text := string(data)
		for _, want := range []string{"pnpm-lock.yaml", "yarn.lock", "package-lock.json", "npm-shrinkwrap.json"} {
			if !strings.Contains(text, want) {
				t.Fatalf("%s missing node lockfile skip guard marker %q", rel, want)
			}
		}
		for _, forbidden := range []string{"pipfile|pipfile.lock", `"pipfile"`, `"pipfile.lock"`} {
			if strings.Contains(strings.ToLower(text), forbidden) {
				t.Fatalf("%s still maps unsupported Pipenv target marker %q", rel, forbidden)
			}
		}
	}
}

func TestGoAutoSBOMRequirementsUseGoToolchainOnly(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..")
	requirementsData, err := os.ReadFile(filepath.Join(root, "requirements", "packmon-tools.tsv")) //nolint:gosec // static repository fixture path.
	if err != nil {
		t.Fatalf("read requirements file: %v", err)
	}
	if strings.Contains(string(requirementsData), "cyclonedx-gomod|cyclonedx-gomod|sbom,") ||
		strings.Contains(string(requirementsData), "cyclonedx-gomod|cyclonedx-gomod|sbom,dev|") {
		t.Fatal("Go auto-SBOM profile must not require cyclonedx-gomod")
	}
	if !strings.Contains(string(requirementsData), "cyclonedx-gomod|cyclonedx-gomod|dev|true|v1.10.0|go-install:") {
		t.Fatal("cyclonedx-gomod release tooling pin must remain available in the dev profile")
	}

	requirementsDoc, err := os.ReadFile(filepath.Join(root, "REQUIREMENTS.md")) //nolint:gosec // static repository fixture path.
	if err != nil {
		t.Fatalf("read REQUIREMENTS.md: %v", err)
	}
	for _, want := range []string{
		"| `go.mod` | Go toolchain (`go list`) |",
		"`cyclonedx-gomod` is retained only for release SBOM generation",
	} {
		if !strings.Contains(string(requirementsDoc), want) {
			t.Fatalf("REQUIREMENTS.md missing Go auto-SBOM requirement marker %q", want)
		}
	}
	if strings.Contains(string(requirementsDoc), "| `go.mod` | Go and `cyclonedx-gomod` |") {
		t.Fatal("REQUIREMENTS.md still documents cyclonedx-gomod as a Go auto-SBOM target requirement")
	}

	scriptMarkers := map[string][]string{
		filepath.Join("scripts", "lib", "requirements.sh"): {
			"AUTO_SBOM_MANIFESTS_PATH=\"$ROOT_DIR/internal/sbomgen/auto_sbom_manifests.tsv\"",
			"while IFS='|' read -r manifest kind ecosystem input_kind ids; do",
			"tr ',' '\\n' <<< \"$ids\"",
		},
		filepath.Join("scripts", "lib", "requirements.ps1"): {
			`$AutoSbomManifestSupportPath = Join-Path $RootDir "internal\sbomgen\auto_sbom_manifests.tsv"`,
			"Read-AutoSbomManifestSupport",
			`Add-RequirementId $Ids $id`,
		},
	}
	for rel, markers := range scriptMarkers {
		data, err := os.ReadFile(filepath.Join(root, rel)) //nolint:gosec // static repository script path.
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		text := string(data)
		for _, marker := range markers {
			if !strings.Contains(text, marker) {
				t.Fatalf("%s missing Go target marker %q", rel, marker)
			}
		}
		if strings.Contains(text, "go cyclonedx-gomod") ||
			strings.Contains(text, `Add-RequirementId $ids "cyclonedx-gomod"`) {
			t.Fatalf("%s still maps go.mod targets to cyclonedx-gomod", rel)
		}
	}
	manifestData, err := os.ReadFile(filepath.Join(root, "internal", "sbomgen", "auto_sbom_manifests.tsv")) //nolint:gosec // static repository fixture path.
	if err != nil {
		t.Fatalf("read auto-SBOM manifest support file: %v", err)
	}
	if !strings.Contains(string(manifestData), "go.mod|detect|go|go.mod|go") {
		t.Fatal("auto-SBOM manifest support file must map go.mod targets to only the Go toolchain")
	}
	if strings.Contains(string(manifestData), "go.mod|detect|go|go.mod|go,cyclonedx-gomod") {
		t.Fatal("auto-SBOM manifest support file still maps go.mod targets to cyclonedx-gomod")
	}
}

func TestMavenAutoSBOMRequirementConstrainsRuntime(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..")
	requirementsData, err := os.ReadFile(filepath.Join(root, "requirements", "packmon-tools.tsv")) //nolint:gosec // static repository fixture path.
	if err != nil {
		t.Fatalf("read requirements file: %v", err)
	}
	requirements := string(requirementsData)
	for _, want := range []string{
		"mvn|mvn|sbom,dev|true|>=3.9.9|manual|Install JDK 17 or newer and Apache Maven 3.9.9 or newer",
	} {
		if !strings.Contains(requirements, want) {
			t.Fatalf("requirements/packmon-tools.tsv missing Maven runtime pin marker %q", want)
		}
	}
	if strings.Contains(requirements, "mvn|mvn|sbom,dev|true|any|manual|") {
		t.Fatal("Maven auto-SBOM runtime must not remain unconstrained")
	}

	checks := map[string][]string{
		filepath.Join("scripts", "lib", "requirements.sh"): {
			"maven_java_version()",
			"mvn --version",
			`version_ge "$java_version" "17"`,
		},
		filepath.Join("scripts", "check-requirements.sh"): {
			"mvn)",
			"maven_java_version",
		},
		filepath.Join("scripts", "lib", "requirements.ps1"): {
			"function Get-MavenJavaVersion",
			"mvn --version",
			`Test-VersionAtLeast $javaVersion "17"`,
		},
		filepath.Join("scripts", "check-requirements.ps1"): {
			`$requirement.Command -in @("go", "node", "npm", "python", "mvn")`,
			"Get-MavenJavaVersion",
		},
		filepath.Join("REQUIREMENTS.md"): {
			"Maven 3.9.9 or newer",
			"JDK 17 or newer",
		},
	}
	for rel, markers := range checks {
		data, err := os.ReadFile(filepath.Join(root, rel)) //nolint:gosec // static repository fixture path.
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		text := string(data)
		for _, marker := range markers {
			if !strings.Contains(text, marker) {
				t.Fatalf("%s missing Maven runtime preflight marker %q", rel, marker)
			}
		}
	}
}

func TestManagedRequirementPinsAreCheckedBeforeAcceptingInstalledTools(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..")
	requirementsData, err := os.ReadFile(filepath.Join(root, "requirements", "packmon-tools.tsv")) //nolint:gosec // static repository fixture path.
	if err != nil {
		t.Fatalf("read requirements file: %v", err)
	}
	for _, want := range []string{
		"cyclonedx-gomod|cyclonedx-gomod|dev|true|v1.10.0|go-install:",
		"cyclonedx-npm|cyclonedx-npm|sbom,dev|true|5.0.0|npm-global:",
		"cyclonedx-py|cyclonedx-py|sbom,dev|true|7.3.0|pip-user:",
		"go-licenses|go-licenses|dev|true|v1.6.0|go-install:",
		"gosec|gosec|dev|true|v2.27.1|go-install:",
	} {
		if !strings.Contains(string(requirementsData), want) {
			t.Fatalf("requirements/packmon-tools.tsv missing managed pin marker %q", want)
		}
	}

	scriptMarkers := map[string][]string{
		filepath.Join("scripts", "check-requirements.sh"): {
			`"$installer" != "manual"`,
			`version_eq "$version_text" "$version"`,
		},
		filepath.Join("scripts", "check-requirements.ps1"): {
			`$requirement.Installer -ne "manual"`,
			`Test-VersionEquals $versionText $requirement.Version`,
		},
		filepath.Join("scripts", "bootstrap.sh"): {
			`requirement_satisfied "$command" "$version" "$installer" "$resolved_command"`,
			`install_managed_tool "$command" "$installer"`,
		},
		filepath.Join("scripts", "bootstrap.ps1"): {
			`Test-RequirementSatisfied $requirement $resolvedCommand`,
			`Install-ManagedTool $requirement`,
		},
	}
	for rel, markers := range scriptMarkers {
		data, err := os.ReadFile(filepath.Join(root, rel)) //nolint:gosec // static repository script path.
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		text := string(data)
		for _, marker := range markers {
			if !strings.Contains(text, marker) {
				t.Fatalf("%s must enforce managed tool version pins before accepting installed tools; missing marker %q", rel, marker)
			}
		}
	}

	requirementsDoc, err := os.ReadFile(filepath.Join(root, "REQUIREMENTS.md")) //nolint:gosec // static repository fixture path.
	if err != nil {
		t.Fatalf("read REQUIREMENTS.md: %v", err)
	}
	for _, want := range []string{
		"check-requirements rejects stale managed tool versions",
		"bootstrap upgrades stale managed tools to the pinned versions",
	} {
		if !strings.Contains(string(requirementsDoc), want) {
			t.Fatalf("REQUIREMENTS.md missing managed-version behavior %q", want)
		}
	}
}

func TestBashRequirementScriptsSharePreflightLibrary(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..")
	helperRel := filepath.Join("scripts", "lib", "requirements.sh")
	helperData, err := os.ReadFile(filepath.Join(root, helperRel)) //nolint:gosec // static repository script path.
	if err != nil {
		t.Fatalf("read %s: %v", helperRel, err)
	}
	helper := string(helperData)
	for _, marker := range []string{
		"parse_requirements_args()",
		"validate_profile()",
		"detect_sbom_ids()",
		"prepare_target_filter()",
		"requirement_applies()",
		"resolve_packmon_command()",
		"resolve_requirement_command()",
		"requirement_satisfied()",
	} {
		if !strings.Contains(helper, marker) {
			t.Fatalf("%s missing shared preflight helper marker %q", helperRel, marker)
		}
	}

	for _, rel := range []string{
		filepath.Join("scripts", "check-requirements.sh"),
		filepath.Join("scripts", "bootstrap.sh"),
	} {
		data, err := os.ReadFile(filepath.Join(root, rel)) //nolint:gosec // static repository script path.
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		text := string(data)
		if !strings.Contains(text, "scripts/lib/requirements.sh") {
			t.Fatalf("%s must source scripts/lib/requirements.sh", rel)
		}
		for _, duplicate := range []string{
			"detect_sbom_ids()",
			"resolve_packmon_command()",
			"resolve_requirement_command()",
			"requirement_satisfied()",
		} {
			if strings.Contains(text, duplicate) {
				t.Fatalf("%s still defines shared helper %q", rel, duplicate)
			}
		}
	}
}

func TestPowerShellRequirementScriptsSharePreflightLibrary(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..")
	helperRel := filepath.Join("scripts", "lib", "requirements.ps1")
	helperData, err := os.ReadFile(filepath.Join(root, helperRel)) //nolint:gosec // static repository script path.
	if err != nil {
		t.Fatalf("read %s: %v", helperRel, err)
	}
	helper := string(helperData)
	for _, marker := range []string{
		"function Read-PackmonRequirements",
		"function Test-InProfile",
		"function Get-SbomRequirementIds",
		"function Resolve-PackmonCommand",
		"function Resolve-RequirementCommand",
		"function Test-VersionEquals",
		"function Test-VersionAtLeast",
		"requirements\\packmon-tools.tsv",
	} {
		if !strings.Contains(helper, marker) {
			t.Fatalf("%s missing shared preflight helper marker %q", helperRel, marker)
		}
	}

	for _, rel := range []string{
		filepath.Join("scripts", "check-requirements.ps1"),
		filepath.Join("scripts", "bootstrap.ps1"),
	} {
		data, err := os.ReadFile(filepath.Join(root, rel)) //nolint:gosec // static repository script path.
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		text := string(data)
		if !strings.Contains(text, `scripts\lib\requirements.ps1`) {
			t.Fatalf("%s must dot-source scripts/lib/requirements.ps1", rel)
		}
		for _, duplicate := range []string{
			"function Read-PackmonRequirements",
			"function Get-SbomRequirementIds",
			"function Resolve-PackmonCommand",
			"function Resolve-RequirementCommand",
		} {
			if strings.Contains(text, duplicate) {
				t.Fatalf("%s still defines shared helper %q", rel, duplicate)
			}
		}
	}
}

func TestServerRequirementPreflightChecksDockerComposeV2(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..")
	checks := map[string][]string{
		filepath.Join("scripts", "lib", "requirements.sh"): {
			"docker compose version",
		},
		filepath.Join("scripts", "lib", "requirements.ps1"): {
			"docker compose version",
		},
		filepath.Join("REQUIREMENTS.md"): {
			"Docker with Compose v2",
		},
		filepath.Join("requirements", "packmon-tools.tsv"): {
			"docker|docker|server,dev|true|any|manual|Install Docker Desktop or Docker Engine with Compose v2",
		},
	}
	for rel, markers := range checks {
		data, err := os.ReadFile(filepath.Join(root, rel)) //nolint:gosec // static repository fixture path.
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		text := string(data)
		for _, marker := range markers {
			if !strings.Contains(text, marker) {
				t.Fatalf("%s must check Docker Compose v2 for server/dev preflight; missing marker %q", rel, marker)
			}
		}
	}
}
