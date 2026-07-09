package ci

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// TestGitHubReleaseWorkflowHasTagTrigger verifies the release workflow fires on
// a "v*" tag push (and not only on manual dispatch), per the documented
// release policy.
func TestGitHubReleaseWorkflowHasTagTrigger(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", ".github", "workflows", "release.yml")
	data, err := os.ReadFile(path) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read release.yml: %v", err)
	}

	// Bind the "on" key explicitly via the struct tag so the YAML boolean
	// handling of the bare word "on" cannot interfere with key lookup.
	var wf struct {
		On struct {
			Push struct {
				Tags []string `yaml:"tags"`
			} `yaml:"push"`
			WorkflowDispatch map[string]any `yaml:"workflow_dispatch"`
		} `yaml:"on"`
	}
	if err := yaml.Unmarshal(data, &wf); err != nil {
		t.Fatalf("parse release.yml: %v", err)
	}

	if !slices.Contains(wf.On.Push.Tags, "v*") {
		t.Fatalf("release workflow on.push.tags = %v, want it to include \"v*\"", wf.On.Push.Tags)
	}

	if wf.On.WorkflowDispatch == nil {
		t.Fatal("release workflow should also keep the manual workflow_dispatch trigger")
	}
}

func TestGitHubReusableScanWorkflowRequiresExplicitExistingReleaseTag(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", ".github", "workflows", "packmon-scan.yml")
	data, err := os.ReadFile(path) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read packmon-scan.yml: %v", err)
	}

	var wf struct {
		On struct {
			WorkflowCall struct {
				Inputs map[string]struct {
					Description string `yaml:"description"`
					Required    bool   `yaml:"required"`
					Default     any    `yaml:"default"`
				} `yaml:"inputs"`
			} `yaml:"workflow_call"`
		} `yaml:"on"`
	}
	if err := yaml.Unmarshal(data, &wf); err != nil {
		t.Fatalf("parse packmon-scan.yml: %v", err)
	}

	input, ok := wf.On.WorkflowCall.Inputs["packmon_version"]
	if !ok {
		t.Fatal("packmon-scan.yml must define packmon_version input")
	}
	if !input.Required {
		t.Fatal("packmon_version must be required because this repository currently has no supported default release tag")
	}
	if input.Default != nil {
		t.Fatalf("packmon_version default = %#v, want no default non-existent release tag", input.Default)
	}
	for _, forbidden := range []string{"v0.5.0", "releases/latest/download"} {
		if strings.Contains(string(data), forbidden) {
			t.Fatalf("packmon-scan.yml must not reference non-existent or mutable release marker %q", forbidden)
		}
	}
	if !strings.Contains(strings.ToLower(input.Description), "existing") {
		t.Fatalf("packmon_version description = %q, want it to require an existing release tag", input.Description)
	}
}

func TestGitHubReusableScanWorkflowShellBlocksParseAsBash(t *testing.T) {
	t.Parallel()

	bashPath, ok := workflowShellBashPath()
	if !ok {
		t.Skip("bash is unavailable; skipping workflow shell syntax check")
	}
	if output, err := runBashSyntaxCheck(bashPath, ""); err != nil {
		t.Skipf("bash -n is unavailable at %q: %v%s", bashPath, err, formatCommandOutput(output))
	}

	path := filepath.Join("..", "..", ".github", "workflows", "packmon-scan.yml")
	data, err := os.ReadFile(path) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read packmon-scan.yml: %v", err)
	}

	var wf struct {
		Jobs map[string]struct {
			Steps []struct {
				Name string `yaml:"name"`
				Run  string `yaml:"run"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(data, &wf); err != nil {
		t.Fatalf("parse packmon-scan.yml: %v", err)
	}

	scan, ok := wf.Jobs["scan"]
	if !ok {
		t.Fatal("packmon-scan.yml must define jobs.scan")
	}

	checked := 0
	for i, step := range scan.Steps {
		if strings.TrimSpace(step.Run) == "" {
			continue
		}
		checked++
		name := step.Name
		if name == "" {
			name = "step " + strconv.Itoa(i+1)
		}
		if output, err := runBashSyntaxCheck(bashPath, step.Run); err != nil {
			t.Fatalf("jobs.scan %q run block is not valid bash: %v%s", name, err, formatCommandOutput(output))
		}
	}
	if checked == 0 {
		t.Fatal("packmon-scan.yml jobs.scan must include at least one shell run block")
	}
}

func TestGitHubReusableScanWorkflowVerifiesReleaseChecksum(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", ".github", "workflows", "packmon-scan.yml")
	data, err := os.ReadFile(path) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read packmon-scan.yml: %v", err)
	}
	text := string(data)
	for _, want := range []string{
		"set -euo pipefail",
		`BINARY_NAME="packmon-linux-${ARCH}"`,
		`CHECKSUM_URL="${BINARY_BASE_URL}/checksums.txt"`,
		`curl ${CURL_FLAGS} "${BINARY_URL}" -o "/tmp/${BINARY_NAME}"`,
		`curl ${CURL_FLAGS} "${CHECKSUM_URL}" -o /tmp/checksums.txt`,
		`sha256sum -c "${BINARY_NAME}.sha256"`,
		`sudo install -m 0755 "/tmp/${BINARY_NAME}" /usr/local/bin/packmon`,
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("packmon-scan.yml missing %q", want)
		}
	}
	assertSubstringOrder(t, text, `sha256sum -c "${BINARY_NAME}.sha256"`, `sudo install -m 0755 "/tmp/${BINARY_NAME}" /usr/local/bin/packmon`)
	assertSubstringOrder(t, text, `gh attestation verify "/tmp/${BINARY_NAME}"`, `sudo install -m 0755 "/tmp/${BINARY_NAME}" /usr/local/bin/packmon`)
}

func TestGitHubReusableScanWorkflowSupportsBinaryMirror(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", ".github", "workflows", "packmon-scan.yml")
	data, err := os.ReadFile(path) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read packmon-scan.yml: %v", err)
	}

	var wf struct {
		On struct {
			WorkflowCall struct {
				Inputs map[string]struct {
					Description string `yaml:"description"`
					Required    bool   `yaml:"required"`
					Default     any    `yaml:"default"`
					Type        string `yaml:"type"`
				} `yaml:"inputs"`
			} `yaml:"workflow_call"`
		} `yaml:"on"`
	}
	if err := yaml.Unmarshal(data, &wf); err != nil {
		t.Fatalf("parse packmon-scan.yml: %v", err)
	}

	input, ok := wf.On.WorkflowCall.Inputs["binary_mirror"]
	if !ok {
		t.Fatal("packmon-scan.yml must define binary_mirror input")
	}
	if input.Required {
		t.Fatal("binary_mirror must be optional")
	}
	if got, ok := input.Default.(string); !ok || got != "" {
		t.Fatalf("binary_mirror default = %#v, want empty string", input.Default)
	}
	if input.Type != "string" {
		t.Fatalf("binary_mirror type = %q, want string", input.Type)
	}
	if !strings.Contains(strings.ToLower(input.Description), "mirror") {
		t.Fatalf("binary_mirror description = %q, want mirror wording", input.Description)
	}

	text := string(data)
	for _, want := range []string{
		`PACKMON_BINARY_MIRROR: ${{ inputs.binary_mirror }}`,
		`DEFAULT_BINARY_BASE_URL="https://github.com/8linkz-sec/packmon/releases/download/${PACKMON_VERSION}"`,
		`BINARY_BASE_URL="${PACKMON_BINARY_MIRROR:-${DEFAULT_BINARY_BASE_URL}}"`,
		`BINARY_BASE_URL="${BINARY_BASE_URL%/}"`,
		`BINARY_URL="${BINARY_BASE_URL}/${BINARY_NAME}"`,
		`CHECKSUM_URL="${BINARY_BASE_URL}/checksums.txt"`,
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("packmon-scan.yml missing binary mirror marker %q", want)
		}
	}
}

func TestGitHubReusableScanWorkflowUsesBoundedCurlDownloads(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", ".github", "workflows", "packmon-scan.yml")
	data, err := os.ReadFile(path) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read packmon-scan.yml: %v", err)
	}
	text := string(data)
	for _, want := range []string{
		`CURL_FLAGS="--fail --show-error --location --retry 3 --retry-delay 2 --retry-connrefused --connect-timeout 10 --max-time 120"`,
		`curl ${CURL_FLAGS} "${BINARY_URL}" -o "/tmp/${BINARY_NAME}"`,
		`curl ${CURL_FLAGS} "${CHECKSUM_URL}" -o /tmp/checksums.txt`,
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("packmon-scan.yml missing bounded curl marker %q", want)
		}
	}
}

func TestGitHubReusableScanWorkflowPreservesScanArtifactContract(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", ".github", "workflows", "packmon-scan.yml")
	data, err := os.ReadFile(path) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read packmon-scan.yml: %v", err)
	}
	text := string(data)
	for _, want := range []string{
		`artifact_retention_days:`,
		`retention-days: ${{ inputs.artifact_retention_days }}`,
		`packmon scan \`,
		`--mode remote`,
		`--output-json /tmp/results.json`,
		`--output-sarif /tmp/results.sarif`,
		`--output-junit /tmp/results.xml`,
		`echo "exit_code=${EXIT_CODE}" >> "$GITHUB_OUTPUT"`,
		`if [ "${EXIT_CODE}" = "3" ]; then`,
		`EXIT_CODE=0`,
		`name: packmon-results`,
		`/tmp/results.json`,
		`/tmp/results.sarif`,
		`/tmp/results.xml`,
		`github/codeql-action/upload-sarif@`,
		`sarif_file: /tmp/packmon-results/results.sarif`,
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("packmon-scan.yml missing reusable scan contract marker %q", want)
		}
	}
}

func TestGitHubReusableScanWorkflowCommentsAllFindingTypes(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", ".github", "workflows", "packmon-scan.yml")
	data, err := os.ReadFile(path) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read packmon-scan.yml: %v", err)
	}
	text := string(data)
	for _, want := range []string{
		"f.type === 'vulnerability'",
		"f.type === 'malicious'",
		"f.type === 'supply_chain_risk'",
		"f.type === 'lifecycle'",
		"renderFindingSection(",
		"'Supply Chain Risk Findings'",
		"'Lifecycle Findings'",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("packmon-scan.yml missing PR comment marker %q", want)
		}
	}
}

func TestGitHubReusableScanWorkflowSurfacesDegradedFeedHealth(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", ".github", "workflows", "packmon-scan.yml")
	data, err := os.ReadFile(path) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read packmon-scan.yml: %v", err)
	}
	text := string(data)
	for _, want := range []string{
		"feed_status",
		"db_stale",
		"db_age_days",
		"::warning::Packmon scan coverage degraded",
		"$GITHUB_STEP_SUMMARY",
		"Coverage warning",
		"results.db_stale === true",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("packmon-scan.yml missing degraded feed marker %q", want)
		}
	}
}

func TestGitHubReusableScanWorkflowExplainsFailOnNoneScope(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", ".github", "workflows", "packmon-scan.yml")
	data, err := os.ReadFile(path) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read packmon-scan.yml: %v", err)
	}
	text := string(data)
	for _, want := range []string{
		"NONE disables vulnerability blocking only",
		"malicious and active supply-chain risk findings still block",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("packmon-scan.yml missing fail_on NONE scope text %q", want)
		}
	}
}

func assertSubstringOrder(t *testing.T, text, before, after string) {
	t.Helper()

	beforeIndex := strings.Index(text, before)
	if beforeIndex == -1 {
		t.Fatalf("missing ordered marker %q", before)
	}
	afterIndex := strings.Index(text, after)
	if afterIndex == -1 {
		t.Fatalf("missing ordered marker %q", after)
	}
	if beforeIndex > afterIndex {
		t.Fatalf("marker %q must appear before %q", before, after)
	}
}

func workflowShellBashPath() (string, bool) {
	if runtime.GOOS == "windows" {
		for _, base := range []string{
			os.Getenv("ProgramFiles"),
			os.Getenv("ProgramFiles(x86)"),
		} {
			if base == "" {
				continue
			}
			for _, rel := range []string{
				filepath.Join("Git", "bin", "bash.exe"),
				filepath.Join("Git", "usr", "bin", "bash.exe"),
			} {
				path := filepath.Join(base, rel)
				if info, err := os.Stat(path); err == nil && !info.IsDir() {
					return path, true
				}
			}
		}
	}

	path, err := exec.LookPath("bash")
	if err != nil {
		return "", false
	}
	return path, true
}

func runBashSyntaxCheck(bashPath, script string) ([]byte, error) {
	cmd := exec.Command(bashPath, "-n") //nolint:gosec // test invokes discovered local bash without user input.
	cmd.Stdin = strings.NewReader(script)
	return cmd.CombinedOutput()
}

func formatCommandOutput(output []byte) string {
	if len(output) == 0 {
		return ""
	}
	return "\n" + strings.TrimRight(string(output), "\r\n")
}
