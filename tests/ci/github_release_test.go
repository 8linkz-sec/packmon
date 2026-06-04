package ci

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
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
		`curl -sfL "${BINARY_URL}" -o "/tmp/${BINARY_NAME}"`,
		`curl -sfL "${CHECKSUM_URL}" -o /tmp/checksums.txt`,
		`sha256sum -c "${BINARY_NAME}.sha256"`,
		`sudo install -m 0755 "/tmp/${BINARY_NAME}" /usr/local/bin/packmon`,
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("packmon-scan.yml missing %q", want)
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
		"### Supply Chain Risk Findings",
		"### Lifecycle Findings",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("packmon-scan.yml missing PR comment marker %q", want)
		}
	}
}
