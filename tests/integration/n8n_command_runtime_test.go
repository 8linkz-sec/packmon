//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

const (
	n8nCommandRuntimeVersion = "2.46.6"
	n8nCommandRuntimeTimeout = 4 * time.Minute
)

type n8nDockerRuntimeContract struct {
	Image       string            `json:"image"`
	Environment map[string]string `json:"environment"`
}

func TestN8NCommandRuntimeDockerContract(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatalf("docker not available; tagged n8n runtime test requires Docker: %v", err)
	}
	contract := readN8NDockerRuntimeContract(t)
	requireN8NDockerPrerequisites(t, contract)
	fixtureRoot := createN8NRuntimeFixtures(t)

	t.Run("default policy rejects Execute Command", func(t *testing.T) {
		workflowID := "packmonDefault" + randomN8NSuffix(t)
		workflow := filepath.Join(fixtureRoot, "default", "workflow.json")
		writeN8NDailyRuntimeWorkflow(t, workflow, workflowID)
		output, err := runN8NWorkflowScenario(t, contract, fixtureRoot, workflow, workflowID, nil)
		if err == nil {
			t.Fatalf("default n8n policy executed an Execute Command workflow:\n%s", n8nRuntimeDiagnostic(output, fixtureRoot))
		}
		if !strings.Contains(output, "Unrecognized node type: n8n-nodes-base.executeCommand") {
			t.Fatalf("default policy failed for the wrong reason: %v\n%s", err, n8nRuntimeDiagnostic(output, fixtureRoot))
		}
	})

	t.Run("supported policy executes daily sync", func(t *testing.T) {
		workflowID := "packmonSuccess" + randomN8NSuffix(t)
		workflow := filepath.Join(fixtureRoot, "success", "workflow.json")
		writeN8NDailyRuntimeWorkflow(t, workflow, workflowID)
		output, err := runN8NWorkflowScenario(t, contract, fixtureRoot, workflow, workflowID, contract.Environment)
		if err != nil {
			t.Fatalf("supported n8n command policy failed: %v\n%s", err, n8nRuntimeDiagnostic(output, fixtureRoot))
		}
		compactOutput := strings.NewReplacer(" ", "", "\t", "", "\r", "", "\n", "").Replace(output)
		for _, want := range []string{`"workflow":"daily-sync"`, `"status":"ok"`, `"finishedAt"`} {
			if !strings.Contains(compactOutput, want) {
				t.Fatalf("successful daily sync output is missing %s:\n%s", want, n8nRuntimeDiagnostic(output, fixtureRoot))
			}
		}
	})

	t.Run("exit 23 stops before Result", func(t *testing.T) {
		workflowID := "packmonFailure" + randomN8NSuffix(t)
		workflow := filepath.Join(fixtureRoot, "failure", "workflow.json")
		writeN8NDailyRuntimeWorkflow(t, workflow, workflowID)
		environment := cloneN8NRuntimeEnvironment(contract.Environment)
		environment["PACKMON_STUB_EXIT"] = "23"
		output, err := runN8NWorkflowScenario(t, contract, fixtureRoot, workflow, workflowID, environment)
		if err == nil {
			t.Fatalf("exit-23 Packmon stub unexpectedly reached a successful result:\n%s", n8nRuntimeDiagnostic(output, fixtureRoot))
		}
		if !strings.Contains(output, "Command failed with exit code 23") {
			t.Fatalf("exit-23 workflow failed for the wrong reason: %v\n%s", err, n8nRuntimeDiagnostic(output, fixtureRoot))
		}
		for _, forbidden := range []string{`"workflow":"daily-sync"`, `"status":"ok"`} {
			if strings.Contains(output, forbidden) {
				t.Fatalf("exit-23 workflow reached Result output %s:\n%s", forbidden, n8nRuntimeDiagnostic(output, fixtureRoot))
			}
		}
	})

	t.Run("supported policy keeps Local File Trigger disabled", func(t *testing.T) {
		workflowID := "packmonLocalFile" + randomN8NSuffix(t)
		workflow := filepath.Join(fixtureRoot, "local-file", "workflow.json")
		writeN8NLocalFileRuntimeWorkflow(t, workflow, workflowID)
		output, err := runN8NWorkflowScenario(t, contract, fixtureRoot, workflow, workflowID, contract.Environment)
		if err == nil {
			t.Fatalf("supported policy unexpectedly loaded Local File Trigger:\n%s", n8nRuntimeDiagnostic(output, fixtureRoot))
		}
		if !strings.Contains(output, "Unrecognized node type: n8n-nodes-base.localFileTrigger") {
			t.Fatalf("Local File Trigger failed for the wrong reason: %v\n%s", err, n8nRuntimeDiagnostic(output, fixtureRoot))
		}
	})
}

func readN8NDockerRuntimeContract(t *testing.T) n8nDockerRuntimeContract {
	t.Helper()
	path := filepath.Join("..", "..", "deploy", "n8n", "command-runtime.json")
	data, err := os.ReadFile(path) //nolint:gosec // repository-owned runtime contract
	if err != nil {
		t.Fatalf("read n8n command runtime contract: %v", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var contract n8nDockerRuntimeContract
	if err := decoder.Decode(&contract); err != nil {
		t.Fatalf("parse n8n command runtime contract: %v", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		t.Fatalf("n8n command runtime contract has trailing JSON: %v", err)
	}
	if contract.Image == "" || len(contract.Environment) != 2 ||
		contract.Environment["NODES_EXCLUDE"] != "[\"n8n-nodes-base.localFileTrigger\"]" ||
		contract.Environment["N8N_BLOCK_ENV_ACCESS_IN_NODE"] != "true" {
		t.Fatalf("n8n command runtime contract does not contain the reviewed image and narrow policy: %+v", contract)
	}
	return contract
}

func requireN8NDockerPrerequisites(t *testing.T, contract n8nDockerRuntimeContract) {
	t.Helper()
	output, err := n8nDockerCommand(n8nCommandRuntimeTimeout, "version", "--format", "{{.Server.Os}}")
	if err != nil {
		t.Fatalf("Docker prerequisite unavailable: %v: %s", err, n8nRuntimeDiagnostic(output, ""))
	}
	if got := strings.TrimSpace(output); got != "linux" {
		t.Fatalf("Docker engine OS = %q, want linux for the n8n image", got)
	}
	if output, err = n8nDockerCommand(n8nCommandRuntimeTimeout, "image", "inspect", contract.Image); err != nil {
		t.Fatalf("exact n8n image is not preloaded (pull it explicitly before this test): %v: %s", err, n8nRuntimeDiagnostic(output, ""))
	}

	base := []string{"run", "--rm", "--pull=never", "--network=none"}
	versionOutput, err := n8nDockerCommand(n8nCommandRuntimeTimeout, append(base, contract.Image, "--version")...)
	if err != nil {
		t.Fatalf("run exact n8n version: %v: %s", err, n8nRuntimeDiagnostic(versionOutput, ""))
	}
	if got := strings.TrimSpace(versionOutput); got != n8nCommandRuntimeVersion {
		t.Fatalf("exact n8n image version = %q, want %q", got, n8nCommandRuntimeVersion)
	}
	identityArgs := append(base, "--entrypoint=/bin/sh", contract.Image, "-ec", "id -u")
	identityOutput, err := n8nDockerCommand(n8nCommandRuntimeTimeout, identityArgs...)
	if err != nil {
		t.Fatalf("inspect n8n runtime identity: %v: %s", err, n8nRuntimeDiagnostic(identityOutput, ""))
	}
	if got := strings.TrimSpace(identityOutput); got == "" || got == "0" {
		t.Fatalf("n8n runtime UID = %q, want a non-root user", got)
	}
}

func createN8NRuntimeFixtures(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatalf("make n8n fixture root container-readable: %v", err)
	}
	templates := filepath.Join(root, "templates")
	binDir := filepath.Join(root, "bin")
	for _, dir := range []string{templates, binDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("create n8n fixture directory: %v", err)
		}
	}
	for _, name := range []string{"daily-sync.json", "on-demand-scan.json", "weekly-maintenance.json"} {
		source := filepath.Join("..", "..", "deploy", "n8n", name)
		data, err := os.ReadFile(source) //nolint:gosec // repository-owned workflow template
		if err != nil {
			t.Fatalf("read %s: %v", source, err)
		}
		if err := os.WriteFile(filepath.Join(templates, name), data, 0o644); err != nil {
			t.Fatalf("copy %s into isolated n8n fixture: %v", name, err)
		}
	}
	stub := "#!/bin/sh\nexit \"${PACKMON_STUB_EXIT:-0}\"\n"
	if err := os.WriteFile(filepath.Join(binDir, "packmon"), []byte(stub), 0o755); err != nil { //nolint:gosec // executable test stub
		t.Fatalf("write Packmon command stub: %v", err)
	}
	return root
}

func writeN8NDailyRuntimeWorkflow(t *testing.T, path, workflowID string) {
	t.Helper()
	source := filepath.Join("..", "..", "deploy", "n8n", "daily-sync.json")
	data, err := os.ReadFile(source) //nolint:gosec // repository-owned workflow template
	if err != nil {
		t.Fatalf("read daily-sync workflow: %v", err)
	}
	var workflow map[string]any
	if err := json.Unmarshal(data, &workflow); err != nil {
		t.Fatalf("parse daily-sync workflow: %v", err)
	}
	workflow["id"] = workflowID
	nodes, ok := workflow["nodes"].([]any)
	if !ok || len(nodes) == 0 {
		t.Fatalf("daily-sync nodes = %#v, want a trigger", workflow["nodes"])
	}
	trigger, ok := nodes[0].(map[string]any)
	if !ok || trigger["name"] != "Daily Trigger" || trigger["type"] != "n8n-nodes-base.scheduleTrigger" {
		t.Fatalf("daily-sync first node = %#v, want Daily Trigger", nodes[0])
	}
	trigger["type"] = "n8n-nodes-base.executeWorkflowTrigger"
	trigger["typeVersion"] = float64(1)
	trigger["parameters"] = map[string]any{}
	writeN8NRuntimeWorkflow(t, path, workflow)
}

func writeN8NLocalFileRuntimeWorkflow(t *testing.T, path, workflowID string) {
	t.Helper()
	workflow := map[string]any{
		"id":       workflowID,
		"name":     "Packmon Local File Policy Probe",
		"active":   false,
		"settings": map[string]any{},
		"nodes": []any{
			map[string]any{
				"id":          "execute-trigger",
				"name":        "Execute Trigger",
				"type":        "n8n-nodes-base.executeWorkflowTrigger",
				"typeVersion": float64(1),
				"position":    []any{float64(260), float64(260)},
				"parameters":  map[string]any{},
			},
			map[string]any{
				"id":          "local-file-trigger",
				"name":        "Local File Trigger",
				"type":        "n8n-nodes-base.localFileTrigger",
				"typeVersion": float64(1),
				"position":    []any{float64(540), float64(260)},
				"parameters":  map[string]any{"path": "/fixtures/never-created"},
			},
		},
		"connections": map[string]any{
			"Execute Trigger": map[string]any{
				"main": []any{[]any{map[string]any{
					"node": "Local File Trigger", "type": "main", "index": float64(0),
				}}},
			},
		},
	}
	writeN8NRuntimeWorkflow(t, path, workflow)
}

func writeN8NRuntimeWorkflow(t *testing.T, path string, workflow map[string]any) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("create scenario fixture directory: %v", err)
	}
	data, err := json.Marshal(workflow)
	if err != nil {
		t.Fatalf("marshal scenario workflow: %v", err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		t.Fatalf("write scenario workflow: %v", err)
	}
}

func runN8NWorkflowScenario(t *testing.T, contract n8nDockerRuntimeContract, fixtureRoot, workflow, workflowID string, policy map[string]string) (string, error) {
	t.Helper()
	state := t.TempDir()
	if err := os.Chmod(state, 0o777); err != nil { //nolint:gosec // disposable bind mount must be writable by the image's non-root UID
		t.Fatalf("make isolated n8n state writable by its container user: %v", err)
	}
	name := "packmon-n8n-" + randomN8NSuffix(t)
	t.Cleanup(func() {
		_, _ = n8nDockerCommand(30*time.Second, "rm", "-f", name)
	})

	fixtureMount := "type=bind,source=" + filepath.Clean(fixtureRoot) + ",target=/fixtures,readonly"
	stateMount := "type=bind,source=" + filepath.Clean(state) + ",target=/home/node/.n8n"
	containerWorkflow := "/fixtures/" + filepath.ToSlash(strings.TrimPrefix(filepath.Clean(workflow), filepath.Clean(fixtureRoot)+string(filepath.Separator)))
	command := "n8n import:workflow --separate --input=/fixtures/templates && " +
		"n8n import:workflow --input=" + containerWorkflow + " && " +
		"n8n execute --id=" + workflowID + " --rawOutput"
	args := []string{
		"run", "--rm", "--pull=never", "--network=none", "--name", name,
		"--mount", fixtureMount, "--mount", stateMount,
		"--env", "N8N_DIAGNOSTICS_ENABLED=false",
		"--env", "N8N_PERSONALIZATION_ENABLED=false",
		"--env", "N8N_VERSION_NOTIFICATIONS_ENABLED=false",
		"--env", "PATH=/fixtures/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
	}
	if _, explicitlySet := policy["N8N_BLOCK_ENV_ACCESS_IN_NODE"]; !explicitlySet {
		args = append(args, "--env", "N8N_BLOCK_ENV_ACCESS_IN_NODE=true")
	}
	for _, key := range []string{"NODES_EXCLUDE", "N8N_BLOCK_ENV_ACCESS_IN_NODE", "PACKMON_STUB_EXIT"} {
		if value, ok := policy[key]; ok {
			args = append(args, "--env", key+"="+value)
		}
	}
	args = append(args, "--entrypoint=/bin/sh", contract.Image, "-ec", command)
	output, err := n8nDockerCommand(n8nCommandRuntimeTimeout, args...)
	return output, err
}

func randomN8NSuffix(t *testing.T) string {
	t.Helper()
	value := make([]byte, 6)
	if _, err := rand.Read(value); err != nil {
		t.Fatalf("generate n8n fixture suffix: %v", err)
	}
	return hex.EncodeToString(value)
}

func cloneN8NRuntimeEnvironment(environment map[string]string) map[string]string {
	cloned := make(map[string]string, len(environment)+1)
	for key, value := range environment {
		cloned[key] = value
	}
	return cloned
}

func n8nDockerCommand(timeout time.Duration, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", args...) // #nosec G204 -- fixed Docker executable with test-controlled arguments
	cmd.Env = n8nDockerClientEnvironment()
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return string(output), fmt.Errorf("docker %s timed out after %s", args[0], timeout)
	}
	return string(output), err
}

func n8nDockerClientEnvironment() []string {
	allowed := map[string]struct{}{
		"PATH": {}, "PATHEXT": {}, "SYSTEMROOT": {}, "WINDIR": {}, "TEMP": {}, "TMP": {},
		"HOME": {}, "USERPROFILE": {}, "HOMEDRIVE": {}, "HOMEPATH": {},
		"DOCKER_HOST": {}, "DOCKER_CONTEXT": {}, "DOCKER_CERT_PATH": {}, "DOCKER_TLS_VERIFY": {},
	}
	var environment []string
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if _, ok := allowed[strings.ToUpper(key)]; ok {
			environment = append(environment, entry)
		}
	}
	return environment
}

func n8nRuntimeDiagnostic(output, fixtureRoot string) string {
	if fixtureRoot != "" {
		output = strings.ReplaceAll(output, fixtureRoot, "[FIXTURE]")
		if runtime.GOOS == "windows" {
			output = strings.ReplaceAll(output, filepath.ToSlash(fixtureRoot), "[FIXTURE]")
		}
	}
	const limit = 4000
	if len(output) > limit {
		return "[truncated]..." + output[len(output)-limit:]
	}
	return output
}
