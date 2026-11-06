//go:build integration

package integration

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const n8nMetricsFixtureBody = "packmon_test_metric 1"

type n8nMetricsRuntimeResources struct {
	network    string
	containers []string
}

func TestN8NWeeklyMetricsRuntime(t *testing.T) {
	if _, err := n8nDockerCommand(30*time.Second, "version"); err != nil {
		t.Fatalf("Docker prerequisite unavailable: %v", err)
	}
	contract := readN8NDockerRuntimeContract(t)
	requireN8NDockerPrerequisites(t, contract)
	fixtureRoot := createN8NRuntimeFixtures(t)
	network := "packmon-n8n-metrics-" + randomN8NSuffix(t)
	resources := &n8nMetricsRuntimeResources{network: network}
	t.Cleanup(func() {
		assertN8NMetricsResourcesAbsent(t, resources)
	})
	if output, err := n8nDockerCommand(30*time.Second, "network", "create", "--internal", network); err != nil {
		t.Fatalf("create isolated n8n metrics network: %v: %s", err, n8nRuntimeDiagnostic(output, fixtureRoot))
	}
	t.Cleanup(func() {
		removeN8NMetricsNetwork(t, network)
	})
	internal, err := n8nDockerCommand(30*time.Second, "network", "inspect", network, "--format", "{{.Internal}}")
	if err != nil {
		t.Fatalf("inspect isolated n8n metrics network: %v: %s", err, n8nRuntimeDiagnostic(internal, fixtureRoot))
	}
	if got := strings.TrimSpace(internal); got != "true" {
		t.Fatalf("n8n metrics network Internal = %q, want true", got)
	}

	endpoint := "packmon-metrics-" + randomN8NSuffix(t)
	startN8NMetricsEndpoint(t, contract, resources, endpoint)

	t.Run("configured URL fetches metrics", func(t *testing.T) {
		workflowID := "packmonMetricsSuccess" + randomN8NSuffix(t)
		workflow := filepath.Join(fixtureRoot, "metrics-success", "workflow.json")
		writeN8NWeeklyMetricsWorkflow(t, workflow, workflowID, "http://"+endpoint+":8080/metrics")
		output, err := runN8NWeeklyMetricsScenario(t, contract, resources, fixtureRoot, workflow, workflowID)
		if err != nil {
			t.Fatalf("configured weekly metrics workflow failed: %v\n%s", err, n8nRuntimeDiagnostic(output, fixtureRoot))
		}
		if !strings.Contains(output, n8nMetricsFixtureBody) {
			t.Fatalf("configured weekly metrics output is missing the endpoint body:\n%s", n8nRuntimeDiagnostic(output, fixtureRoot))
		}
	})

	t.Run("empty URL fails visibly", func(t *testing.T) {
		workflowID := "packmonMetricsMissing" + randomN8NSuffix(t)
		workflow := filepath.Join(fixtureRoot, "metrics-missing", "workflow.json")
		writeN8NWeeklyMetricsWorkflow(t, workflow, workflowID, "")
		output, err := runN8NWeeklyMetricsScenario(t, contract, resources, fixtureRoot, workflow, workflowID)
		if err == nil {
			t.Fatalf("empty weekly metrics URL unexpectedly succeeded:\n%s", n8nRuntimeDiagnostic(output, fixtureRoot))
		}
		if !strings.Contains(output, "URL parameter cannot be empty") {
			t.Fatalf("empty weekly metrics URL failed for the wrong reason: %v\n%s", err, n8nRuntimeDiagnostic(output, fixtureRoot))
		}
		assertN8NMetricsFailureHasNoEnvironmentDependency(t, output, fixtureRoot)
	})

	t.Run("unreachable URL fails visibly", func(t *testing.T) {
		workflowID := "packmonMetricsUnreachable" + randomN8NSuffix(t)
		workflow := filepath.Join(fixtureRoot, "metrics-unreachable", "workflow.json")
		const unreachableHost = "packmon-metrics-unreachable"
		writeN8NWeeklyMetricsWorkflow(t, workflow, workflowID, "http://"+unreachableHost+":8080/metrics")
		output, err := runN8NWeeklyMetricsScenario(t, contract, resources, fixtureRoot, workflow, workflowID)
		if err == nil {
			t.Fatalf("unreachable weekly metrics URL unexpectedly succeeded:\n%s", n8nRuntimeDiagnostic(output, fixtureRoot))
		}
		if !strings.Contains(output, unreachableHost) {
			t.Fatalf("unreachable weekly metrics URL failed without identifying its configured host: %v\n%s", err, n8nRuntimeDiagnostic(output, fixtureRoot))
		}
		assertN8NMetricsFailureHasNoEnvironmentDependency(t, output, fixtureRoot)
	})
}

func startN8NMetricsEndpoint(t *testing.T, contract n8nDockerRuntimeContract, resources *n8nMetricsRuntimeResources, name string) {
	t.Helper()
	resources.containers = append(resources.containers, name)
	t.Cleanup(func() {
		removeN8NMetricsContainer(t, name, false)
	})
	script := `const http=require('http');http.createServer((request,response)=>{if(request.url!=='/metrics'){response.statusCode=404;response.end('not found');return}response.setHeader('Content-Type','text/plain');response.end('` + n8nMetricsFixtureBody + `\n')}).listen(8080,'0.0.0.0',()=>console.log('READY'))`
	args := []string{
		"run", "-d", "--pull=never", "--network", resources.network, "--name", name,
		"--entrypoint=/usr/local/bin/node", contract.Image, "-e", script,
	}
	if output, err := n8nDockerCommand(30*time.Second, args...); err != nil {
		t.Fatalf("start isolated metrics endpoint: %v: %s", err, n8nRuntimeDiagnostic(output, ""))
	}

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		output, err := n8nDockerCommand(10*time.Second, "logs", name)
		if err == nil && strings.Contains(output, "READY") {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	output, _ := n8nDockerCommand(10*time.Second, "logs", name)
	t.Fatalf("isolated metrics endpoint did not become ready: %s", n8nRuntimeDiagnostic(output, ""))
}

func writeN8NWeeklyMetricsWorkflow(t *testing.T, path, workflowID, metricsURL string) {
	t.Helper()
	source := filepath.Join("..", "..", "deploy", "n8n", "weekly-maintenance.json")
	data, err := os.ReadFile(source) //nolint:gosec // repository-owned workflow template
	if err != nil {
		t.Fatalf("read weekly maintenance workflow: %v", err)
	}
	var workflow map[string]any
	if err := json.Unmarshal(data, &workflow); err != nil {
		t.Fatalf("parse weekly maintenance workflow: %v", err)
	}
	workflow["id"] = workflowID
	nodes, ok := workflow["nodes"].([]any)
	if !ok || len(nodes) != 3 {
		t.Fatalf("weekly maintenance nodes = %#v, want exact trigger/configuration/request chain", workflow["nodes"])
	}
	trigger, ok := nodes[0].(map[string]any)
	if !ok || trigger["name"] != "Weekly Trigger" || trigger["type"] != "n8n-nodes-base.scheduleTrigger" {
		t.Fatalf("weekly maintenance first node = %#v, want Weekly Trigger", nodes[0])
	}
	trigger["type"] = "n8n-nodes-base.executeWorkflowTrigger"
	trigger["typeVersion"] = float64(1)
	trigger["parameters"] = map[string]any{}

	configuration, ok := nodes[1].(map[string]any)
	if !ok || configuration["name"] != "Configure Metrics URL" || configuration["type"] != "n8n-nodes-base.set" {
		t.Fatalf("weekly maintenance second node = %#v, want Configure Metrics URL", nodes[1])
	}
	parameters := configuration["parameters"].(map[string]any)
	assignmentContainer := parameters["assignments"].(map[string]any)
	assignments := assignmentContainer["assignments"].([]any)
	if len(assignments) != 1 {
		t.Fatalf("Configure Metrics URL assignments = %#v, want exactly one", assignments)
	}
	assignment := assignments[0].(map[string]any)
	assignment["value"] = metricsURL
	writeN8NRuntimeWorkflow(t, path, workflow)
}

func runN8NWeeklyMetricsScenario(t *testing.T, contract n8nDockerRuntimeContract, resources *n8nMetricsRuntimeResources, fixtureRoot, workflow, workflowID string) (string, error) {
	t.Helper()
	state := t.TempDir()
	if err := os.Chmod(state, 0o777); err != nil { //nolint:gosec // disposable bind mount must be writable by the image's non-root UID
		t.Fatalf("make isolated n8n metrics state writable by its container user: %v", err)
	}
	name := "packmon-n8n-metrics-run-" + randomN8NSuffix(t)
	resources.containers = append(resources.containers, name)
	t.Cleanup(func() {
		removeN8NMetricsContainer(t, name, true)
	})

	fixtureMount := "type=bind,source=" + filepath.Clean(fixtureRoot) + ",target=/fixtures,readonly"
	stateMount := "type=bind,source=" + filepath.Clean(state) + ",target=/home/node/.n8n"
	containerWorkflow := "/fixtures/" + filepath.ToSlash(strings.TrimPrefix(filepath.Clean(workflow), filepath.Clean(fixtureRoot)+string(filepath.Separator)))
	command := "n8n import:workflow --input=" + containerWorkflow + " && " +
		"n8n execute --id=" + workflowID + " --rawOutput"
	args := []string{
		"run", "--rm", "--pull=never", "--network", resources.network, "--name", name,
		"--mount", fixtureMount, "--mount", stateMount,
		"--env", "N8N_DIAGNOSTICS_ENABLED=false",
		"--env", "N8N_PERSONALIZATION_ENABLED=false",
		"--env", "N8N_VERSION_NOTIFICATIONS_ENABLED=false",
	}
	for _, key := range []string{"NODES_EXCLUDE", "N8N_BLOCK_ENV_ACCESS_IN_NODE"} {
		args = append(args, "--env", key+"="+contract.Environment[key])
	}
	args = append(args, "--entrypoint=/bin/sh", contract.Image, "-ec", command)
	return n8nDockerCommand(n8nCommandRuntimeTimeout, args...)
}

func removeN8NMetricsContainer(t *testing.T, name string, allowAlreadyRemoved bool) {
	t.Helper()
	output, err := n8nDockerCommand(30*time.Second, "rm", "-f", name)
	if err == nil {
		return
	}
	trimmed := strings.TrimSpace(output)
	wantAlreadyRemoved := "Error response from daemon: No such container: " + name
	if allowAlreadyRemoved && trimmed == wantAlreadyRemoved {
		return
	}
	t.Errorf("remove n8n metrics container %q: %v: %s", name, err, n8nRuntimeDiagnostic(output, ""))
}

func removeN8NMetricsNetwork(t *testing.T, name string) {
	t.Helper()
	output, err := n8nDockerCommand(30*time.Second, "network", "rm", name)
	if err != nil {
		t.Errorf("remove n8n metrics network %q: %v: %s", name, err, n8nRuntimeDiagnostic(output, ""))
	}
}

func assertN8NMetricsResourcesAbsent(t *testing.T, resources *n8nMetricsRuntimeResources) {
	t.Helper()
	containerOutput, err := n8nDockerCommand(30*time.Second, "ps", "-a", "--format", "{{.Names}}")
	if err != nil {
		t.Errorf("inventory Docker containers after n8n metrics cleanup: %v: %s", err, n8nRuntimeDiagnostic(containerOutput, ""))
	} else {
		present := n8nMetricsInventoryNames(containerOutput)
		for _, name := range resources.containers {
			if _, exists := present[name]; exists {
				t.Errorf("n8n metrics container %q remains after cleanup", name)
			}
		}
	}

	networkOutput, err := n8nDockerCommand(30*time.Second, "network", "ls", "--format", "{{.Name}}")
	if err != nil {
		t.Errorf("inventory Docker networks after n8n metrics cleanup: %v: %s", err, n8nRuntimeDiagnostic(networkOutput, ""))
	} else if _, exists := n8nMetricsInventoryNames(networkOutput)[resources.network]; exists {
		t.Errorf("n8n metrics network %q remains after cleanup", resources.network)
	}
}

func n8nMetricsInventoryNames(output string) map[string]struct{} {
	names := make(map[string]struct{})
	for _, name := range strings.Fields(output) {
		names[name] = struct{}{}
	}
	return names
}

func assertN8NMetricsFailureHasNoEnvironmentDependency(t *testing.T, output, fixtureRoot string) {
	t.Helper()
	if strings.Contains(output, "access to env vars denied") || strings.Contains(output, "PACKMON_METRICS_URL") {
		t.Fatalf("weekly metrics execution still depends on environment access:\n%s", n8nRuntimeDiagnostic(output, fixtureRoot))
	}
	if strings.Contains(output, n8nMetricsFixtureBody) {
		t.Fatalf("failed weekly metrics execution unexpectedly returned the success body:\n%s", n8nRuntimeDiagnostic(output, fixtureRoot))
	}
}
