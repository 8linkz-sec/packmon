//go:build integration

package integration

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

const (
	n8nWebhookHeaderName  = "X-Packmon-N8N-Test-Secret"
	n8nWebhookHeaderValue = "packmon-safe-runtime-fixture"
)

type n8nOnDemandRuntimeResources struct {
	network    string
	containers []string
}

type n8nWebhookResponse struct {
	Status int    `json:"status"`
	Body   string `json:"body"`
}

func TestN8NOnDemandWebhookRuntime(t *testing.T) {
	if _, err := n8nDockerCommand(30*time.Second, "version"); err != nil {
		t.Fatalf("Docker prerequisite unavailable: %v", err)
	}
	contract := readN8NDockerRuntimeContract(t)
	requireN8NDockerPrerequisites(t, contract)
	fixtureRoot := createN8NOnDemandRuntimeFixtures(t)
	network := "packmon-n8n-on-demand-" + randomN8NSuffix(t)
	resources := &n8nOnDemandRuntimeResources{network: network}
	t.Cleanup(func() {
		assertN8NOnDemandResourcesAbsent(t, resources)
	})
	if output, err := n8nDockerCommand(30*time.Second, "network", "create", "--internal", network); err != nil {
		t.Fatalf("create isolated n8n on-demand network: %v: %s", err, n8nRuntimeDiagnostic(output, fixtureRoot))
	}
	t.Cleanup(func() {
		removeN8NOnDemandNetwork(t, network)
	})
	client := "packmon-n8n-on-demand-client-" + randomN8NSuffix(t)
	startN8NOnDemandHTTPClient(t, contract, resources, client)

	successServer := "packmon-n8n-on-demand-success-" + randomN8NSuffix(t)
	successState := startN8NOnDemandServer(t, contract, resources, fixtureRoot, successServer, client)

	t.Run("unauthenticated request does not invoke helper", func(t *testing.T) {
		response := requestN8NOnDemandWebhook(t, client, successServer, "")
		if response.Status != 401 && response.Status != 403 {
			t.Fatalf("unauthenticated webhook status = %d, want an authentication rejection; body = %q", response.Status, response.Body)
		}
		assertN8NHelperInvocationCount(t, successState, 0)
	})

	t.Run("authenticated successful scan returns completed JSON", func(t *testing.T) {
		response := requestN8NOnDemandWebhook(t, client, successServer, n8nWebhookHeaderValue)
		if response.Status != 200 {
			t.Fatalf("authenticated webhook status = %d, want 200; body = %q", response.Status, response.Body)
		}
		var body struct {
			Workflow string `json:"workflow"`
			Status   string `json:"status"`
		}
		if err := json.Unmarshal([]byte(response.Body), &body); err != nil {
			t.Fatalf("authenticated webhook body is not parseable JSON: %v; body = %q", err, response.Body)
		}
		if body.Workflow != "on-demand-scan" || body.Status != "completed" {
			t.Fatalf("authenticated webhook body = %+v, want completed on-demand scan", body)
		}
		assertN8NHelperInvocationCount(t, successState, 1)
	})

	t.Run("helper failure cannot return success", func(t *testing.T) {
		if err := os.WriteFile(filepath.Join(successState, "helper-exit"), []byte("23\n"), 0o644); err != nil { //nolint:gosec // non-secret fixture must be readable by the container UID
			t.Fatalf("configure Packmon helper failure fixture: %s", n8nOnDemandDiagnostic(err.Error(), "", successState))
		}
		response := requestN8NOnDemandWebhook(t, client, successServer, n8nWebhookHeaderValue)
		if response.Status >= 200 && response.Status < 300 {
			t.Fatalf("exit-23 helper returned successful HTTP status %d; body = %q", response.Status, response.Body)
		}
		if strings.Contains(response.Body, `"status":"completed"`) {
			t.Fatalf("exit-23 helper returned the completed response body: %q", response.Body)
		}
		assertN8NHelperInvocationCount(t, successState, 2)
	})
}

func TestN8NOnDemandDiagnosticRedactsHostPaths(t *testing.T) {
	fixtureRoot := filepath.Join(string(filepath.Separator), "private", "fixture-root")
	stateRoot := filepath.Join(string(filepath.Separator), "private", "state-root")
	fixtureError := (&os.PathError{Op: "open", Path: filepath.Join(fixtureRoot, "workflow.json"), Err: os.ErrPermission}).Error()
	stateError := (&os.PathError{Op: "write", Path: filepath.Join(stateRoot, "helper-exit"), Err: os.ErrPermission}).Error()
	input := fixtureError + " " + stateError + " slash=" + filepath.ToSlash(stateRoot) + " case=" + strings.ToUpper(filepath.ToSlash(fixtureRoot))
	got := n8nOnDemandDiagnostic(input, fixtureRoot, stateRoot)
	for _, forbidden := range []string{fixtureRoot, stateRoot, filepath.ToSlash(fixtureRoot), filepath.ToSlash(stateRoot), strings.ToUpper(filepath.ToSlash(fixtureRoot))} {
		if forbidden != "" && strings.Contains(got, forbidden) {
			t.Fatalf("diagnostic retained host path %q: %q", forbidden, got)
		}
	}
	for _, want := range []string{"[FIXTURE]", "[STATE]"} {
		if !strings.Contains(got, want) {
			t.Fatalf("diagnostic = %q, want redaction marker %q", got, want)
		}
	}
}

func createN8NOnDemandRuntimeFixtures(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0o755); err != nil { //nolint:gosec // disposable fixture must be traversable by the container UID
		t.Fatalf("make n8n on-demand fixture root container-readable: %s", n8nOnDemandDiagnostic(err.Error(), root))
	}

	workflowSource := filepath.Join("..", "..", "deploy", "n8n", "on-demand-scan.json")
	workflowData, err := os.ReadFile(workflowSource) //nolint:gosec // repository-owned workflow template
	if err != nil {
		t.Fatalf("read on-demand workflow: %v", err)
	}
	var workflow map[string]any
	if err := json.Unmarshal(workflowData, &workflow); err != nil {
		t.Fatalf("parse on-demand workflow: %v", err)
	}
	workflow["id"] = "packmonOnDemandRuntime"
	workflowData, err = json.Marshal(workflow)
	if err != nil {
		t.Fatalf("marshal on-demand workflow fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "workflow.json"), append(workflowData, '\n'), 0o644); err != nil { //nolint:gosec // fixture must be readable by the container UID
		t.Fatalf("write on-demand workflow fixture: %s", n8nOnDemandDiagnostic(err.Error(), root))
	}

	credential := []map[string]any{{
		"id":   "replace-with-packmon-webhook-header-auth",
		"name": "Packmon On-Demand Webhook Header Auth",
		"type": "httpHeaderAuth",
		"data": map[string]string{
			"name":  n8nWebhookHeaderName,
			"value": n8nWebhookHeaderValue,
		},
	}}
	credentialData, err := json.Marshal(credential)
	if err != nil {
		t.Fatalf("marshal safe n8n credential fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "credential.json"), append(credentialData, '\n'), 0o644); err != nil { //nolint:gosec // safe fixture must be readable by the container UID
		t.Fatalf("write safe n8n credential fixture: %s", n8nOnDemandDiagnostic(err.Error(), root))
	}

	helperSource := filepath.Join("..", "..", "deploy", "n8n", "on-demand-scan.sh")
	helperData, err := os.ReadFile(helperSource) //nolint:gosec // repository-owned helper
	if err != nil {
		t.Fatalf("read on-demand helper: %v", err)
	}
	helperDir := filepath.Join(root, "helper")
	if err := os.MkdirAll(helperDir, 0o755); err != nil { //nolint:gosec // disposable fixture must be traversable by the container UID
		t.Fatalf("create n8n on-demand helper fixture directory: %s", n8nOnDemandDiagnostic(err.Error(), root))
	}
	if err := os.WriteFile(filepath.Join(helperDir, "on-demand-scan.sh"), helperData, 0o644); err != nil { //nolint:gosec // repository helper must be readable by the container UID
		t.Fatalf("copy on-demand helper into fixture: %s", n8nOnDemandDiagnostic(err.Error(), root))
	}

	binDir := filepath.Join(root, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil { //nolint:gosec // disposable fixture must be traversable by the container UID
		t.Fatalf("create n8n on-demand binary fixture directory: %s", n8nOnDemandDiagnostic(err.Error(), root))
	}
	stub := "#!/bin/sh\nprintf 'invoked\\n' >> \"$PACKMON_STUB_RECORD\"\nexit_code=0\nif [ -f \"$PACKMON_STUB_EXIT_FILE\" ]; then read -r exit_code < \"$PACKMON_STUB_EXIT_FILE\"; fi\nexit \"$exit_code\"\n"
	if err := os.WriteFile(filepath.Join(binDir, "packmon"), []byte(stub), 0o755); err != nil { //nolint:gosec // executable test stub
		t.Fatalf("write Packmon command stub: %s", n8nOnDemandDiagnostic(err.Error(), root))
	}
	return root
}

func startN8NOnDemandHTTPClient(t *testing.T, contract n8nDockerRuntimeContract, resources *n8nOnDemandRuntimeResources, name string) {
	t.Helper()
	resources.containers = append(resources.containers, name)
	t.Cleanup(func() {
		removeN8NOnDemandContainer(t, name)
	})
	args := []string{
		"run", "-d", "--rm", "--pull=never", "--network", resources.network, "--name", name,
		"--entrypoint=/bin/sh", contract.Image, "-ec", "while :; do sleep 3600; done",
	}
	if output, err := n8nDockerCommand(30*time.Second, args...); err != nil {
		t.Fatalf("start isolated n8n on-demand HTTP client: %v: %s", err, n8nOnDemandDiagnostic(output))
	}
}

func startN8NOnDemandServer(t *testing.T, contract n8nDockerRuntimeContract, resources *n8nOnDemandRuntimeResources, fixtureRoot, name, client string) string {
	t.Helper()
	state := t.TempDir()
	if err := os.Chmod(state, 0o777); err != nil { //nolint:gosec // disposable bind mount must be writable by the image's non-root UID
		t.Fatalf("make isolated n8n on-demand state writable by its container user: %s", n8nOnDemandDiagnostic(err.Error(), "", state))
	}
	resources.containers = append(resources.containers, name)
	t.Cleanup(func() {
		removeN8NOnDemandContainer(t, name)
	})

	fixtureMount := "type=bind,source=" + filepath.Clean(fixtureRoot) + ",target=/fixtures,readonly"
	helperMount := "type=bind,source=" + filepath.Join(filepath.Clean(fixtureRoot), "helper") + ",target=/opt/packmon/n8n,readonly"
	stateMount := "type=bind,source=" + filepath.Clean(state) + ",target=/home/node/.n8n"
	command := "n8n import:credentials --input=/fixtures/credential.json && " +
		"n8n import:workflow --input=/fixtures/workflow.json && " +
		"n8n publish:workflow --id=packmonOnDemandRuntime && " +
		"n8n update:workflow --id=packmonOnDemandRuntime --active=true && " +
		"exec n8n start"
	args := []string{
		"run", "-d", "--pull=never", "--network", resources.network, "--name", name,
		"--mount", fixtureMount, "--mount", helperMount, "--mount", stateMount,
		"--env", "N8N_DIAGNOSTICS_ENABLED=false",
		"--env", "N8N_PERSONALIZATION_ENABLED=false",
		"--env", "N8N_VERSION_NOTIFICATIONS_ENABLED=false",
		"--env", "N8N_ENCRYPTION_KEY=packmon-safe-runtime-encryption-fixture",
		"--env", "N8N_SECURE_COOKIE=false",
		"--env", "PATH=/fixtures/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"--env", "PACKMON_API_KEY=packmon-safe-api-key-fixture",
		"--env", "PACKMON_SERVER=http://packmon.test.invalid",
		"--env", "PACKMON_SCAN_PATH=workspace",
		"--env", "PACKMON_STUB_RECORD=/home/node/.n8n/helper-invocations",
		"--env", "PACKMON_STUB_EXIT_FILE=/home/node/.n8n/helper-exit",
	}
	for _, key := range []string{"NODES_EXCLUDE", "N8N_BLOCK_ENV_ACCESS_IN_NODE"} {
		args = append(args, "--env", key+"="+contract.Environment[key])
	}
	args = append(args, "--entrypoint=/bin/sh", contract.Image, "-ec", command)
	if output, err := n8nDockerCommand(30*time.Second, args...); err != nil {
		t.Fatalf("start isolated n8n on-demand server: %v: %s", err, n8nOnDemandDiagnostic(output, fixtureRoot, state))
	}
	waitForN8NOnDemandServer(t, client, name, fixtureRoot, state)
	return state
}

func waitForN8NOnDemandServer(t *testing.T, client, name, fixtureRoot, stateRoot string) {
	t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		response, err := runN8NHTTPClient(client, n8nOnDemandWebhookURL(name), "")
		if err == nil && (response.Status == 401 || response.Status == 403) {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	output, _ := n8nDockerCommand(10*time.Second, "logs", name)
	t.Fatalf("isolated n8n on-demand server did not become ready: %s", n8nOnDemandDiagnostic(output, fixtureRoot, stateRoot))
}

func requestN8NOnDemandWebhook(t *testing.T, client, server, credential string) n8nWebhookResponse {
	t.Helper()
	response, err := runN8NHTTPClient(client, n8nOnDemandWebhookURL(server), credential)
	if err != nil {
		t.Fatalf("request n8n on-demand webhook: %v", err)
	}
	return response
}

func n8nOnDemandWebhookURL(server string) string {
	// The shipped template leaves webhookId unset. n8n therefore
	// registers its documented path below the imported workflow and node names.
	return "http://" + server + ":5678/webhook/packmonOnDemandRuntime/webhook/packmon/scan"
}

func n8nOnDemandDiagnostic(output string, roots ...string) string {
	labels := []string{"[FIXTURE]", "[STATE]"}
	for index, root := range roots {
		if root == "" {
			continue
		}
		label := fmt.Sprintf("[TEMP-%d]", index+1)
		if index < len(labels) {
			label = labels[index]
		}
		for _, form := range []string{root, filepath.Clean(root), filepath.ToSlash(root), strings.ReplaceAll(root, `\`, `\\`)} {
			if form != "" {
				output = regexp.MustCompile(`(?i)`+regexp.QuoteMeta(form)).ReplaceAllString(output, label)
			}
		}
	}
	return n8nRuntimeDiagnostic(output, "")
}

func runN8NHTTPClient(client, target, credential string) (n8nWebhookResponse, error) {
	const script = `const headers={'Content-Type':'application/json'};if(process.env.HEADER_VALUE){headers[process.env.HEADER_NAME]=process.env.HEADER_VALUE}fetch(process.env.TARGET_URL,{method:'POST',headers,body:'{}',signal:AbortSignal.timeout(5000)}).then(async response=>console.log(JSON.stringify({status:response.status,body:await response.text()}))).catch(error=>{console.error(error.message);process.exit(2)})`
	args := []string{
		"exec",
		"--env", "TARGET_URL=" + target,
		"--env", "HEADER_NAME=" + n8nWebhookHeaderName,
		"--env", "HEADER_VALUE=" + credential,
		client, "/usr/local/bin/node", "-e", script,
	}
	output, err := n8nDockerCommand(30*time.Second, args...)
	if err != nil {
		return n8nWebhookResponse{}, fmt.Errorf("HTTP client failed: %w: %s", err, n8nRuntimeDiagnostic(output, ""))
	}
	var response n8nWebhookResponse
	if err := json.Unmarshal([]byte(strings.TrimSpace(output)), &response); err != nil {
		return n8nWebhookResponse{}, fmt.Errorf("decode HTTP client response: %w: %s", err, n8nRuntimeDiagnostic(output, ""))
	}
	return response, nil
}

func assertN8NHelperInvocationCount(t *testing.T, state string, want int) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(state, "helper-invocations")) //nolint:gosec // isolated disposable test state
	if os.IsNotExist(err) {
		if want == 0 {
			return
		}
		t.Fatalf("Packmon helper invocation count = 0, want %d", want)
	}
	if err != nil {
		t.Fatalf("read Packmon helper invocation record: %s", n8nOnDemandDiagnostic(err.Error(), "", state))
	}
	if got := strings.Count(string(data), "invoked\n"); got != want {
		t.Fatalf("Packmon helper invocation count = %d, want %d", got, want)
	}
}

func removeN8NOnDemandContainer(t *testing.T, name string) {
	t.Helper()
	output, err := n8nDockerCommand(30*time.Second, "rm", "-f", name)
	if err == nil {
		return
	}
	if strings.TrimSpace(output) == "Error response from daemon: No such container: "+name {
		return
	}
	t.Errorf("remove n8n on-demand container %q: %v: %s", name, err, n8nRuntimeDiagnostic(output, ""))
}

func removeN8NOnDemandNetwork(t *testing.T, name string) {
	t.Helper()
	output, err := n8nDockerCommand(30*time.Second, "network", "rm", name)
	if err != nil {
		t.Errorf("remove n8n on-demand network %q: %v: %s", name, err, n8nRuntimeDiagnostic(output, ""))
	}
}

func assertN8NOnDemandResourcesAbsent(t *testing.T, resources *n8nOnDemandRuntimeResources) {
	t.Helper()
	containerOutput, err := n8nDockerCommand(30*time.Second, "ps", "-a", "--format", "{{.Names}}")
	if err != nil {
		t.Errorf("inventory Docker containers after n8n on-demand cleanup: %v: %s", err, n8nRuntimeDiagnostic(containerOutput, ""))
	} else {
		present := n8nMetricsInventoryNames(containerOutput)
		for _, name := range resources.containers {
			if _, exists := present[name]; exists {
				t.Errorf("n8n on-demand container %q remains after cleanup", name)
			}
		}
	}

	networkOutput, err := n8nDockerCommand(30*time.Second, "network", "ls", "--format", "{{.Name}}")
	if err != nil {
		t.Errorf("inventory Docker networks after n8n on-demand cleanup: %v: %s", err, n8nRuntimeDiagnostic(networkOutput, ""))
	} else if _, exists := n8nMetricsInventoryNames(networkOutput)[resources.network]; exists {
		t.Errorf("n8n on-demand network %q remains after cleanup", resources.network)
	}
}
