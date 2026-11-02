package ci

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

type n8nConnectionTarget struct {
	Node  string `json:"node"`
	Type  string `json:"type"`
	Index int    `json:"index"`
}

type n8nConnections map[string]map[string][][]n8nConnectionTarget

type n8nWorkflowNode struct {
	ID               string          `json:"id"`
	Name             string          `json:"name"`
	Type             string          `json:"type"`
	TypeVersion      int             `json:"typeVersion"`
	Parameters       map[string]any  `json:"parameters"`
	Credentials      json.RawMessage `json:"credentials"`
	AlwaysOutputData json.RawMessage `json:"alwaysOutputData"`
	ContinueOnFail   json.RawMessage `json:"continueOnFail"`
	OnError          json.RawMessage `json:"onError"`
	RetryOnFail      json.RawMessage `json:"retryOnFail"`
}

type n8nWorkflow struct {
	Active      *bool             `json:"active"`
	Name        string            `json:"name"`
	Settings    map[string]any    `json:"settings"`
	Nodes       []n8nWorkflowNode `json:"nodes"`
	Connections n8nConnections    `json:"connections"`
}

func TestN8NOnDemandScanDoesNotInterpolateWebhookPathIntoShell(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", "deploy", "n8n", "on-demand-scan.json")
	data, err := os.ReadFile(path) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read on-demand-scan.json: %v", err)
	}

	var workflow struct {
		Nodes []struct {
			Type       string         `json:"type"`
			Parameters map[string]any `json:"parameters"`
		} `json:"nodes"`
	}
	if err := json.Unmarshal(data, &workflow); err != nil {
		t.Fatalf("parse on-demand-scan.json: %v", err)
	}

	for _, node := range workflow.Nodes {
		if node.Type != "n8n-nodes-base.executeCommand" {
			continue
		}
		command, ok := node.Parameters["command"].(string)
		if !ok {
			t.Fatalf("on-demand scan command has type %T, want string", node.Parameters["command"])
		}
		helper := n8nOnDemandScanHelper(t)
		for _, forbidden := range []string{"$json.body.path", "{{$env.PACKMON_SCAN_PATH}}", "packmon scan $PACKMON_SCAN_PATH"} {
			if strings.Contains(command, forbidden) {
				t.Fatalf("executeCommand interpolates scan path into shell unsafely via %q: %s", forbidden, command)
			}
		}
		if strings.TrimSpace(command) != "sh /opt/packmon/n8n/on-demand-scan.sh" {
			t.Fatalf("executeCommand command = %q, want helper invocation", command)
		}
		for _, want := range []string{`case "${PACKMON_SCAN_PATH:-}"`, `packmon scan "$PACKMON_SCAN_PATH"`} {
			if !strings.Contains(helper, want) {
				t.Fatalf("helper must validate and quote PACKMON_SCAN_PATH; missing %q in %s", want, helper)
			}
		}
		return
	}
	t.Fatal("on-demand workflow has no executeCommand node")
}

func TestN8NOnDemandScanForcesAuthenticatedRemoteMode(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", "deploy", "n8n", "on-demand-scan.json")
	data, err := os.ReadFile(path) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read on-demand-scan.json: %v", err)
	}

	var workflow struct {
		Nodes []struct {
			Type       string         `json:"type"`
			Parameters map[string]any `json:"parameters"`
		} `json:"nodes"`
	}
	if err := json.Unmarshal(data, &workflow); err != nil {
		t.Fatalf("parse on-demand-scan.json: %v", err)
	}

	for _, node := range workflow.Nodes {
		if node.Type != "n8n-nodes-base.executeCommand" {
			continue
		}
		command, ok := node.Parameters["command"].(string)
		if !ok {
			t.Fatalf("on-demand scan command has type %T, want string", node.Parameters["command"])
		}
		helper := n8nOnDemandScanHelper(t)
		if strings.TrimSpace(command) != "sh /opt/packmon/n8n/on-demand-scan.sh" {
			t.Fatalf("executeCommand command = %q, want helper invocation", command)
		}
		for _, want := range []string{
			`case "${PACKMON_API_KEY:-}"`,
			`case "${PACKMON_SERVER:-}"`,
			`packmon scan "$PACKMON_SCAN_PATH"`,
			`--mode remote`,
			`--require-remote`,
			`--server "$PACKMON_SERVER"`,
		} {
			if !strings.Contains(helper, want) {
				t.Fatalf("on-demand helper must force authenticated remote mode; missing %q in %s", want, helper)
			}
		}
		for _, forbidden := range []string{"--output-json", "/tmp/packmon-scan", "mktemp", "PACKMON_SCAN_OUTPUT"} {
			if strings.Contains(command, forbidden) || strings.Contains(helper, forbidden) {
				t.Fatalf("on-demand scan must not create runtime report artifacts via %q", forbidden)
			}
		}
		if strings.Contains(command, "--api-key") || strings.Contains(helper, "--api-key") {
			t.Fatalf("on-demand scan must not pass PACKMON_API_KEY via argv")
		}
		return
	}
	t.Fatal("on-demand workflow has no executeCommand node")
}

func n8nOnDemandScanHelper(t *testing.T) string {
	t.Helper()

	path := filepath.Join("..", "..", "deploy", "n8n", "on-demand-scan.sh")
	data, err := os.ReadFile(path) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read on-demand-scan.sh: %v", err)
	}
	return string(data)
}

func TestN8NOnDemandWebhookRequiresHeaderAuth(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", "deploy", "n8n", "on-demand-scan.json")
	data, err := os.ReadFile(path) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read on-demand-scan.json: %v", err)
	}

	var workflow struct {
		Nodes []struct {
			Type        string         `json:"type"`
			Parameters  map[string]any `json:"parameters"`
			Credentials map[string]any `json:"credentials"`
		} `json:"nodes"`
	}
	if err := json.Unmarshal(data, &workflow); err != nil {
		t.Fatalf("parse on-demand-scan.json: %v", err)
	}

	for _, node := range workflow.Nodes {
		if node.Type != "n8n-nodes-base.webhook" {
			continue
		}
		if got, _ := node.Parameters["authentication"].(string); got != "headerAuth" {
			t.Fatalf("webhook authentication = %q, want headerAuth", got)
		}
		if _, ok := node.Credentials["httpHeaderAuth"]; !ok {
			t.Fatalf("webhook must reference an httpHeaderAuth credential: %+v", node.Credentials)
		}
		return
	}
	t.Fatal("on-demand workflow has no webhook node")
}

func TestN8NOnDemandResponseDoesNotEchoScanPath(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", "deploy", "n8n", "on-demand-scan.json")
	data, err := os.ReadFile(path) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read on-demand-scan.json: %v", err)
	}

	var workflow struct {
		Nodes []struct {
			Type       string         `json:"type"`
			Parameters map[string]any `json:"parameters"`
		} `json:"nodes"`
	}
	if err := json.Unmarshal(data, &workflow); err != nil {
		t.Fatalf("parse on-demand-scan.json: %v", err)
	}

	for _, node := range workflow.Nodes {
		if node.Type != "n8n-nodes-base.respondToWebhook" {
			continue
		}
		body, ok := node.Parameters["responseBody"].(string)
		if !ok {
			t.Fatalf("respond node responseBody has type %T, want string", node.Parameters["responseBody"])
		}
		if strings.Contains(body, `"status":"queued"`) {
			t.Fatalf("on-demand response must not claim queued after scan completion: %s", body)
		}
		if !strings.Contains(body, `"status":"completed"`) {
			t.Fatalf("on-demand response must report completed synchronous scan status: %s", body)
		}
		for _, forbidden := range []string{"PACKMON_SCAN_PATH", `"path"`, "$env."} {
			if strings.Contains(body, forbidden) {
				t.Fatalf("on-demand response leaks path/env value via %q: %s", forbidden, body)
			}
		}
		return
	}
	t.Fatal("on-demand workflow has no respondToWebhook node")
}

func TestN8NDailySyncKeepsAPIKeyOutOfCommandArguments(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", "deploy", "n8n", "daily-sync.json")
	data, err := os.ReadFile(path) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read daily-sync.json: %v", err)
	}

	var workflow struct {
		Nodes []struct {
			Type       string         `json:"type"`
			Parameters map[string]any `json:"parameters"`
		} `json:"nodes"`
	}
	if err := json.Unmarshal(data, &workflow); err != nil {
		t.Fatalf("parse daily-sync.json: %v", err)
	}

	for _, node := range workflow.Nodes {
		if node.Type != "n8n-nodes-base.executeCommand" {
			continue
		}
		command, ok := node.Parameters["command"].(string)
		if !ok {
			t.Fatalf("daily sync command has type %T, want string", node.Parameters["command"])
		}
		for _, forbidden := range []string{"--api-key", "PACKMON_API_KEY"} {
			if strings.Contains(command, forbidden) {
				t.Fatalf("daily sync command must not pass API keys via argv; found %q in %s", forbidden, command)
			}
		}
		if strings.TrimSpace(command) != "packmon db sync" {
			t.Fatalf("daily sync command = %q, want packmon db sync with PACKMON_* env vars", command)
		}
		return
	}
	t.Fatal("daily sync workflow has no executeCommand node")
}

func TestN8NDailySyncPinsCompleteWorkflowTopology(t *testing.T) {
	t.Parallel()

	workflow := readN8NWorkflow(t, "daily-sync.json")
	assertN8NWorkflowEnvelope(t, workflow, "daily sync", "Packmon Daily Sync")
	nodes := indexN8NNodes(t, workflow.Nodes, "daily sync")
	assertN8NNodeTuples(t, nodes, "daily sync", map[string]n8nNodeTuple{
		"Daily Trigger": {ID: "daily-trigger", Type: "n8n-nodes-base.scheduleTrigger", TypeVersion: 1},
		"Sync Local DB": {ID: "sync-db", Type: "n8n-nodes-base.executeCommand", TypeVersion: 1},
		"Result":        {ID: "result", Type: "n8n-nodes-base.code", TypeVersion: 2},
	})
	assertN8NNodesHaveNoErrorOverrides(t, workflow.Nodes, "daily sync")
	assertN8NNodesHaveNoCredentials(t, workflow.Nodes, "daily sync")
	assertN8NErrorOverrideMutationResistance(t, workflow)

	rule, ok := nodes["Daily Trigger"].Parameters["rule"].(map[string]any)
	if !ok {
		t.Fatalf("daily trigger rule = %T, want object", nodes["Daily Trigger"].Parameters["rule"])
	}
	interval, ok := rule["interval"].([]any)
	if !ok || len(interval) != 1 {
		t.Fatalf("daily trigger interval = %#v, want one cron rule", rule["interval"])
	}
	cron, ok := interval[0].(map[string]any)
	if !ok || cron["field"] != "cronExpression" || cron["expression"] != "0 3 * * *" {
		t.Fatalf("daily trigger cron = %#v, want 0 3 * * *", interval[0])
	}
	wantTriggerParameters := map[string]any{"rule": map[string]any{"interval": []any{map[string]any{
		"field": "cronExpression", "expression": "0 3 * * *",
	}}}}
	if got := nodes["Daily Trigger"].Parameters; !reflect.DeepEqual(got, wantTriggerParameters) {
		t.Fatalf("daily trigger parameters = %#v, want exact %#v", got, wantTriggerParameters)
	}
	if got, want := nodes["Sync Local DB"].Parameters, map[string]any{"command": "packmon db sync"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("daily sync parameters = %#v, want exact %#v", got, want)
	}
	if got, want := nodes["Result"].Parameters, map[string]any{"jsCode": n8nDailySyncResultCode}; !reflect.DeepEqual(got, want) {
		t.Fatalf("daily result parameters = %#v, want %#v", got, want)
	}

	wantConnections := n8nConnections{
		"Daily Trigger": {"main": {{{Node: "Sync Local DB", Type: "main", Index: 0}}}},
		"Sync Local DB": {"main": {{{Node: "Result", Type: "main", Index: 0}}}},
	}
	if !reflect.DeepEqual(workflow.Connections, wantConnections) {
		t.Fatalf("daily sync connections = %#v, want exact map %#v", workflow.Connections, wantConnections)
	}
}

const n8nDailySyncResultCode = "return [{ json: { workflow: 'daily-sync', status: 'ok', finishedAt: new Date().toISOString() } }];"

func TestN8NDailySyncResultCodeExecutesExactSuccessEnvelope(t *testing.T) {
	t.Parallel()

	nodePath, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is required to execute the n8n code-node contract")
	}
	workflow := readN8NWorkflow(t, "daily-sync.json")
	nodes := indexN8NNodes(t, workflow.Nodes, "daily sync")
	resultNode, ok := nodes["Result"]
	if !ok {
		t.Fatal("daily sync has no Result node")
	}
	jsCode, ok := resultNode.Parameters["jsCode"].(string)
	if !ok {
		t.Fatalf("daily result jsCode = %T, want string", resultNode.Parameters["jsCode"])
	}
	if jsCode != n8nDailySyncResultCode {
		t.Fatalf("daily result jsCode = %q, want byte-identical %q", jsCode, n8nDailySyncResultCode)
	}

	const fixedTime = "2026-10-31T03:04:05.678Z"
	const harness = `
const jsCode = Buffer.from(process.argv[1], 'base64').toString('utf8');
const expectedCode = Buffer.from(process.argv[2], 'base64').toString('utf8');
if (jsCode !== expectedCode) throw new Error('decoded jsCode is not byte-identical');
const RealDate = Date;
class FixedDate extends RealDate {
  constructor(...args) {
    if (args.length !== 0) throw new Error('production code supplied unexpected Date arguments');
    super(process.argv[3]);
  }
}
const execute = new Function('Date', jsCode);
process.stdout.write(JSON.stringify(execute(FixedDate)));
`
	encodedCode := base64.StdEncoding.EncodeToString([]byte(jsCode))
	encodedExpected := base64.StdEncoding.EncodeToString([]byte(n8nDailySyncResultCode))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, nodePath, "-e", harness, encodedCode, encodedExpected, fixedTime) //nolint:gosec // fixed executable and static test script
	output, err := command.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("execute daily result code: %v", ctx.Err())
	}
	if err != nil {
		t.Fatalf("execute daily result code: %v\n%s", err, output)
	}
	want := `[{"json":{"workflow":"daily-sync","status":"ok","finishedAt":"` + fixedTime + `"}}]`
	if string(output) != want {
		t.Fatalf("daily result envelope = %s, want exact %s", output, want)
	}
}

func TestN8NOnDemandScanPinsCompleteWorkflowTopology(t *testing.T) {
	t.Parallel()

	workflow := readN8NWorkflow(t, "on-demand-scan.json")
	assertN8NWorkflowEnvelope(t, workflow, "on-demand scan", "Packmon On Demand Scan")
	nodes := indexN8NNodes(t, workflow.Nodes, "on-demand scan")
	assertN8NNodeTuples(t, nodes, "on-demand scan", map[string]n8nNodeTuple{
		"Webhook":  {ID: "webhook", Type: "n8n-nodes-base.webhook", TypeVersion: 1},
		"Run Scan": {ID: "run-scan", Type: "n8n-nodes-base.executeCommand", TypeVersion: 1},
		"Respond":  {ID: "respond", Type: "n8n-nodes-base.respondToWebhook", TypeVersion: 1},
	})
	assertN8NNodesHaveNoErrorOverrides(t, workflow.Nodes, "on-demand scan")

	wantWebhookParameters := map[string]any{
		"httpMethod":     "POST",
		"path":           "packmon/scan",
		"authentication": "headerAuth",
		"responseMode":   "responseNode",
	}
	if got := nodes["Webhook"].Parameters; !reflect.DeepEqual(got, wantWebhookParameters) {
		t.Fatalf("webhook parameters = %#v, want exact %#v", got, wantWebhookParameters)
	}
	wantCredentials := map[string]any{
		"httpHeaderAuth": map[string]any{
			"id":   "replace-with-packmon-webhook-header-auth",
			"name": "Packmon On-Demand Webhook Header Auth",
		},
	}
	var gotCredentials map[string]any
	if err := json.Unmarshal(nodes["Webhook"].Credentials, &gotCredentials); err != nil {
		t.Fatalf("parse webhook credentials: %v", err)
	}
	if !reflect.DeepEqual(gotCredentials, wantCredentials) {
		t.Fatalf("webhook credentials = %#v, want exact %#v", gotCredentials, wantCredentials)
	}
	for _, name := range []string{"Run Scan", "Respond"} {
		if len(nodes[name].Credentials) != 0 {
			t.Fatalf("on-demand node %q credentials = %s, want field absent", name, nodes[name].Credentials)
		}
	}
	if got, want := nodes["Run Scan"].Parameters, map[string]any{"command": "sh /opt/packmon/n8n/on-demand-scan.sh"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("run-scan parameters = %#v, want exact %#v", got, want)
	}

	const responseBody = `={"workflow":"on-demand-scan","status":"completed"}`
	wantRespondParameters := map[string]any{"respondWith": "json", "responseBody": responseBody}
	if got := nodes["Respond"].Parameters; !reflect.DeepEqual(got, wantRespondParameters) {
		t.Fatalf("respond parameters = %#v, want exact %#v", got, wantRespondParameters)
	}
	var response map[string]any
	if err := json.Unmarshal([]byte(strings.TrimPrefix(responseBody, "=")), &response); err != nil {
		t.Fatalf("parse responseBody literal: %v", err)
	}
	wantResponse := map[string]any{"workflow": "on-demand-scan", "status": "completed"}
	if !reflect.DeepEqual(response, wantResponse) {
		t.Fatalf("responseBody JSON = %#v, want exact %#v", response, wantResponse)
	}

	wantConnections := n8nConnections{
		"Webhook":  {"main": {{{Node: "Run Scan", Type: "main", Index: 0}}}},
		"Run Scan": {"main": {{{Node: "Respond", Type: "main", Index: 0}}}},
	}
	if !reflect.DeepEqual(workflow.Connections, wantConnections) {
		t.Fatalf("on-demand connections = %#v, want exact map %#v", workflow.Connections, wantConnections)
	}
}

func TestN8NWeeklyMaintenanceDoesNotWriteUnusedExportFile(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", "deploy", "n8n", "weekly-maintenance.json")
	data, err := os.ReadFile(path) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read weekly-maintenance.json: %v", err)
	}

	var workflow struct {
		Nodes []struct {
			Type       string         `json:"type"`
			Parameters map[string]any `json:"parameters"`
		} `json:"nodes"`
	}
	if err := json.Unmarshal(data, &workflow); err != nil {
		t.Fatalf("parse weekly-maintenance.json: %v", err)
	}

	for _, node := range workflow.Nodes {
		if node.Type == "n8n-nodes-base.executeCommand" {
			t.Fatalf("weekly maintenance must not write unused command artifacts: %+v", node.Parameters)
		}
	}
}

func TestN8NWeeklyMaintenanceUsesConfiguredMetricsURL(t *testing.T) {
	t.Parallel()

	workflow := readN8NWorkflow(t, "weekly-maintenance.json")
	if err := validateN8NWeeklyMetricsRequest(workflow); err != nil {
		t.Fatalf("weekly maintenance metrics request: %v", err)
	}

	mutations := map[string]func(*n8nWorkflow){
		"altered URL expression": func(mutated *n8nWorkflow) {
			for i := range mutated.Nodes {
				if mutated.Nodes[i].Name == "Fetch Metrics" {
					mutated.Nodes[i].Parameters["url"] = "prefix={{$env.PACKMON_METRICS_URL}}"
				}
			}
		},
		"nonempty request options": func(mutated *n8nWorkflow) {
			for i := range mutated.Nodes {
				if mutated.Nodes[i].Name == "Fetch Metrics" {
					mutated.Nodes[i].Parameters["options"] = map[string]any{"timeout": float64(1000)}
				}
			}
		},
		"additional HTTP destination": func(mutated *n8nWorkflow) {
			extra := mutated.Nodes[1]
			extra.ID = "unexpected-request"
			extra.Name = "Unexpected Request"
			mutated.Nodes = append(mutated.Nodes, extra)
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			mutated := cloneN8NWorkflow(t, workflow)
			mutate(&mutated)
			if err := validateN8NWeeklyMetricsRequest(mutated); err == nil {
				t.Fatal("mutated workflow unexpectedly satisfied the exact metrics-request contract")
			}
		})
	}
}

func TestN8NWeeklyMaintenancePinsTopology(t *testing.T) {
	t.Parallel()

	workflow := readN8NWorkflow(t, "weekly-maintenance.json")
	assertN8NWorkflowEnvelope(t, workflow, "weekly maintenance", "Packmon Weekly Maintenance")
	nodes := indexN8NNodes(t, workflow.Nodes, "weekly maintenance")
	assertN8NNodeTuples(t, nodes, "weekly maintenance", map[string]n8nNodeTuple{
		"Weekly Trigger": {ID: "weekly-trigger", Type: "n8n-nodes-base.scheduleTrigger", TypeVersion: 1},
		"Fetch Metrics":  {ID: "fetch-metrics", Type: "n8n-nodes-base.httpRequest", TypeVersion: 4},
	})
	assertN8NNodesHaveNoErrorOverrides(t, workflow.Nodes, "weekly maintenance")
	assertN8NNodesHaveNoCredentials(t, workflow.Nodes, "weekly maintenance")

	trigger := nodes["Weekly Trigger"]
	rule, ok := trigger.Parameters["rule"].(map[string]any)
	if !ok {
		t.Fatalf("weekly trigger rule = %#v, want object", trigger.Parameters["rule"])
	}
	intervals, ok := rule["interval"].([]any)
	if !ok || len(intervals) != 1 {
		t.Fatalf("weekly trigger intervals = %#v, want one cron interval", rule["interval"])
	}
	interval, ok := intervals[0].(map[string]any)
	if !ok || interval["field"] != "cronExpression" || interval["expression"] != "0 4 * * 0" {
		t.Fatalf("weekly trigger interval = %#v, want Sunday 04:00 cron", intervals[0])
	}
	wantTriggerParameters := map[string]any{"rule": map[string]any{"interval": []any{map[string]any{
		"field": "cronExpression", "expression": "0 4 * * 0",
	}}}}
	if got := trigger.Parameters; !reflect.DeepEqual(got, wantTriggerParameters) {
		t.Fatalf("weekly trigger parameters = %#v, want exact %#v", got, wantTriggerParameters)
	}

	wantConnections := n8nConnections{
		"Weekly Trigger": {"main": {{{Node: "Fetch Metrics", Type: "main", Index: 0}}}},
	}
	if !reflect.DeepEqual(workflow.Connections, wantConnections) {
		t.Fatalf("weekly maintenance connections = %#v, want exact map %#v", workflow.Connections, wantConnections)
	}
}

type n8nNodeTuple struct {
	ID          string
	Type        string
	TypeVersion int
}

func readN8NWorkflow(t *testing.T, name string) n8nWorkflow {
	t.Helper()

	path := filepath.Join("..", "..", "deploy", "n8n", name)
	data, err := os.ReadFile(path) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	var workflow n8nWorkflow
	if err := json.Unmarshal(data, &workflow); err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	return workflow
}

func cloneN8NWorkflow(t *testing.T, workflow n8nWorkflow) n8nWorkflow {
	t.Helper()

	data, err := json.Marshal(workflow)
	if err != nil {
		t.Fatalf("marshal workflow clone: %v", err)
	}
	var cloned n8nWorkflow
	if err := json.Unmarshal(data, &cloned); err != nil {
		t.Fatalf("unmarshal workflow clone: %v", err)
	}
	return cloned
}

func assertN8NWorkflowEnvelope(t *testing.T, workflow n8nWorkflow, label, wantName string) {
	t.Helper()

	if workflow.Name != wantName {
		t.Fatalf("%s workflow name = %q, want exact %q", label, workflow.Name, wantName)
	}
	if workflow.Active == nil {
		t.Fatalf("%s workflow is missing active=false", label)
	}
	if *workflow.Active {
		t.Fatalf("%s workflow must remain disabled by default", label)
	}
	if workflow.Settings == nil {
		t.Fatalf("%s workflow is missing settings={}", label)
	}
	if len(workflow.Settings) != 0 {
		t.Fatalf("%s workflow settings = %#v, want present empty object", label, workflow.Settings)
	}
}

func indexN8NNodes(t *testing.T, workflowNodes []n8nWorkflowNode, label string) map[string]n8nWorkflowNode {
	t.Helper()

	nodes := make(map[string]n8nWorkflowNode, len(workflowNodes))
	ids := make(map[string]struct{}, len(workflowNodes))
	for _, node := range workflowNodes {
		if node.Name == "" || node.ID == "" {
			t.Fatalf("%s node must have name and id: %+v", label, node)
		}
		if _, duplicate := nodes[node.Name]; duplicate {
			t.Fatalf("%s has duplicate node name %q", label, node.Name)
		}
		if _, duplicate := ids[node.ID]; duplicate {
			t.Fatalf("%s has duplicate node id %q", label, node.ID)
		}
		nodes[node.Name] = node
		ids[node.ID] = struct{}{}
	}
	return nodes
}

func assertN8NNodeTuples(t *testing.T, nodes map[string]n8nWorkflowNode, label string, want map[string]n8nNodeTuple) {
	t.Helper()

	if len(nodes) != len(want) {
		t.Fatalf("%s node count = %d, want exactly %d", label, len(nodes), len(want))
	}
	for name, wantTuple := range want {
		node, ok := nodes[name]
		if !ok {
			t.Fatalf("%s is missing node %q", label, name)
		}
		got := n8nNodeTuple{ID: node.ID, Type: node.Type, TypeVersion: node.TypeVersion}
		if got != wantTuple {
			t.Fatalf("%s node %q tuple = %+v, want %+v", label, name, got, wantTuple)
		}
	}
}

func assertN8NNodesHaveNoErrorOverrides(t *testing.T, nodes []n8nWorkflowNode, label string) {
	t.Helper()

	if err := validateN8NNodesHaveNoErrorOverrides(nodes); err != nil {
		t.Fatalf("%s: %v", label, err)
	}
}

func validateN8NNodesHaveNoErrorOverrides(nodes []n8nWorkflowNode) error {
	for _, node := range nodes {
		fields := []struct {
			name  string
			value json.RawMessage
		}{
			{name: "alwaysOutputData", value: node.AlwaysOutputData},
			{name: "continueOnFail", value: node.ContinueOnFail},
			{name: "onError", value: node.OnError},
			{name: "retryOnFail", value: node.RetryOnFail},
		}
		for _, field := range fields {
			if len(field.value) != 0 {
				return fmt.Errorf("node %q overrides failure propagation via %s=%s", node.Name, field.name, field.value)
			}
		}
	}
	return nil
}

func assertN8NErrorOverrideMutationResistance(t *testing.T, workflow n8nWorkflow) {
	t.Helper()

	mutations := map[string]func(*n8nWorkflowNode){
		"alwaysOutputData": func(node *n8nWorkflowNode) { node.AlwaysOutputData = json.RawMessage("true") },
		"continueOnFail":   func(node *n8nWorkflowNode) { node.ContinueOnFail = json.RawMessage("true") },
		"onError":          func(node *n8nWorkflowNode) { node.OnError = json.RawMessage(`"continueRegularOutput"`) },
		"retryOnFail":      func(node *n8nWorkflowNode) { node.RetryOnFail = json.RawMessage("true") },
	}
	for name, mutate := range mutations {
		t.Run("rejects "+name, func(t *testing.T) {
			mutatedNodes := append([]n8nWorkflowNode(nil), workflow.Nodes...)
			mutate(&mutatedNodes[0])
			err := validateN8NNodesHaveNoErrorOverrides(mutatedNodes)
			if err == nil {
				t.Fatalf("workflow with %s unexpectedly satisfied the no-error-override contract", name)
			}
			if !strings.Contains(err.Error(), name) {
				t.Fatalf("workflow with %s failed for the wrong field: %v", name, err)
			}
		})
	}
}

func assertN8NNodesHaveNoCredentials(t *testing.T, nodes []n8nWorkflowNode, label string) {
	t.Helper()

	for _, node := range nodes {
		if len(node.Credentials) != 0 {
			t.Fatalf("%s node %q credentials = %s, want field absent", label, node.Name, node.Credentials)
		}
	}
}

func validateN8NWeeklyMetricsRequest(workflow n8nWorkflow) error {
	const httpRequestType = "n8n-nodes-base.httpRequest"
	wantParameters := map[string]any{
		"url":     "={{$env.PACKMON_METRICS_URL}}",
		"options": map[string]any{},
	}
	httpNodes := 0
	for _, node := range workflow.Nodes {
		if node.Type != httpRequestType {
			continue
		}
		httpNodes++
		if node.Name != "Fetch Metrics" {
			return fmt.Errorf("unexpected HTTP request node %q", node.Name)
		}
		if !reflect.DeepEqual(node.Parameters, wantParameters) {
			return fmt.Errorf("Fetch Metrics parameters = %#v, want exact %#v", node.Parameters, wantParameters)
		}
	}
	if httpNodes != 1 {
		return fmt.Errorf("HTTP request node count = %d, want exactly 1", httpNodes)
	}
	return nil
}
