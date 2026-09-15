package ci

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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

	path := filepath.Join("..", "..", "deploy", "n8n", "daily-sync.json")
	data, err := os.ReadFile(path) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read daily-sync.json: %v", err)
	}

	var workflow struct {
		Active bool `json:"active"`
		Nodes  []struct {
			Name       string         `json:"name"`
			Type       string         `json:"type"`
			Parameters map[string]any `json:"parameters"`
		} `json:"nodes"`
		Connections map[string]map[string][][]struct {
			Node  string `json:"node"`
			Type  string `json:"type"`
			Index int    `json:"index"`
		} `json:"connections"`
	}
	if err := json.Unmarshal(data, &workflow); err != nil {
		t.Fatalf("parse daily-sync.json: %v", err)
	}
	if workflow.Active {
		t.Fatal("daily sync workflow must remain disabled by default")
	}
	if len(workflow.Nodes) != 3 {
		t.Fatalf("daily sync node count = %d, want exactly 3", len(workflow.Nodes))
	}

	nodes := make(map[string]struct {
		Type       string
		Parameters map[string]any
	}, len(workflow.Nodes))
	for _, node := range workflow.Nodes {
		if _, duplicate := nodes[node.Name]; duplicate {
			t.Fatalf("daily sync has duplicate node name %q", node.Name)
		}
		nodes[node.Name] = struct {
			Type       string
			Parameters map[string]any
		}{Type: node.Type, Parameters: node.Parameters}
	}
	for name, wantType := range map[string]string{
		"Daily Trigger": "n8n-nodes-base.scheduleTrigger",
		"Sync Local DB": "n8n-nodes-base.executeCommand",
		"Result":        "n8n-nodes-base.code",
	} {
		node, ok := nodes[name]
		if !ok || node.Type != wantType {
			t.Fatalf("daily sync node %q = %+v, want type %q", name, node, wantType)
		}
	}

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
	if got := nodes["Sync Local DB"].Parameters["command"]; got != "packmon db sync" {
		t.Fatalf("daily sync command = %#v, want packmon db sync", got)
	}

	assertN8NMainConnection(t, workflow.Connections, "Daily Trigger", "Sync Local DB")
	assertN8NMainConnection(t, workflow.Connections, "Sync Local DB", "Result")
	if len(workflow.Connections) != 2 {
		t.Fatalf("daily sync connection sources = %d, want exactly 2", len(workflow.Connections))
	}
}

func TestN8NOnDemandScanPinsCompleteWorkflowTopology(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", "deploy", "n8n", "on-demand-scan.json")
	data, err := os.ReadFile(path) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read on-demand-scan.json: %v", err)
	}

	var workflow struct {
		Active bool `json:"active"`
		Nodes  []struct {
			Name       string         `json:"name"`
			Type       string         `json:"type"`
			Parameters map[string]any `json:"parameters"`
		} `json:"nodes"`
		Connections map[string]map[string][][]struct {
			Node  string `json:"node"`
			Type  string `json:"type"`
			Index int    `json:"index"`
		} `json:"connections"`
	}
	if err := json.Unmarshal(data, &workflow); err != nil {
		t.Fatalf("parse on-demand-scan.json: %v", err)
	}
	if workflow.Active {
		t.Fatal("on-demand scan workflow must remain disabled by default")
	}
	if len(workflow.Nodes) != 3 {
		t.Fatalf("on-demand scan node count = %d, want exactly 3", len(workflow.Nodes))
	}

	nodes := make(map[string]struct {
		Type       string
		Parameters map[string]any
	}, len(workflow.Nodes))
	for _, node := range workflow.Nodes {
		if _, duplicate := nodes[node.Name]; duplicate {
			t.Fatalf("on-demand scan has duplicate node name %q", node.Name)
		}
		nodes[node.Name] = struct {
			Type       string
			Parameters map[string]any
		}{Type: node.Type, Parameters: node.Parameters}
	}
	for name, wantType := range map[string]string{
		"Webhook":  "n8n-nodes-base.webhook",
		"Run Scan": "n8n-nodes-base.executeCommand",
		"Respond":  "n8n-nodes-base.respondToWebhook",
	} {
		node, ok := nodes[name]
		if !ok || node.Type != wantType {
			t.Fatalf("on-demand scan node %q = %+v, want type %q", name, node, wantType)
		}
	}

	for key, want := range map[string]string{
		"httpMethod":     "POST",
		"path":           "packmon/scan",
		"authentication": "headerAuth",
		"responseMode":   "responseNode",
	} {
		if got := nodes["Webhook"].Parameters[key]; got != want {
			t.Fatalf("webhook parameter %q = %#v, want %q", key, got, want)
		}
	}
	if got := nodes["Respond"].Parameters["respondWith"]; got != "json" {
		t.Fatalf("response format = %#v, want json", got)
	}

	assertN8NMainConnection(t, workflow.Connections, "Webhook", "Run Scan")
	assertN8NMainConnection(t, workflow.Connections, "Run Scan", "Respond")
	if len(workflow.Connections) != 2 {
		t.Fatalf("on-demand scan connection sources = %d, want exactly 2", len(workflow.Connections))
	}
}

func assertN8NMainConnection(t *testing.T, connections map[string]map[string][][]struct {
	Node  string `json:"node"`
	Type  string `json:"type"`
	Index int    `json:"index"`
}, from, wantNode string) {
	t.Helper()
	branches := connections[from]["main"]
	if len(branches) != 1 || len(branches[0]) != 1 {
		t.Fatalf("connection %q main = %#v, want one target", from, branches)
	}
	target := branches[0][0]
	if target.Node != wantNode || target.Type != "main" || target.Index != 0 {
		t.Fatalf("connection %q target = %+v, want main -> %q index 0", from, target, wantNode)
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
		if node.Type != "n8n-nodes-base.httpRequest" {
			continue
		}
		url, ok := node.Parameters["url"].(string)
		if !ok {
			t.Fatalf("weekly maintenance metrics URL has type %T, want string", node.Parameters["url"])
		}
		if !strings.Contains(url, "PACKMON_METRICS_URL") {
			t.Fatalf("weekly maintenance must use PACKMON_METRICS_URL, got %q", url)
		}
		if strings.Contains(url, "127.0.0.1:9090") || strings.Contains(url, "localhost") {
			t.Fatalf("weekly maintenance must not hard-code a localhost metrics URL, got %q", url)
		}
		return
	}
	t.Fatal("weekly maintenance workflow has no httpRequest node")
}

func TestN8NWeeklyMaintenancePinsTopology(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", "deploy", "n8n", "weekly-maintenance.json")
	data, err := os.ReadFile(path) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read weekly-maintenance.json: %v", err)
	}

	var workflow struct {
		Active bool `json:"active"`
		Nodes  []struct {
			ID         string         `json:"id"`
			Name       string         `json:"name"`
			Type       string         `json:"type"`
			Parameters map[string]any `json:"parameters"`
		} `json:"nodes"`
		Connections map[string]map[string][][]struct {
			Node  string `json:"node"`
			Type  string `json:"type"`
			Index int    `json:"index"`
		} `json:"connections"`
	}
	if err := json.Unmarshal(data, &workflow); err != nil {
		t.Fatalf("parse weekly-maintenance.json: %v", err)
	}
	if workflow.Active {
		t.Fatal("weekly maintenance workflow must be disabled by default")
	}
	if len(workflow.Nodes) != 2 {
		t.Fatalf("weekly maintenance nodes = %d, want 2", len(workflow.Nodes))
	}

	nodes := make(map[string]struct {
		ID         string
		Type       string
		Parameters map[string]any
	}, len(workflow.Nodes))
	ids := make(map[string]struct{}, len(workflow.Nodes))
	for _, node := range workflow.Nodes {
		if node.Name == "" || node.ID == "" {
			t.Fatalf("weekly maintenance node must have name and id: %+v", node)
		}
		if _, exists := nodes[node.Name]; exists {
			t.Fatalf("duplicate weekly maintenance node name %q", node.Name)
		}
		if _, exists := ids[node.ID]; exists {
			t.Fatalf("duplicate weekly maintenance node id %q", node.ID)
		}
		nodes[node.Name] = struct {
			ID         string
			Type       string
			Parameters map[string]any
		}{node.ID, node.Type, node.Parameters}
		ids[node.ID] = struct{}{}
	}

	trigger, ok := nodes["Weekly Trigger"]
	if !ok || trigger.Type != "n8n-nodes-base.scheduleTrigger" {
		t.Fatalf("weekly trigger = %+v, want schedule trigger", trigger)
	}
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

	fetch, ok := nodes["Fetch Metrics"]
	if !ok || fetch.Type != "n8n-nodes-base.httpRequest" {
		t.Fatalf("fetch metrics node = %+v, want HTTP request", fetch)
	}
	assertN8NMainConnection(t, workflow.Connections, "Weekly Trigger", "Fetch Metrics")
	if len(workflow.Connections) != 1 {
		t.Fatalf("weekly maintenance connection sources = %d, want exactly 1", len(workflow.Connections))
	}
}
