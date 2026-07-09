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
