package ci

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type n8nOnDemandNode struct {
	Type        string         `json:"type"`
	Parameters  map[string]any `json:"parameters"`
	Credentials map[string]any `json:"credentials"`
}

func TestN8NOnDemandScanInspectsEveryCommandAndWebhookNode(t *testing.T) {
	t.Parallel()

	nodes := readN8NOnDemandNodes(t)
	if violations := n8nOnDemandNodeViolations(nodes); len(violations) != 0 {
		t.Fatalf("committed on-demand workflow has unsafe nodes: %s", strings.Join(violations, "; "))
	}

	unsafeNodes := append(append([]n8nOnDemandNode(nil), nodes...),
		n8nOnDemandNode{
			Type:       "n8n-nodes-base.executeCommand",
			Parameters: map[string]any{"command": "packmon scan $json.body.path"},
		},
		n8nOnDemandNode{
			Type:       "n8n-nodes-base.webhook",
			Parameters: map[string]any{"authentication": "none"},
		},
	)
	violations := n8nOnDemandNodeViolations(unsafeNodes)
	if len(violations) != 2 {
		t.Fatalf("unsafe additional command and webhook violations = %#v, want 2", violations)
	}
	if !strings.Contains(violations[0], "executeCommand") || !strings.Contains(violations[1], "webhook") {
		t.Fatalf("unsafe additional nodes must both be inspected, got %#v", violations)
	}
}

func readN8NOnDemandNodes(t *testing.T) []n8nOnDemandNode {
	t.Helper()

	path := filepath.Join("..", "..", "deploy", "n8n", "on-demand-scan.json")
	data, err := os.ReadFile(path) //nolint:gosec // static repository fixture path
	if err != nil {
		t.Fatalf("read on-demand-scan.json: %v", err)
	}
	var workflow struct {
		Nodes []n8nOnDemandNode `json:"nodes"`
	}
	if err := json.Unmarshal(data, &workflow); err != nil {
		t.Fatalf("parse on-demand-scan.json: %v", err)
	}
	return workflow.Nodes
}

func n8nOnDemandNodeViolations(nodes []n8nOnDemandNode) []string {
	var violations []string
	for _, node := range nodes {
		switch node.Type {
		case "n8n-nodes-base.executeCommand":
			if command, _ := node.Parameters["command"].(string); strings.TrimSpace(command) != "sh /opt/packmon/n8n/on-demand-scan.sh" {
				violations = append(violations, "executeCommand must invoke the fixed on-demand scan helper")
			}
		case "n8n-nodes-base.webhook":
			if authentication, _ := node.Parameters["authentication"].(string); authentication != "headerAuth" {
				violations = append(violations, "webhook must require header authentication")
				continue
			}
			if _, ok := node.Credentials["httpHeaderAuth"]; !ok {
				violations = append(violations, "webhook must reference an httpHeaderAuth credential")
			}
		}
	}
	return violations
}
