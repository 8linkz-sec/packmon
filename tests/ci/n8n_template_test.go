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
			Type       string            `json:"type"`
			Parameters map[string]string `json:"parameters"`
		} `json:"nodes"`
	}
	if err := json.Unmarshal(data, &workflow); err != nil {
		t.Fatalf("parse on-demand-scan.json: %v", err)
	}

	for _, node := range workflow.Nodes {
		if node.Type != "n8n-nodes-base.executeCommand" {
			continue
		}
		command := node.Parameters["command"]
		if strings.Contains(command, "$json.body.path") {
			t.Fatalf("executeCommand interpolates webhook body path: %s", command)
		}
		if !strings.Contains(command, "$env.PACKMON_SCAN_PATH") {
			t.Fatalf("executeCommand must scan configured PACKMON_SCAN_PATH: %s", command)
		}
		return
	}
	t.Fatal("on-demand workflow has no executeCommand node")
}
