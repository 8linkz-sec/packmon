package main

import "testing"

func TestScanOutputArtifactFlagListFormatsEmptySingleAndMultipleRegistries(t *testing.T) {
	original := scanOutputArtifacts
	t.Cleanup(func() {
		scanOutputArtifacts = original
	})

	scanOutputArtifacts = nil
	if got := scanOutputArtifactFlagList(); got != "" {
		t.Fatalf("scanOutputArtifactFlagList() with no artifacts = %q, want empty", got)
	}

	scanOutputArtifacts = []scanOutputArtifact{{flagName: "output-json"}}
	if got := scanOutputArtifactFlagList(); got != "--output-json" {
		t.Fatalf("scanOutputArtifactFlagList() with one artifact = %q, want --output-json", got)
	}

	scanOutputArtifacts = []scanOutputArtifact{
		{flagName: "output-json"},
		{flagName: "output-sarif"},
		{flagName: "html"},
	}
	if got := scanOutputArtifactFlagList(); got != "--output-json, --output-sarif, and --html" {
		t.Fatalf("scanOutputArtifactFlagList() with several artifacts = %q, want Oxford-list format", got)
	}
}
