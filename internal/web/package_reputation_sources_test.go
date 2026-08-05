package web

import (
	"os"
	"strings"
	"testing"
)

func TestPackageReadPathsUseReputationSourceDescriptors(t *testing.T) {
	source, err := os.ReadFile("package.go")
	if err != nil {
		t.Fatalf("read package.go: %v", err)
	}
	if strings.Contains(string(source), "ReputationSourceReversingLabs") {
		t.Fatal("package.go references the ReversingLabs reputation constant directly; read paths must use reputation source descriptors")
	}
	if !strings.Contains(string(source), "ReputationReadSources()") {
		t.Fatal("package.go must load reputation findings through configured reputation read sources")
	}
}
