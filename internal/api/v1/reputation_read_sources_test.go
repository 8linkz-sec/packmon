package v1

import (
	"os"
	"strings"
	"testing"
)

func TestHandlerReadPathsUseReputationSourceDescriptors(t *testing.T) {
	source, err := os.ReadFile("handler.go")
	if err != nil {
		t.Fatalf("read handler.go: %v", err)
	}
	if strings.Contains(string(source), "ReputationSourceReversingLabs") {
		t.Fatal("handler.go references the ReversingLabs reputation constant directly; read paths must use reputation source descriptors")
	}
	if !strings.Contains(string(source), "reputationReadSources()") {
		t.Fatal("handler.go must expose reputation read sources through a descriptor helper")
	}
}
