package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

const mainUnknownCommandHelperEnv = "PACKMON_MAIN_UNKNOWN_COMMAND_HELPER"

func TestMainUnknownCommandWritesSingleDiagnosticAndExitUsage(t *testing.T) {
	//nolint:gosec // G204: the test re-executes its own test binary as a process-exit harness.
	cmd := exec.Command(os.Args[0], "-test.run=^TestMainUnknownCommandHelper$")
	cmd.Env = append(os.Environ(), mainUnknownCommandHelperEnv+"=1")

	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err == nil {
		t.Fatal("unknown command helper exited successfully")
	}
	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("run unknown command helper: %v", err)
	}
	if got := exitErr.ExitCode(); got != 2 {
		t.Fatalf("unknown command exit code = %d, want 2; stderr=%q", got, stderr.String())
	}
	if got := stdout.String(); got != "" {
		t.Fatalf("unknown command stdout = %q, want empty", got)
	}
	const want = "Error: unknown command \"unknown-command-for-contract\" for \"packmon\"\n"
	if got := stderr.String(); got != want {
		t.Fatalf("unknown command stderr = %q, want exactly %q", got, want)
	}
}

func TestMainUnknownCommandHelper(t *testing.T) {
	if os.Getenv(mainUnknownCommandHelperEnv) != "1" {
		return
	}
	os.Args = []string{"packmon", "unknown-command-for-contract"}
	main()
}
