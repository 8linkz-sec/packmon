package main

import (
	"runtime"
	"strings"
	"testing"
)

func TestVersionCommandPrintsBuildMetadata(t *testing.T) {
	cmd := newVersionCmd()
	cmd.SetArgs([]string{})
	output := captureStdout(t, func() {
		if err := cmd.Execute(); err != nil {
			t.Fatalf("version command: %v", err)
		}
	})

	for _, want := range []string{"packmon ", runtime.GOOS + "/" + runtime.GOARCH} {
		if !strings.Contains(output, want) {
			t.Fatalf("version output = %q, missing %q", output, want)
		}
	}
}

func TestEnvHelpers(t *testing.T) {
	t.Setenv("PACKMON_TEST_VALUE", "from-env")
	if got := envOrDefault("PACKMON_TEST_VALUE", "fallback"); got != "from-env" {
		t.Fatalf("envOrDefault(existing) = %q", got)
	}
	if got := envOrDefault("PACKMON_MISSING_VALUE", "fallback"); got != "fallback" {
		t.Fatalf("envOrDefault(missing) = %q", got)
	}

	for _, value := range []string{"true", "1", "yes"} {
		t.Setenv("PACKMON_TEST_BOOL", value)
		if !envBool("PACKMON_TEST_BOOL") {
			t.Fatalf("envBool(%q) = false, want true", value)
		}
	}
	t.Setenv("PACKMON_TEST_BOOL", "false")
	if envBool("PACKMON_TEST_BOOL") {
		t.Fatal("envBool(false) = true")
	}
}

func TestRootCommandRegistersExpectedSubcommands(t *testing.T) {
	originalConfig := flagConfig
	originalLogLevel := flagLogLevel
	originalQuiet := flagQuiet
	originalNoColor := flagNoColor
	t.Cleanup(func() {
		flagConfig = originalConfig
		flagLogLevel = originalLogLevel
		flagQuiet = originalQuiet
		flagNoColor = originalNoColor
	})

	t.Setenv("PACKMON_NO_COLOR", "true")
	cmd := newRootCmd()

	for _, name := range []string{"scan", "version", "dashboard", "db", "config", "hook", "history", "report"} {
		if found, _, err := cmd.Find([]string{name}); err != nil || found == nil || found.Name() != name {
			t.Fatalf("root command missing %q: found=%v err=%v", name, found, err)
		}
	}
	if flag := cmd.PersistentFlags().Lookup("no-color"); flag == nil {
		t.Fatal("root command missing --no-color")
	}
}
