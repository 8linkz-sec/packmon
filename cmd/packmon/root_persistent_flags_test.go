package main

import (
	"io"
	"testing"
)

func TestRootPersistentFlagsRegisterDefaultsAndReachChildCommand(t *testing.T) {
	originalConfig := flagConfig
	originalLogLevel := flagLogLevel
	originalQuiet := flagQuiet
	originalNoColor := flagNoColor
	originalNoProjectConfig := flagNoProjectConfig
	t.Cleanup(func() {
		flagConfig = originalConfig
		flagLogLevel = originalLogLevel
		flagQuiet = originalQuiet
		flagNoColor = originalNoColor
		flagNoProjectConfig = originalNoProjectConfig
	})

	t.Setenv("PACKMON_LOG_LEVEL", "")
	t.Setenv("PACKMON_NO_COLOR", "true")
	cmd := newRootCmd()
	for name, wantDefault := range map[string]string{
		"config":            "",
		"log-level":         "INFO",
		"quiet":             "false",
		"no-color":          "true",
		"no-project-config": "false",
	} {
		flag := cmd.PersistentFlags().Lookup(name)
		if flag == nil {
			t.Fatalf("root command missing persistent --%s", name)
		}
		if got := flag.DefValue; got != wantDefault {
			t.Fatalf("persistent --%s default = %q, want %q", name, got, wantDefault)
		}
	}

	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{
		"--config", "custom.yaml",
		"--log-level", "debug",
		"--quiet",
		"--no-color=false",
		"--no-project-config",
		"version",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute child command with inherited root flags: %v", err)
	}
	if flagConfig != "custom.yaml" || flagLogLevel != "debug" || !flagQuiet || flagNoColor || !flagNoProjectConfig {
		t.Fatalf("inherited root flags = config=%q logLevel=%q quiet=%t noColor=%t noProjectConfig=%t", flagConfig, flagLogLevel, flagQuiet, flagNoColor, flagNoProjectConfig)
	}
}
