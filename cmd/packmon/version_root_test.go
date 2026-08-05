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

	t.Setenv("PACKMON_NO_COLOR", "")
	t.Setenv("NO_COLOR", "1")
	if !defaultNoColor() {
		t.Fatal("defaultNoColor() = false, want true when NO_COLOR is set")
	}
}

func TestRootCommandRegistersExpectedSubcommands(t *testing.T) {
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
	if flag := cmd.PersistentFlags().Lookup("no-project-config"); flag == nil {
		t.Fatal("root command missing --no-project-config")
	}
}

func TestPrimaryHelpMentionsCurrentFindingScope(t *testing.T) {
	root := newRootCmd()
	scan, _, err := root.Find([]string{"scan"})
	if err != nil {
		t.Fatalf("find scan command: %v", err)
	}

	rootHelp := strings.ToLower(root.Short + "\n" + root.Long)
	scanHelp := strings.ToLower(scan.Short + "\n" + scan.Long)
	for label, text := range map[string]string{
		"root": rootHelp,
		"scan": scanHelp,
	} {
		for _, want := range []string{"vulnerab", "malicious", "supply-chain", "lifecycle", "sbom"} {
			if !strings.Contains(text, want) {
				t.Fatalf("%s help missing current finding scope marker %q:\n%s", label, want, text)
			}
		}
	}
}
