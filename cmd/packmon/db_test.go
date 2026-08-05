package main

import (
	"strings"
	"testing"
)

func TestDBSyncSourceHelpOnlyAdvertisesServer(t *testing.T) {
	t.Parallel()

	cmd := newDBSyncCmd()
	flag := cmd.Flag("source")
	if flag == nil {
		t.Fatal("source flag missing")
	}
	if strings.Contains(flag.Usage, "osv") {
		t.Fatalf("source flag usage = %q, should not advertise unsupported osv source", flag.Usage)
	}
}

func TestDBSyncRejectsUnsupportedSource(t *testing.T) {
	// Isolate config discovery so loadCurrentCLIConfig finds nothing.
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Chdir(t.TempDir())

	for _, src := range []string{"osv", "OSV", "ghsa"} {
		cmd := newDBSyncCmd()
		cmd.SetArgs([]string{"--source", src})
		cmd.SilenceUsage = true
		cmd.SilenceErrors = true

		err := cmd.Execute()
		if err == nil {
			t.Fatalf("--source %q: expected error, got nil", src)
		}
		if !strings.Contains(err.Error(), "not yet implemented") {
			t.Fatalf("--source %q: error = %v, want 'not yet implemented'", src, err)
		}
	}
}
