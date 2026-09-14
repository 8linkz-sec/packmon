package main

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestRejectSecretFlagValuePropagatesChangedNonStringFlagError(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().Bool("token", false, "test-only non-string flag")
	if err := cmd.Flags().Set("token", "true"); err != nil {
		t.Fatalf("set token flag: %v", err)
	}

	err := rejectSecretFlagValue(cmd, "token", "PACKMON_TOKEN")
	if err == nil {
		t.Fatal("rejectSecretFlagValue() error = nil, want GetString type error")
	}
	if !strings.Contains(err.Error(), "string") {
		t.Fatalf("rejectSecretFlagValue() error = %q, want GetString type context", err)
	}
}

func TestSecretFlagStringValueNilAndMissingFlagAreEmpty(t *testing.T) {
	t.Parallel()

	missing := &cobra.Command{Use: "test"}
	for _, tc := range []struct {
		name string
		cmd  *cobra.Command
	}{
		{name: "nil command"},
		{name: "missing flag", cmd: missing},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := secretFlagStringValue(tc.cmd, "token")
			if err != nil {
				t.Fatalf("secretFlagStringValue() error = %v, want nil", err)
			}
			if got != "" {
				t.Fatalf("secretFlagStringValue() = %q, want empty", got)
			}
		})
	}
}
