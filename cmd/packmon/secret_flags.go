package main

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

//nolint:gosec // G101: environment variable name, not a credential.
const allowSecretFlagsEnv = "PACKMON_ALLOW_SECRET_FLAGS"

func rejectSecretFlagValue(cmd *cobra.Command, flagName, replacement string) error {
	if !commandFlagChanged(cmd, flagName) {
		return nil
	}
	value, err := secretFlagStringValue(cmd, flagName)
	if err != nil {
		return err
	}
	if strings.TrimSpace(value) == "" {
		return nil
	}

	allowed, _, err := strictEnvBool(allowSecretFlagsEnv)
	if err != nil {
		return err
	}
	if allowed {
		return nil
	}

	return fmt.Errorf("--%s no longer accepts secret values on the command line by default; use %s instead (temporary argv compatibility requires %s=true)", flagName, replacement, allowSecretFlagsEnv)
}

func secretFlagStringValue(cmd *cobra.Command, flagName string) (string, error) {
	if cmd == nil || cmd.Flags().Lookup(flagName) == nil {
		return "", nil
	}
	return cmd.Flags().GetString(flagName)
}
