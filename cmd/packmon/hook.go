package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newHookCmd() *cobra.Command {
	hookCmd := &cobra.Command{
		Use:   "hook",
		Short: "Manage Git hooks",
		Long:  "Install, uninstall, or check status of the packmon Git hook in the current repository.",
	}

	hookCmd.AddCommand(
		newHookInstallCmd(),
		newHookUninstallCmd(),
		newHookStatusCmd(),
	)

	return hookCmd
}

func newHookInstallCmd() *cobra.Command {
	var flagType string

	cmd := &cobra.Command{
		Use:   "install",
		Short: "Install packmon hook in current repo",
		Run: func(_ *cobra.Command, _ []string) {
			fmt.Printf("hook install (%s) not yet implemented\n", flagType)
		},
	}

	cmd.Flags().StringVar(&flagType, "type", "pre-push", "hook type (pre-push|pre-commit)")

	return cmd
}

func newHookUninstallCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "uninstall",
		Short: "Remove packmon hook from current repo",
		Run: func(_ *cobra.Command, _ []string) {
			fmt.Println("hook uninstall not yet implemented")
		},
	}
}

func newHookStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show hook status in current repo",
		Run: func(_ *cobra.Command, _ []string) {
			fmt.Println("hook status not yet implemented")
		},
	}
}
