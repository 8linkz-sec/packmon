package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newHistoryCmd() *cobra.Command {
	historyCmd := &cobra.Command{
		Use:   "history",
		Short: "Manage scan history",
		Long:  "View and manage stored scan results.",
	}

	historyCmd.AddCommand(
		newHistoryClearCmd(),
	)

	return historyCmd
}

func newHistoryClearCmd() *cobra.Command {
	var (
		flagBefore string
		flagRepo   string
	)

	cmd := &cobra.Command{
		Use:   "clear",
		Short: "Clear scan history",
		Run: func(_ *cobra.Command, _ []string) {
			fmt.Println("history clear not yet implemented")
		},
	}

	f := cmd.Flags()
	f.StringVar(&flagBefore, "before", "", "clear entries before this date (YYYY-MM-DD)")
	f.StringVar(&flagRepo, "repo", "", "clear entries for specific repository")

	return cmd
}
