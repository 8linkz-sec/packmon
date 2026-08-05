package main

import (
	"fmt"
	"time"

	"github.com/8linkz-sec/packmon/internal/ioutils"

	"github.com/8linkz-sec/packmon/internal/db/sqlite"
	"github.com/8linkz-sec/packmon/internal/termtext"
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
		flagForce  bool
	)

	cmd := &cobra.Command{
		Use:   "clear",
		Short: "Clear scan history",
		RunE: func(cmd *cobra.Command, _ []string) error {
			dbPath, err := resolveLocalDBPath()
			if err != nil {
				return err
			}
			store, err := sqlite.New(dbPath)
			if err != nil {
				return fmt.Errorf("open local database: %w", err)
			}
			defer ioutils.CloseSilently(store)

			var before *time.Time
			if flagBefore != "" {
				parsed, err := time.Parse("2006-01-02", flagBefore)
				if err != nil {
					return fmt.Errorf("parse --before: %w", err)
				}
				before = &parsed
			}
			if before == nil && flagRepo == "" && !flagForce {
				return fmt.Errorf("refusing to clear all scan history without --force; pass --repo or --before to scope deletion")
			}

			deleted, err := store.ClearHistory(cmd.Context(), before, flagRepo)
			if err != nil {
				return fmt.Errorf("clear scan history: %w", err)
			}

			fmt.Printf("Cleared %d scan history entr", deleted)
			if deleted == 1 {
				fmt.Print("y")
			} else {
				fmt.Print("ies")
			}
			if flagRepo != "" {
				fmt.Printf(" for repo %q", termtext.Sanitize(flagRepo))
			}
			if before != nil {
				fmt.Printf(" before %s", before.Format("2006-01-02 UTC"))
			}
			fmt.Println(".")
			return nil
		},
	}

	f := cmd.Flags()
	f.StringVar(&flagBefore, "before", "", "clear entries before this UTC date (YYYY-MM-DD)")
	f.StringVar(&flagRepo, "repo", "", "clear entries for specific repository")
	f.BoolVar(&flagForce, "force", false, "allow clearing all scan history without --repo or --before")

	return cmd
}
