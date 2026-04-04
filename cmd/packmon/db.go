package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newDBCmd() *cobra.Command {
	dbCmd := &cobra.Command{
		Use:   "db",
		Short: "Manage local vulnerability database",
		Long:  "Commands for synchronizing and inspecting the local SQLite database used in offline mode.",
	}

	dbCmd.AddCommand(
		newDBSyncCmd(),
		newDBInfoCmd(),
		newDBExportCmd(),
	)

	return dbCmd
}

func newDBSyncCmd() *cobra.Command {
	var (
		flagEcosystems string
		flagFull       bool
		flagSource     string
	)

	cmd := &cobra.Command{
		Use:   "sync",
		Short: "Synchronize local database",
		Run: func(_ *cobra.Command, _ []string) {
			fmt.Println("db sync not yet implemented")
		},
	}

	f := cmd.Flags()
	f.StringVar(&flagEcosystems, "ecosystems", "", "comma-separated ecosystem filter")
	f.BoolVar(&flagFull, "full", false, "full sync instead of incremental")
	f.StringVar(&flagSource, "source", "server", "sync source (server|osv)")

	return cmd
}

func newDBInfoCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "info",
		Short: "Show local database version, age, and entry count",
		Run: func(_ *cobra.Command, _ []string) {
			fmt.Println("db info not yet implemented")
		},
	}
}

func newDBExportCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "export",
		Short: "Export local database as JSON",
		Run: func(_ *cobra.Command, _ []string) {
			fmt.Println("db export not yet implemented")
		},
	}
}
