package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newReportCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "report",
		Short: "Generate security report",
		Run: func(_ *cobra.Command, _ []string) {
			fmt.Println("report not yet implemented")
		},
	}
}
