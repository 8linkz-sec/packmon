package main

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version, commit, build date, and OS/Arch",
		Args:  cobra.NoArgs,
		Run: func(_ *cobra.Command, _ []string) {
			fmt.Printf("packmon %s (%s) built %s %s/%s\n",
				version, commit, date, runtime.GOOS, runtime.GOARCH)
		},
	}
}
