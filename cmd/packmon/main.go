package main

import (
	"fmt"
	"os"
	"runtime"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Printf("packmon %s (%s) built %s %s/%s\n", version, commit, date, runtime.GOOS, runtime.GOARCH)
		return
	}

	fmt.Println("packmon - Dependency Security Scanner")
	fmt.Println("Run 'packmon version' for version info")
	os.Exit(0)
}
