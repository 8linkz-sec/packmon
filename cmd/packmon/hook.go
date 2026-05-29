package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

// hookMarker identifies a packmon-managed hook file.
const hookMarker = "# packmon managed hook"

// hookTypes lists the hook types packmon can manage.
var hookTypes = []string{"pre-push", "pre-commit"}

// hookScript returns the shell script content for a packmon Git hook.
func hookScript() string {
	return `#!/bin/sh
# packmon managed hook -- do not edit
# To remove: packmon hook uninstall
packmon scan . --fail-on CRITICAL --quiet
`
}

// findGitRoot walks up from dir looking for a .git directory.
// Returns the repository root (the parent of .git) or empty string if not found.
func findGitRoot(dir string) string {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return ""
	}
	for {
		gitDir := filepath.Join(dir, ".git")
		info, err := os.Stat(gitDir)
		if err == nil && info.IsDir() {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			// Reached filesystem root without finding .git.
			return ""
		}
		dir = parent
	}
}

// isPackmonHook returns true if the file at path contains the packmon marker.
func isPackmonHook(path string) bool {
	data, err := os.ReadFile(path) // #nosec G304 -- path is built from .git/hooks/ + known hook name
	if err != nil {
		return false
	}
	return strings.Contains(string(data), hookMarker)
}

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
		RunE: func(_ *cobra.Command, _ []string) error {
			// Validate hook type.
			if flagType != "pre-push" && flagType != "pre-commit" {
				fmt.Fprintf(os.Stderr, "Error: unsupported hook type %q (use pre-push or pre-commit)\n", flagType)
				os.Exit(ExitOperational)
			}

			cwd, err := os.Getwd()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: cannot determine working directory: %v\n", err)
				os.Exit(ExitOperational)
			}

			root := findGitRoot(cwd)
			if root == "" {
				fmt.Println("Not in a git repository.")
				return nil
			}

			hooksDir := filepath.Join(root, ".git", "hooks")
			hookPath := filepath.Join(hooksDir, flagType)

			// Check if hook already exists.
			if _, err := os.Stat(hookPath); err == nil {
				if !isPackmonHook(hookPath) {
					fmt.Fprintf(os.Stderr, "Warning: %s hook already exists and is not managed by packmon.\n", flagType)
					fmt.Fprintf(os.Stderr, "Remove it manually or back it up before installing the packmon hook.\n")
					fmt.Fprintf(os.Stderr, "Path: %s\n", hookPath)
					os.Exit(ExitOperational)
				}
				// Existing packmon hook -- overwrite (update).
			}

			// Ensure hooks directory exists (some bare clones may lack it).
			if err := os.MkdirAll(hooksDir, 0o750); err != nil { // #nosec G301
				fmt.Fprintf(os.Stderr, "Error: cannot create hooks directory: %v\n", err)
				os.Exit(ExitOperational)
			}

			//nolint:gosec // hooks must be executable for Git to run them.
			if err := os.WriteFile(hookPath, []byte(hookScript()), 0o755); err != nil { // #nosec G306 -- hooks must be executable
				fmt.Fprintf(os.Stderr, "Error: cannot write hook file: %v\n", err)
				os.Exit(ExitOperational)
			}

			fmt.Printf("Installed packmon %s hook in %s\n", flagType, hookPath)
			return nil
		},
	}

	cmd.Flags().StringVar(&flagType, "type", "pre-push", "hook type (pre-push|pre-commit)")

	return cmd
}

func newHookUninstallCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "uninstall",
		Short: "Remove packmon hook from current repo",
		RunE: func(_ *cobra.Command, _ []string) error {
			cwd, err := os.Getwd()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: cannot determine working directory: %v\n", err)
				os.Exit(ExitOperational)
			}

			root := findGitRoot(cwd)
			if root == "" {
				fmt.Println("Not in a git repository.")
				return nil
			}

			removed := 0
			for _, hookType := range hookTypes {
				hookPath := filepath.Join(root, ".git", "hooks", hookType)
				if _, err := os.Stat(hookPath); os.IsNotExist(err) {
					continue
				}
				if !isPackmonHook(hookPath) {
					fmt.Printf("Skipping %s: not a packmon-managed hook.\n", hookType)
					continue
				}
				if err := os.Remove(hookPath); err != nil {
					fmt.Fprintf(os.Stderr, "Error: cannot remove %s hook: %v\n", hookType, err)
					os.Exit(ExitOperational)
				}
				fmt.Printf("Removed packmon %s hook.\n", hookType)
				removed++
			}

			if removed == 0 {
				fmt.Println("No packmon-managed hooks found.")
			}
			return nil
		},
	}
}

func newHookStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show hook status in current repo",
		RunE: func(_ *cobra.Command, _ []string) error {
			cwd, err := os.Getwd()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: cannot determine working directory: %v\n", err)
				os.Exit(ExitOperational)
			}

			root := findGitRoot(cwd)
			if root == "" {
				fmt.Println("Not in a git repository.")
				return nil
			}

			fmt.Printf("Repository: %s\n", root)
			for _, hookType := range hookTypes {
				hookPath := filepath.Join(root, ".git", "hooks", hookType)
				info, err := os.Stat(hookPath)
				if os.IsNotExist(err) {
					fmt.Printf("  %-12s not installed\n", hookType+":")
					continue
				}
				if err != nil {
					fmt.Printf("  %-12s error: %v\n", hookType+":", err)
					continue
				}
				_ = info
				if isPackmonHook(hookPath) {
					fmt.Printf("  %-12s packmon hook installed\n", hookType+":")
				} else {
					fmt.Printf("  %-12s custom hook (not packmon)\n", hookType+":")
				}
			}
			return nil
		},
	}
}
