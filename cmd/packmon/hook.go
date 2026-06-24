package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/8linkz-sec/packmon/internal/termtext"
	"github.com/spf13/cobra"
)

// hookMarker identifies a packmon-managed hook file.
const hookMarker = "# packmon managed hook"

// hookTypes lists the hook types packmon can manage.
var hookTypes = []string{"pre-push", "pre-commit"}

// hookScript returns the shell script content for a packmon Git hook.
func hookScript(failOn string) string {
	failOn = normalizeSeverityString(failOn)
	if err := validateSeverityString(failOn); err != nil || failOn == "" {
		failOn = "CRITICAL"
	}
	return fmt.Sprintf(`#!/bin/sh
# packmon managed hook -- do not edit
# To remove: packmon hook uninstall
packmon scan . --fail-on %s --quiet
`, failOn)
}

// findGitRoot walks up from dir looking for a .git directory or gitdir file.
// Returns the repository root (the parent of .git) or empty string if not found.
func findGitRoot(dir string) string {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return ""
	}
	for {
		gitDir := filepath.Join(dir, ".git")
		info, err := os.Stat(gitDir)
		if err == nil {
			if info.IsDir() || gitDirFileTarget(dir) != "" {
				return dir
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			// Reached filesystem root without finding .git.
			return ""
		}
		dir = parent
	}
}

func findGitHooksDir(root string) string {
	if hooksDir := gitResolvedHooksDir(root); hooksDir != "" {
		return hooksDir
	}
	if gitDir := gitDirFileTarget(root); gitDir != "" {
		return filepath.Join(gitDir, "hooks")
	}
	return filepath.Join(root, ".git", "hooks")
}

func gitResolvedHooksDir(root string) string {
	ctx, cancel := context.WithTimeout(context.Background(), gitMetadataTimeout)
	defer cancel()

	out, err := gitCommandOutput(ctx, "-C", root, "rev-parse", "--show-toplevel", "--git-path", "hooks")
	if err != nil {
		return ""
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) < 2 {
		return ""
	}
	if !sameCleanPath(lines[0], root) {
		return ""
	}
	hooksDir := strings.TrimSpace(lines[1])
	if hooksDir == "" {
		return ""
	}
	if !filepath.IsAbs(hooksDir) {
		hooksDir = filepath.Join(root, hooksDir)
	}
	return filepath.Clean(hooksDir)
}

func sameCleanPath(a, b string) bool {
	a = filepath.Clean(strings.TrimSpace(a))
	b = filepath.Clean(strings.TrimSpace(b))
	if runtime.GOOS == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}

func gitDirFileTarget(root string) string {
	data, err := os.ReadFile(filepath.Join(root, ".git")) // #nosec G304 -- path is derived from the discovered repository root.
	if err != nil {
		return ""
	}
	line, _, _ := strings.Cut(string(data), "\n")
	key, value, ok := strings.Cut(strings.TrimSpace(line), ":")
	if !ok || !strings.EqualFold(strings.TrimSpace(key), "gitdir") {
		return ""
	}
	gitDir := strings.TrimSpace(value)
	if gitDir == "" {
		return ""
	}
	if !filepath.IsAbs(gitDir) {
		gitDir = filepath.Join(root, gitDir)
	}
	return filepath.Clean(gitDir)
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
			hookType, failOn, err := hookDefaultsFromConfig()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: cannot load hook configuration: %v\n", err)
				os.Exit(ExitOperational)
			}
			if strings.TrimSpace(flagType) != "" {
				hookType = strings.TrimSpace(flagType)
			}

			// Validate hook type.
			if hookType != "pre-push" && hookType != "pre-commit" {
				fmt.Fprintf(os.Stderr, "Error: unsupported hook type %q (use pre-push or pre-commit)\n", hookType)
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

			hooksDir := findGitHooksDir(root)
			hookPath := filepath.Join(hooksDir, hookType)

			// Check if hook already exists.
			if _, err := os.Stat(hookPath); err == nil {
				if !isPackmonHook(hookPath) {
					fmt.Fprintf(os.Stderr, "Warning: %s hook already exists and is not managed by packmon.\n", hookType)
					fmt.Fprintf(os.Stderr, "Remove it manually or back it up before installing the packmon hook.\n")
					fmt.Fprintf(os.Stderr, "Path: %s\n", termtext.Sanitize(hookPath))
					os.Exit(ExitOperational)
				}
				// Existing packmon hook -- overwrite (update).
			}

			// Ensure hooks directory exists (some bare clones may lack it).
			if err := os.MkdirAll(hooksDir, 0o750); err != nil { // #nosec G301 -- Git hooks directory must be traversable by the local repository owner.
				fmt.Fprintf(os.Stderr, "Error: cannot create hooks directory: %v\n", err)
				os.Exit(ExitOperational)
			}

			// #nosec G306 -- hooks must be executable for Git to run them.
			if err := os.WriteFile(hookPath, []byte(hookScript(failOn)), 0o755); err != nil {
				fmt.Fprintf(os.Stderr, "Error: cannot write hook file: %v\n", err)
				os.Exit(ExitOperational)
			}

			fmt.Printf("Installed packmon %s hook in %s\n", hookType, termtext.Sanitize(hookPath))
			return nil
		},
	}

	cmd.Flags().StringVar(&flagType, "type", "", "hook type (pre-push|pre-commit; default: config hook.type or pre-push)")

	return cmd
}

func hookDefaultsFromConfig() (hookType, failOn string, err error) {
	hookType = "pre-push"
	failOn = "CRITICAL"
	cfg, _, err := loadCurrentCLIConfig()
	if err != nil {
		return "", "", err
	}
	if cfg == nil {
		return hookType, failOn, nil
	}
	if cfg.Hook.Type != "" {
		hookType = cfg.Hook.Type
	}
	if cfg.Hook.FailOn != "" {
		failOn = cfg.Hook.FailOn
	} else if cfg.FailOn != "" {
		failOn = cfg.FailOn
	}
	return hookType, failOn, nil
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
				hookPath := filepath.Join(findGitHooksDir(root), hookType)
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

			fmt.Printf("Repository: %s\n", termtext.Sanitize(root))
			hooksDir := findGitHooksDir(root)
			for _, hookType := range hookTypes {
				hookPath := filepath.Join(hooksDir, hookType)
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
