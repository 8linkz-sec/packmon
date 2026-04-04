package feed

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// GitRepo manages a shallow clone of a git repository on disk. It
// handles initial cloning and subsequent pulls, and reports the
// current HEAD commit hash for delta tracking.
type GitRepo struct {
	// URL is the remote repository URL.
	URL string
	// Dir is the local directory where the repo is (or will be) cloned.
	Dir string
	// Logger for git operations.
	Logger *slog.Logger
}

// EnsureCloned clones the repo if it does not exist locally, or pulls
// the latest changes if it does. It returns the current HEAD commit
// hash after the operation.
func (g *GitRepo) EnsureCloned(ctx context.Context) (commitHash string, err error) {
	log := g.Logger.With(slog.String("repo", g.URL), slog.String("dir", g.Dir))

	if g.isCloned() {
		log.Debug("repository already cloned, pulling updates")
		if err := g.pull(ctx); err != nil {
			return "", fmt.Errorf("git pull: %w", err)
		}
	} else {
		log.Info("cloning repository (shallow)")
		if err := g.clone(ctx); err != nil {
			return "", fmt.Errorf("git clone: %w", err)
		}
	}

	hash, err := g.headHash(ctx)
	if err != nil {
		return "", fmt.Errorf("git rev-parse HEAD: %w", err)
	}

	log.Debug("repository ready", slog.String("commit", hash))
	return hash, nil
}

// HeadHash returns the current HEAD commit hash without modifying the
// repository. Returns an error if the directory is not a git repository.
func (g *GitRepo) HeadHash(ctx context.Context) (string, error) {
	return g.headHash(ctx)
}

// isCloned checks whether the local directory contains a .git directory.
func (g *GitRepo) isCloned() bool {
	info, err := os.Stat(filepath.Join(g.Dir, ".git"))
	return err == nil && info.IsDir()
}

// clone performs a shallow clone (depth=1) of the repository.
func (g *GitRepo) clone(ctx context.Context) error {
	// Ensure parent directory exists.
	parent := filepath.Dir(g.Dir)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return fmt.Errorf("creating parent directory: %w", err)
	}

	return g.run(ctx, parent,
		"git", "clone", "--depth=1", "--single-branch", g.URL, filepath.Base(g.Dir),
	)
}

// pull fetches and resets to the latest remote HEAD. We use fetch+reset
// rather than plain pull to handle force-pushes gracefully.
func (g *GitRepo) pull(ctx context.Context) error {
	if err := g.run(ctx, g.Dir, "git", "fetch", "--depth=1", "origin"); err != nil {
		return err
	}
	return g.run(ctx, g.Dir, "git", "reset", "--hard", "origin/HEAD")
}

// headHash reads the current HEAD commit hash.
func (g *GitRepo) headHash(ctx context.Context) (string, error) {
	var stdout bytes.Buffer
	cmd := exec.CommandContext(ctx, "git", "rev-parse", "HEAD")
	cmd.Dir = g.Dir
	cmd.Stdout = &stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return "", err
	}

	return strings.TrimSpace(stdout.String()), nil
}

// run executes a git command in the given directory and returns any error.
func (g *GitRepo) run(ctx context.Context, dir string, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir

	var stderr bytes.Buffer
	cmd.Stdout = os.Stderr // git clone/fetch progress goes to stderr anyway
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %s: %w\nstderr: %s", name, strings.Join(args, " "), err, stderr.String())
	}
	return nil
}
