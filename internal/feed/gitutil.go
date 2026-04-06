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
	"time"
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
	if err := os.MkdirAll(parent, 0o750); err != nil {
		return fmt.Errorf("creating parent directory: %w", err)
	}

	return g.run(ctx, parent,
		"clone", "--depth=1", "--single-branch", g.URL, filepath.Base(g.Dir),
	)
}

// pull fetches and resets to the latest remote HEAD. We use fetch+reset
// rather than plain pull to handle force-pushes gracefully.
func (g *GitRepo) pull(ctx context.Context) error {
	if err := g.run(ctx, g.Dir, "fetch", "--depth=1", "origin"); err != nil {
		return err
	}
	return g.run(ctx, g.Dir, "reset", "--hard", "origin/HEAD")
}

// headHash reads the current HEAD commit hash.
func (g *GitRepo) headHash(ctx context.Context) (string, error) {
	var stdout bytes.Buffer
	cmd := exec.CommandContext(ctx, "git", "rev-parse", "HEAD")
	cmd.Dir = g.Dir
	cmd.Stdout = &stdout
	cmd.Stderr = os.Stderr
	cmd.WaitDelay = 2 * time.Second

	if err := cmd.Run(); err != nil {
		return "", err
	}

	return strings.TrimSpace(stdout.String()), nil
}

// PullWithChangedFiles fetches the latest changes, computes the list of
// changed files between the current HEAD and the fetched origin/HEAD,
// then resets to origin/HEAD. It returns the new commit hash and the
// list of changed files. If the repo was freshly cloned (oldHash is
// empty), changedFiles will be nil (meaning the caller should do a full
// walk). This method must be called instead of EnsureCloned when delta
// detection is desired, because after a shallow fetch+reset the old
// commit is no longer reachable.
func (g *GitRepo) PullWithChangedFiles(ctx context.Context) (newHash string, changedFiles []string, err error) {
	log := g.Logger.With(slog.String("repo", g.URL), slog.String("dir", g.Dir))

	if !g.isCloned() {
		log.Info("cloning repository (shallow)")
		if err := g.clone(ctx); err != nil {
			return "", nil, fmt.Errorf("git clone: %w", err)
		}
		hash, err := g.headHash(ctx)
		if err != nil {
			return "", nil, fmt.Errorf("git rev-parse HEAD: %w", err)
		}
		// Fresh clone: no delta available.
		return hash, nil, nil
	}

	log.Debug("repository already cloned, fetching updates")

	// Step 1: record current HEAD before fetch.
	oldHash, err := g.headHash(ctx)
	if err != nil {
		return "", nil, fmt.Errorf("git rev-parse HEAD (pre-fetch): %w", err)
	}

	// Step 2: fetch latest from origin.
	if err := g.run(ctx, g.Dir, "fetch", "--depth=1", "origin"); err != nil {
		return "", nil, fmt.Errorf("git fetch: %w", err)
	}

	// Step 3: compute diff between local HEAD and fetched origin/HEAD.
	// Both commits are still reachable at this point (before reset).
	var diffFiles []string
	var stdout bytes.Buffer
	cmd := exec.CommandContext(ctx, "git", "diff", "--name-only", oldHash, "origin/HEAD")
	cmd.Dir = g.Dir
	cmd.Stdout = &stdout
	cmd.Stderr = os.Stderr
	cmd.WaitDelay = 2 * time.Second

	if diffErr := cmd.Run(); diffErr != nil {
		log.Warn("git diff failed, delta sync not available",
			slog.String("error", diffErr.Error()),
		)
		// diffFiles stays nil -> caller does full walk.
	} else {
		lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" {
				diffFiles = append(diffFiles, line)
			}
		}
	}

	// Step 4: reset to origin/HEAD.
	if err := g.run(ctx, g.Dir, "reset", "--hard", "origin/HEAD"); err != nil {
		return "", nil, fmt.Errorf("git reset: %w", err)
	}

	hash, err := g.headHash(ctx)
	if err != nil {
		return "", nil, fmt.Errorf("git rev-parse HEAD (post-reset): %w", err)
	}

	if oldHash == hash {
		// No changes -- return empty list (not nil) to signal "no changes".
		return hash, []string{}, nil
	}

	return hash, diffFiles, nil
}

// run executes a git command in the given directory and returns any error.
func (g *GitRepo) run(ctx context.Context, dir string, args ...string) error {
	// #nosec G204 -- command is fixed to git; arguments are internal git subcommands and repo values.
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = dir
	// WaitDelay prevents cmd.Wait() from blocking indefinitely draining
	// stdout/stderr pipes after the process has been killed via context
	// cancellation. Without this, a killed git clone can leave the Go
	// goroutine stuck in Wait() for 30+ seconds.
	cmd.WaitDelay = 2 * time.Second

	var stderr bytes.Buffer
	cmd.Stdout = os.Stderr // git clone/fetch progress goes to stderr anyway
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("git %s: %w\nstderr: %s", strings.Join(args, " "), err, stderr.String())
	}
	return nil
}
