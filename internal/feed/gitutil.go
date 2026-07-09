package feed

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	defaultGitCommandTimeout = 5 * time.Minute
	gitSyncLockFileName      = ".packmon-sync.lock"
	gitSyncLockPollInterval  = 25 * time.Millisecond
)

var (
	gitExecutable     = "git"
	gitExecutableArgs []string
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
	// CommandTimeout bounds each individual git command. When zero, a
	// conservative default is used.
	CommandTimeout time.Duration
}

// EnsureCloned clones the repo if it does not exist locally, or pulls
// the latest changes if it does. It returns the current HEAD commit
// hash after the operation.
func (g *GitRepo) EnsureCloned(ctx context.Context) (commitHash string, err error) {
	log := g.Logger.With(slog.String("repo", g.URL))

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
		return pathOperationError("creating parent directory", parent, err)
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
	if !g.isCloned() {
		return "", fmt.Errorf("not a git clone")
	}

	var stdout bytes.Buffer
	cmdCtx, cancel := g.commandContext(ctx)
	defer cancel()
	cmd := gitCommand(cmdCtx, "rev-parse", "HEAD")
	cmd.Dir = g.Dir
	cmd.Stdout = &stdout
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	cmd.WaitDelay = 2 * time.Second

	if err := cmd.Run(); err != nil {
		if cmdCtx.Err() != nil {
			return "", gitCommandError([]string{"rev-parse", "HEAD"}, cmdCtx.Err(), stdout.String(), stderr.String())
		}
		return "", gitCommandError([]string{"rev-parse", "HEAD"}, err, stdout.String(), stderr.String())
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
	log := g.Logger.With(slog.String("repo", g.URL))

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

	releaseSyncLock, err := g.acquireSyncLock(ctx)
	if err != nil {
		return "", nil, fmt.Errorf("acquire git sync lock: %w", err)
	}
	defer releaseSyncLock()

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
	cmdCtx, cancel := g.commandContext(ctx)
	defer cancel()
	// #nosec G204 -- command is fixed to git; oldHash is read from git itself and origin/HEAD is fixed.
	cmd := gitCommand(cmdCtx, "diff", "--name-only", oldHash, "origin/HEAD")
	cmd.Dir = g.Dir
	cmd.Stdout = &stdout
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	cmd.WaitDelay = 2 * time.Second

	if diffErr := cmd.Run(); diffErr != nil {
		if cmdCtx.Err() != nil {
			diffErr = cmdCtx.Err()
		}
		diffErr = gitCommandError([]string{"diff", "--name-only", oldHash, "origin/HEAD"}, diffErr, stdout.String(), stderr.String())
		log.Warn("git diff failed, delta sync not available",
			slog.String("error", SafeDiagnosticError(diffErr)),
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

	// Step 4: remove stale index.lock if a previous git process crashed.
	lockFile := filepath.Join(g.Dir, ".git", "index.lock")
	if _, statErr := os.Stat(lockFile); statErr == nil {
		log.Warn("removing stale git index.lock", slog.String("file", filepath.Base(lockFile)))
		_ = os.Remove(lockFile)
	}

	// Step 5: reset to origin/HEAD.
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

func (g *GitRepo) acquireSyncLock(ctx context.Context) (func(), error) {
	if ctx == nil {
		ctx = context.Background()
	}
	lockFile := filepath.Join(g.Dir, gitSyncLockFileName)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		file, err := os.OpenFile(lockFile, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			_ = file.Close()
			return func() {
				if err := os.Remove(lockFile); err != nil && !os.IsNotExist(err) && g.Logger != nil {
					g.Logger.Warn("removing git sync lock failed",
						slog.String("file", filepath.Base(lockFile)),
						slog.String("error", SafeDiagnosticError(err)),
					)
				}
			}, nil
		}
		if !os.IsExist(err) {
			return nil, pathOperationError("creating sync lock", lockFile, err)
		}

		timer := time.NewTimer(gitSyncLockPollInterval)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

// run executes a git command in the given directory and returns any error.
func (g *GitRepo) run(ctx context.Context, dir string, args ...string) error {
	cmdCtx, cancel := g.commandContext(ctx)
	defer cancel()

	// #nosec G204 -- command is fixed to git; arguments are internal git subcommands and repo values.
	cmd := gitCommand(cmdCtx, args...)
	cmd.Dir = dir
	// WaitDelay prevents cmd.Wait() from blocking indefinitely draining
	// stdout/stderr pipes after the process has been killed via context
	// cancellation. Without this, a killed git clone can leave the Go
	// goroutine stuck in Wait() for 30+ seconds.
	cmd.WaitDelay = 2 * time.Second

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if cmdCtx.Err() != nil {
			return gitCommandError(args, cmdCtx.Err(), stdout.String(), stderr.String())
		}
		return gitCommandError(args, err, stdout.String(), stderr.String())
	}
	return nil
}

func gitCommand(ctx context.Context, args ...string) *exec.Cmd {
	cmdArgs := append([]string(nil), gitExecutableArgs...)
	cmdArgs = append(cmdArgs, args...)
	// #nosec G204 -- gitExecutable is fixed in production; tests override it with the test binary.
	return exec.CommandContext(ctx, gitExecutable, cmdArgs...)
}

func (g *GitRepo) commandContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	timeout := g.CommandTimeout
	if timeout <= 0 {
		timeout = defaultGitCommandTimeout
	}
	return context.WithTimeout(ctx, timeout)
}

func gitCommandError(args []string, cause error, stdout, stderr string) error {
	detail := strings.TrimSpace(stderr)
	if detail == "" {
		detail = strings.TrimSpace(stdout)
	}
	if detail == "" {
		return fmt.Errorf("git %s: %w", strings.Join(args, " "), cause)
	}
	return fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), cause, SafeDiagnosticMessage(detail))
}

func pathOperationError(action, path string, err error) error {
	var pathErr *os.PathError
	if errors.As(err, &pathErr) && pathErr.Err != nil {
		return fmt.Errorf("%s %q: %w", action, filepath.Base(path), pathErr.Err)
	}
	return fmt.Errorf("%s %q: %s", action, filepath.Base(path), SafeDiagnosticError(err))
}
