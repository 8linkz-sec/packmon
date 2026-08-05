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
	// The initial clone gets its own, much larger budget. Incremental
	// fetch/reset work is bounded by the size of the delta, but a first
	// clone of github/advisory-database transfers and checks out ~350k
	// files -- on a container filesystem that routinely exceeds five
	// minutes, and the timeout is unrecoverable: every later attempt
	// starts the same clone from zero and hits the same wall.
	defaultGitCloneTimeout  = 30 * time.Minute
	gitSyncLockFileName     = ".packmon-sync.lock"
	gitSyncLockPollInterval = 25 * time.Millisecond
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
	// CloneTimeout bounds the initial clone only. When zero,
	// defaultGitCloneTimeout applies -- never the shorter CommandTimeout.
	CloneTimeout time.Duration
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

	// --no-progress: git writes per-percent transfer and checkout progress
	// to stderr, and that stderr is what ends up in feed_sync_status as the
	// admin-visible error. Without it a timed-out clone reports a kilobyte
	// of "Updating files: 3% (12265/351744)" instead of its actual cause.
	err := g.runWithTimeout(ctx, g.cloneTimeout(), parent,
		"clone", "--depth=1", "--single-branch", "--no-progress", g.URL, filepath.Base(g.Dir),
	)
	if err != nil {
		// A clone killed by the deadline leaves a partial checkout that
		// still has a .git directory, so isCloned() would accept it and
		// every later sync would fetch/reset against an incomplete work
		// tree instead of cloning again. Drop it and start clean.
		g.removePartialClone()
		return err
	}
	return nil
}

// removePartialClone deletes the target directory after a failed clone. It is
// only ever called on the clone path, which runs when the directory held no
// usable checkout to begin with.
func (g *GitRepo) removePartialClone() {
	if err := os.RemoveAll(g.Dir); err != nil && g.Logger != nil {
		g.Logger.Warn("removing partial clone failed",
			slog.String("dir", filepath.Base(g.Dir)),
			slog.String("error", SafeDiagnosticError(err)),
		)
	}
}

// pull fetches and resets to the latest remote HEAD. We use fetch+reset
// rather than plain pull to handle force-pushes gracefully.
func (g *GitRepo) pull(ctx context.Context) error {
	if err := g.run(ctx, g.Dir, "fetch", "--depth=1", "--no-progress", "origin"); err != nil {
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
// changed files between sinceCommit -- the caller's last successfully
// imported commit -- and the fetched origin/HEAD, then resets to
// origin/HEAD. It returns the new commit hash and the list of changed
// files. changedFiles is nil when no delta is available (empty
// sinceCommit, fresh clone with a different baseline, or sinceCommit not
// reachable in the shallow history) -- the caller must do a full walk.
// The delta baseline is deliberately NOT the checkout's previous HEAD: a
// checkout advanced by an interrupted earlier attempt would otherwise
// report "no changes" and silently skip everything committed since the
// last real import.
func (g *GitRepo) PullWithChangedFiles(ctx context.Context, sinceCommit string) (newHash string, changedFiles []string, err error) {
	log := g.Logger.With(slog.String("repo", g.URL))
	sinceCommit = strings.TrimSpace(sinceCommit)

	if !g.isCloned() {
		log.Info("cloning repository (shallow)")
		if err := g.clone(ctx); err != nil {
			return "", nil, fmt.Errorf("git clone: %w", err)
		}
		hash, err := g.headHash(ctx)
		if err != nil {
			return "", nil, fmt.Errorf("git rev-parse HEAD: %w", err)
		}
		if sinceCommit != "" && sinceCommit == hash {
			// Everything up to the cloned commit is already imported.
			return hash, []string{}, nil
		}
		// Fresh clone without a matching baseline: no delta available.
		return hash, nil, nil
	}

	log.Debug("repository already cloned, fetching updates")

	releaseSyncLock, err := g.acquireSyncLock(ctx)
	if err != nil {
		return "", nil, fmt.Errorf("acquire git sync lock: %w", err)
	}
	defer releaseSyncLock()

	// Step 1: fetch latest from origin.
	if err := g.run(ctx, g.Dir, "fetch", "--depth=1", "--no-progress", "origin"); err != nil {
		return "", nil, fmt.Errorf("git fetch: %w", err)
	}

	// Step 2: compute diff between the import baseline and fetched
	// origin/HEAD while both may still be reachable (before reset).
	var diffFiles []string
	haveDelta := false
	if sinceCommit == "" {
		log.Info("no import baseline commit recorded, full sync required")
	} else {
		var stdout bytes.Buffer
		cmdCtx, cancel := g.commandContext(ctx)
		defer cancel()
		// #nosec G204 -- command is fixed to git; sinceCommit is a stored commit hash and origin/HEAD is fixed.
		cmd := gitCommand(cmdCtx, "diff", "--name-only", sinceCommit, "origin/HEAD")
		cmd.Dir = g.Dir
		cmd.Stdout = &stdout
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		cmd.WaitDelay = 2 * time.Second

		if diffErr := cmd.Run(); diffErr != nil {
			if cmdCtx.Err() != nil {
				diffErr = cmdCtx.Err()
			}
			diffErr = gitCommandError([]string{"diff", "--name-only", sinceCommit, "origin/HEAD"}, diffErr, stdout.String(), stderr.String())
			log.Warn("git diff against import baseline failed, delta sync not available",
				slog.String("error", SafeDiagnosticError(diffErr)),
			)
			// diffFiles stays nil -> caller does full walk.
		} else {
			haveDelta = true
			lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line != "" {
					diffFiles = append(diffFiles, line)
				}
			}
		}
	}

	// Step 3: remove stale index.lock if a previous git process crashed.
	lockFile := filepath.Join(g.Dir, ".git", "index.lock")
	if _, statErr := os.Stat(lockFile); statErr == nil {
		log.Warn("removing stale git index.lock", slog.String("file", filepath.Base(lockFile)))
		_ = os.Remove(lockFile)
	}

	// Step 4: reset to origin/HEAD.
	if err := g.run(ctx, g.Dir, "reset", "--hard", "origin/HEAD"); err != nil {
		return "", nil, fmt.Errorf("git reset: %w", err)
	}

	hash, err := g.headHash(ctx)
	if err != nil {
		return "", nil, fmt.Errorf("git rev-parse HEAD (post-reset): %w", err)
	}

	if sinceCommit == hash {
		// Baseline already matches origin/HEAD -- nothing new to import.
		return hash, []string{}, nil
	}
	if !haveDelta {
		return hash, nil, nil
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

		//nolint:gosec // G304: lockFile is the operator-configured feed directory
		// joined with a constant file name; no request data reaches this path.
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
	return g.runWithTimeout(ctx, g.effectiveCommandTimeout(), dir, args...)
}

// runWithTimeout is run with an explicit per-command budget.
func (g *GitRepo) runWithTimeout(ctx context.Context, timeout time.Duration, dir string, args ...string) error {
	cmdCtx, cancel := withTimeout(ctx, timeout)
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
	return withTimeout(ctx, g.effectiveCommandTimeout())
}

func (g *GitRepo) effectiveCommandTimeout() time.Duration {
	if g.CommandTimeout > 0 {
		return g.CommandTimeout
	}
	return defaultGitCommandTimeout
}

// cloneTimeout never falls back to the per-command timeout: an explicit
// CommandTimeout is tuned for incremental work and would strand the clone.
func (g *GitRepo) cloneTimeout() time.Duration {
	if g.CloneTimeout > 0 {
		return g.CloneTimeout
	}
	return defaultGitCloneTimeout
}

func withTimeout(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
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
