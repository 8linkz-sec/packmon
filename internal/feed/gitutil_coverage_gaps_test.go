package feed

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGitRepoCommandFailureBranches(t *testing.T) {
	oldExecutable := gitExecutable
	oldArgs := gitExecutableArgs
	gitExecutable = os.Args[0]
	gitExecutableArgs = []string{"-test.run=^TestGitRepoSelectiveFailureHelper$", "--"}
	t.Cleanup(func() {
		gitExecutable = oldExecutable
		gitExecutableArgs = oldArgs
	})

	newRepo := func(t *testing.T) *GitRepo {
		t.Helper()
		dir := t.TempDir()
		if err := os.Mkdir(filepath.Join(dir, ".git"), 0o750); err != nil {
			t.Fatal(err)
		}
		return &GitRepo{URL: "https://example.test/repo.git", Dir: dir, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), CommandTimeout: 10 * time.Second}
	}

	for _, tc := range []struct {
		name, fail, want string
		call             func(*GitRepo) error
	}{
		{name: "ensure fetch", fail: "fetch", want: "git pull", call: func(repo *GitRepo) error { _, err := repo.EnsureCloned(context.Background()); return err }},
		{name: "ensure reset", fail: "reset", want: "git pull", call: func(repo *GitRepo) error { _, err := repo.EnsureCloned(context.Background()); return err }},
		{name: "ensure head", fail: "rev-parse", want: "rev-parse HEAD", call: func(repo *GitRepo) error { _, err := repo.EnsureCloned(context.Background()); return err }},
		{name: "delta fetch", fail: "fetch", want: "git fetch", call: func(repo *GitRepo) error {
			_, _, err := repo.PullWithChangedFiles(context.Background(), "baseline")
			return err
		}},
		{name: "delta reset", fail: "reset", want: "git reset", call: func(repo *GitRepo) error {
			_, _, err := repo.PullWithChangedFiles(context.Background(), "baseline")
			return err
		}},
		{name: "delta head", fail: "rev-parse", want: "post-reset", call: func(repo *GitRepo) error {
			_, _, err := repo.PullWithChangedFiles(context.Background(), "baseline")
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("PACKMON_FAKE_GIT_FAIL_COMMAND", tc.fail)
			err := tc.call(newRepo(t))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}

	t.Setenv("PACKMON_FAKE_GIT_FAIL_COMMAND", "never")
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := newRepo(t).headHash(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("headHash(cancelled) error = %v", err)
	}
}

func TestGitRepoSelectiveFailureHelper(t *testing.T) {
	fail := os.Getenv("PACKMON_FAKE_GIT_FAIL_COMMAND")
	if fail == "" {
		t.Skip("helper process only")
	}
	var args []string
	for i, arg := range os.Args {
		if arg == "--" {
			args = os.Args[i+1:]
			break
		}
	}
	if len(args) == 0 {
		os.Exit(2)
	}
	if args[0] == fail {
		_, _ = os.Stderr.WriteString("forced failure\n")
		os.Exit(1)
	}
	if args[0] == "rev-parse" {
		_, _ = os.Stdout.WriteString("2222222222222222222222222222222222222222\n")
	}
}

func TestGitRepoLockTimeoutAndErrorHelpers(t *testing.T) {
	t.Parallel()

	repo := &GitRepo{Dir: filepath.Join(t.TempDir(), "missing"), Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	cancelled, cancelCancelled := context.WithCancel(context.Background())
	cancelCancelled()
	if _, err := repo.acquireSyncLock(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("acquireSyncLock(cancelled) error = %v", err)
	}
	if _, err := repo.acquireSyncLock(context.Background()); err == nil || !strings.Contains(err.Error(), "creating sync lock") {
		t.Fatalf("acquireSyncLock(missing dir) error = %v", err)
	}

	dir := t.TempDir()
	repo.Dir = dir
	release, err := repo.acquireSyncLock(nil) //nolint:staticcheck // SA1012: the nil-context fallback is under test.
	if err != nil {
		t.Fatalf("acquireSyncLock(nil context) error = %v", err)
	}
	release()
	if _, err := os.Stat(filepath.Join(dir, gitSyncLockFileName)); !os.IsNotExist(err) {
		t.Fatalf("lock survived release: %v", err)
	}

	ctx, cancel := withTimeout(nil, time.Second) //nolint:staticcheck // SA1012: the nil-context fallback is under test.
	if ctx == nil {
		t.Fatal("withTimeout(nil) returned nil context")
	}
	cancel()

	plain := errors.New("plain failure")
	if got := pathOperationError("testing", filepath.Join(dir, "file"), plain); got == nil || !strings.Contains(got.Error(), "plain failure") {
		t.Fatalf("pathOperationError(plain) = %v", got)
	}

	waitDir := t.TempDir()
	waitRepo := &GitRepo{Dir: waitDir, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	lockPath := filepath.Join(waitDir, gitSyncLockFileName)
	if err := os.WriteFile(lockPath, []byte("held"), 0o600); err != nil {
		t.Fatal(err)
	}
	removed := make(chan error, 1)
	go func() {
		time.Sleep(2 * gitSyncLockPollInterval)
		removed <- os.Remove(lockPath)
	}()
	waitCtx, waitCancel := context.WithTimeout(context.Background(), time.Second)
	defer waitCancel()
	waitRelease, err := waitRepo.acquireSyncLock(waitCtx)
	if err != nil {
		t.Fatalf("acquireSyncLock(after wait) error = %v", err)
	}
	if err := <-removed; err != nil {
		t.Fatalf("remove held lock: %v", err)
	}
	waitRelease()
}

func TestPullWithChangedFilesFreshCloneWrapperBranches(t *testing.T) {
	oldExecutable := gitExecutable
	oldArgs := gitExecutableArgs
	gitExecutable = os.Args[0]
	gitExecutableArgs = []string{"-test.run=^TestGitRepoFreshCloneHelper$", "--"}
	t.Cleanup(func() {
		gitExecutable = oldExecutable
		gitExecutableArgs = oldArgs
	})
	const hash = "3333333333333333333333333333333333333333"

	t.Run("matching baseline", func(t *testing.T) {
		t.Setenv("PACKMON_FAKE_GIT_FRESH_CLONE", "success")
		repo := &GitRepo{URL: "https://example.test/repo.git", Dir: filepath.Join(t.TempDir(), "clone"), Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
		gotHash, changed, err := repo.PullWithChangedFiles(context.Background(), hash)
		if err != nil || gotHash != hash || changed == nil || len(changed) != 0 {
			t.Fatalf("PullWithChangedFiles(match) = %q, %+v, %v", gotHash, changed, err)
		}
	})

	t.Run("head failure", func(t *testing.T) {
		t.Setenv("PACKMON_FAKE_GIT_FRESH_CLONE", "fail-head")
		repo := &GitRepo{URL: "https://example.test/repo.git", Dir: filepath.Join(t.TempDir(), "clone"), Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
		if _, _, err := repo.PullWithChangedFiles(context.Background(), ""); err == nil || !strings.Contains(err.Error(), "rev-parse HEAD") {
			t.Fatalf("PullWithChangedFiles(head failure) error = %v", err)
		}
	})

	t.Run("clone failure", func(t *testing.T) {
		t.Setenv("PACKMON_FAKE_GIT_FRESH_CLONE", "fail-clone")
		repo := &GitRepo{URL: "https://example.test/repo.git", Dir: filepath.Join(t.TempDir(), "clone"), Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
		if _, _, err := repo.PullWithChangedFiles(context.Background(), ""); err == nil || !strings.Contains(err.Error(), "git clone") {
			t.Fatalf("PullWithChangedFiles(clone failure) error = %v", err)
		}
	})

	t.Run("ensure clone failure", func(t *testing.T) {
		t.Setenv("PACKMON_FAKE_GIT_FRESH_CLONE", "fail-clone")
		repo := &GitRepo{URL: "https://example.test/repo.git", Dir: filepath.Join(t.TempDir(), "clone"), Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
		if _, err := repo.EnsureCloned(context.Background()); err == nil || !strings.Contains(err.Error(), "git clone") {
			t.Fatalf("EnsureCloned(clone failure) error = %v", err)
		}
	})
}

func TestGitRepoFreshCloneHelper(t *testing.T) {
	mode := os.Getenv("PACKMON_FAKE_GIT_FRESH_CLONE")
	if mode == "" {
		t.Skip("helper process only")
	}
	var args []string
	for i, arg := range os.Args {
		if arg == "--" {
			args = os.Args[i+1:]
			break
		}
	}
	if len(args) == 0 {
		os.Exit(2)
	}
	switch args[0] {
	case "clone":
		if mode == "fail-clone" {
			os.Exit(1)
		}
		target := args[len(args)-1]
		_ = os.MkdirAll(filepath.Join(target, ".git"), 0o750) // #nosec G703 -- fake git helper writes below the test's clone target.
		os.Exit(0)
	case "rev-parse":
		if mode == "fail-head" {
			os.Exit(1)
		}
		_, _ = os.Stdout.WriteString("3333333333333333333333333333333333333333\n")
		os.Exit(0)
	default:
		os.Exit(2)
	}
}
