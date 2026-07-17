package feed

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGitRepoClonePullHeadHashAndChangedFiles(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	ctx := context.Background()
	remote := filepath.Join(t.TempDir(), "remote")
	runGit(t, "", "init", remote)
	runGit(t, remote, "config", "user.email", "packmon@example.test")
	runGit(t, remote, "config", "user.name", "Packmon Test")
	if err := os.WriteFile(filepath.Join(remote, "advisory.txt"), []byte("one"), 0o600); err != nil {
		t.Fatalf("write advisory: %v", err)
	}
	runGit(t, remote, "add", ".")
	runGit(t, remote, "commit", "-m", "initial")

	cloneDir := filepath.Join(t.TempDir(), "clone")
	var logs bytes.Buffer
	repo := &GitRepo{
		URL:    remote,
		Dir:    cloneDir,
		Logger: slog.New(slog.NewTextHandler(&logs, nil)),
	}

	firstHash, err := repo.EnsureCloned(ctx)
	if err != nil {
		t.Fatalf("EnsureCloned() error = %v", err)
	}
	if firstHash == "" {
		t.Fatal("EnsureCloned() returned empty hash")
	}
	if !repo.isCloned() {
		t.Fatal("repo should be cloned")
	}
	if got, err := repo.headHash(ctx); err != nil || got != firstHash {
		t.Fatalf("headHash() = %q, %v; want %q", got, err, firstHash)
	}
	if got, err := repo.EnsureCloned(ctx); err != nil || got != firstHash {
		t.Fatalf("EnsureCloned(existing) = %q, %v; want %q", got, err, firstHash)
	}

	if err := os.WriteFile(filepath.Join(remote, "advisory.txt"), []byte("two"), 0o600); err != nil {
		t.Fatalf("update advisory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(remote, "new.txt"), []byte("new"), 0o600); err != nil {
		t.Fatalf("write new file: %v", err)
	}
	runGit(t, remote, "add", ".")
	runGit(t, remote, "commit", "-m", "update")

	newHash, changed, err := repo.PullWithChangedFiles(ctx, firstHash)
	if err != nil {
		t.Fatalf("PullWithChangedFiles() error = %v", err)
	}
	if newHash == "" || newHash == firstHash {
		t.Fatalf("new hash = %q, first = %q; want changed hash", newHash, firstHash)
	}
	if len(changed) != 2 {
		t.Fatalf("changed files = %#v, want two changed files", changed)
	}
	seen := map[string]bool{}
	for _, file := range changed {
		seen[file] = true
	}
	if !seen["advisory.txt"] || !seen["new.txt"] {
		t.Fatalf("changed files = %#v, want advisory.txt and new.txt", changed)
	}

	lockFile := filepath.Join(cloneDir, ".git", "index.lock")
	if err := os.WriteFile(lockFile, []byte("stale"), 0o600); err != nil {
		t.Fatalf("write stale index lock: %v", err)
	}
	sameHash, noChanges, err := repo.PullWithChangedFiles(ctx, newHash)
	if err != nil {
		t.Fatalf("PullWithChangedFiles(no changes) error = %v", err)
	}
	if sameHash != newHash {
		t.Fatalf("same hash = %q, want %q", sameHash, newHash)
	}
	if noChanges == nil || len(noChanges) != 0 {
		t.Fatalf("noChanges = %#v, want empty non-nil slice", noChanges)
	}
	if _, err := os.Stat(lockFile); !os.IsNotExist(err) {
		t.Fatalf("stale index lock stat = %v, want removed", err)
	}
	logText := logs.String()
	if strings.Contains(logText, cloneDir) || strings.Contains(logText, lockFile) {
		t.Fatalf("git logs contain local paths: %q", logText)
	}
	if !strings.Contains(logText, `file=index.lock`) {
		t.Fatalf("git logs missing sanitized stale-lock filename: %q", logText)
	}
}

func TestGitRepoPullWithChangedFilesFreshClone(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	ctx := context.Background()
	remote := filepath.Join(t.TempDir(), "remote")
	runGit(t, "", "init", remote)
	runGit(t, remote, "config", "user.email", "packmon@example.test")
	runGit(t, remote, "config", "user.name", "Packmon Test")
	if err := os.WriteFile(filepath.Join(remote, "advisory.txt"), []byte("one"), 0o600); err != nil {
		t.Fatalf("write advisory: %v", err)
	}
	runGit(t, remote, "add", ".")
	runGit(t, remote, "commit", "-m", "initial")

	repo := &GitRepo{
		URL:    remote,
		Dir:    filepath.Join(t.TempDir(), "clone"),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	hash, changed, err := repo.PullWithChangedFiles(ctx, "")
	if err != nil {
		t.Fatalf("PullWithChangedFiles(fresh clone) error = %v", err)
	}
	if hash == "" || changed != nil {
		t.Fatalf("PullWithChangedFiles(fresh clone) = %q, %#v; want hash and nil changed files", hash, changed)
	}
}

func TestGitRepoPullWithChangedFilesUsesImportBaselineNotCheckoutHead(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	ctx := context.Background()
	remote := filepath.Join(t.TempDir(), "remote")
	runGit(t, "", "init", remote)
	runGit(t, remote, "config", "user.email", "packmon@example.test")
	runGit(t, remote, "config", "user.name", "Packmon Test")
	if err := os.WriteFile(filepath.Join(remote, "one.txt"), []byte("one"), 0o600); err != nil {
		t.Fatalf("write one.txt: %v", err)
	}
	runGit(t, remote, "add", ".")
	runGit(t, remote, "commit", "-m", "baseline")

	repo := &GitRepo{
		URL:    remote,
		Dir:    filepath.Join(t.TempDir(), "clone"),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	baseline, err := repo.EnsureCloned(ctx)
	if err != nil {
		t.Fatalf("EnsureCloned() error = %v", err)
	}

	if err := os.WriteFile(filepath.Join(remote, "two.txt"), []byte("two"), 0o600); err != nil {
		t.Fatalf("write two.txt: %v", err)
	}
	runGit(t, remote, "add", ".")
	runGit(t, remote, "commit", "-m", "missed change")

	// Simulate an interrupted sync attempt that advanced the checkout to the
	// newest commit without importing anything.
	if _, err := repo.EnsureCloned(ctx); err != nil {
		t.Fatalf("EnsureCloned(advance checkout) error = %v", err)
	}

	// The retry must not treat "checkout already at origin/HEAD" as "no
	// changes": the import baseline is older than the checkout.
	hash, changed, err := repo.PullWithChangedFiles(ctx, baseline)
	if err != nil {
		t.Fatalf("PullWithChangedFiles(stale baseline) error = %v", err)
	}
	if hash == baseline {
		t.Fatalf("hash = %q, want new commit past baseline", hash)
	}
	if changed != nil && len(changed) == 0 {
		t.Fatalf("changed = empty non-nil slice; stale baseline must yield the real delta or nil (full walk)")
	}
	if changed != nil {
		seen := map[string]bool{}
		for _, file := range changed {
			seen[file] = true
		}
		if !seen["two.txt"] {
			t.Fatalf("changed = %#v, want two.txt from baseline delta", changed)
		}
	}

	// An empty baseline on an existing checkout must request a full walk.
	hash, changed, err = repo.PullWithChangedFiles(ctx, "")
	if err != nil {
		t.Fatalf("PullWithChangedFiles(no baseline) error = %v", err)
	}
	if hash == "" || changed != nil {
		t.Fatalf("PullWithChangedFiles(no baseline) = %q, %#v; want hash and nil changed files", hash, changed)
	}
}

func TestGitRepoPullWithChangedFilesWaitsForPackmonSyncLockBeforeRemovingIndexLock(t *testing.T) {
	oldGitExecutable := gitExecutable
	oldGitExecutableArgs := gitExecutableArgs
	gitExecutable = os.Args[0]
	gitExecutableArgs = []string{"-test.run=^TestGitRepoFakeGitSuccessfulPull$", "--"}
	t.Cleanup(func() {
		gitExecutable = oldGitExecutable
		gitExecutableArgs = oldGitExecutableArgs
	})
	t.Setenv("PACKMON_FAKE_GIT_SUCCESSFUL_PULL", "1")

	repoDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(repoDir, ".git"), 0o750); err != nil {
		t.Fatalf("mkdir .git: %v", err)
	}
	indexLock := filepath.Join(repoDir, ".git", "index.lock")
	if err := os.WriteFile(indexLock, []byte("active git process"), 0o600); err != nil {
		t.Fatalf("write active index lock: %v", err)
	}
	packmonLock := filepath.Join(repoDir, ".packmon-sync.lock")
	if err := os.WriteFile(packmonLock, []byte("held by another process"), 0o600); err != nil {
		t.Fatalf("write packmon lock: %v", err)
	}

	repo := &GitRepo{
		URL:            "https://example.invalid/repo.git",
		Dir:            repoDir,
		Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		CommandTimeout: time.Second,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()

	_, _, err := repo.PullWithChangedFiles(ctx, "")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("PullWithChangedFiles() error = %v, want context deadline exceeded", err)
	}
	if _, err := os.Stat(indexLock); err != nil {
		t.Fatalf("index.lock was touched while packmon lock was held: %v", err)
	}
}

func TestGitRepoHeadHashFailsOutsideRepo(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	repo := &GitRepo{Dir: t.TempDir(), Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if _, err := repo.headHash(context.Background()); err == nil {
		t.Fatal("headHash outside repo error = nil")
	}
}

func TestGitRepoRunAndCloneErrorBranches(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	repo := &GitRepo{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if err := repo.run(context.Background(), t.TempDir(), "definitely-not-a-git-subcommand"); err == nil {
		t.Fatal("run(invalid subcommand) error = nil")
	}

	parentFile := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(parentFile, []byte("x"), 0o600); err != nil {
		t.Fatalf("write parent file: %v", err)
	}
	repo = &GitRepo{
		URL:    "https://example.invalid/repo.git",
		Dir:    filepath.Join(parentFile, "clone"),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	if err := repo.clone(context.Background()); err == nil {
		t.Fatal("clone(parent file) error = nil")
	} else if strings.Contains(err.Error(), parentFile) || strings.Contains(err.Error(), filepath.Dir(parentFile)) {
		t.Fatalf("clone(parent file) error leaked full path: %v", err)
	}
}

func TestGitRepoRunSanitizesGitOutputAndKeepsProcessStderrQuiet(t *testing.T) {
	oldGitExecutable := gitExecutable
	oldGitExecutableArgs := gitExecutableArgs
	gitExecutable = os.Args[0]
	gitExecutableArgs = []string{"-test.run=^TestGitRepoFakeGitOutput$", "--"}
	t.Cleanup(func() {
		gitExecutable = oldGitExecutable
		gitExecutableArgs = oldGitExecutableArgs
	})
	t.Setenv("PACKMON_FAKE_GIT_OUTPUT", "1")

	var processStderr bytes.Buffer
	err := withCapturedStderr(&processStderr, func() error {
		repo := &GitRepo{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
		return repo.run(context.Background(), t.TempDir(), "status")
	})
	if err == nil {
		t.Fatal("run(fake git output) error = nil")
	}

	for _, leaked := range []string{
		`C:\Users\Admin\feed-data\repo`,
		"/var/lib/packmon/feed-data/repo",
		"secret-token",
		"token=super-secret",
	} {
		if strings.Contains(err.Error(), leaked) {
			t.Fatalf("sanitized git error leaked %q: %v", leaked, err)
		}
		if strings.Contains(processStderr.String(), leaked) {
			t.Fatalf("process stderr leaked %q: %s", leaked, processStderr.String())
		}
	}
	if processStderr.Len() != 0 {
		t.Fatalf("git helper wrote to process stderr: %s", processStderr.String())
	}
	if !strings.Contains(err.Error(), "(redacted-path)") || !strings.Contains(err.Error(), "token=[redacted]") {
		t.Fatalf("git error missing redacted diagnostics: %v", err)
	}
}

func TestGitRepoHeadHashSanitizesSubprocessStderr(t *testing.T) {
	oldGitExecutable := gitExecutable
	oldGitExecutableArgs := gitExecutableArgs
	gitExecutable = os.Args[0]
	gitExecutableArgs = []string{"-test.run=^TestGitRepoFakeGitOutput$", "--"}
	t.Cleanup(func() {
		gitExecutable = oldGitExecutable
		gitExecutableArgs = oldGitExecutableArgs
	})
	t.Setenv("PACKMON_FAKE_GIT_OUTPUT", "1")

	repoDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(repoDir, ".git"), 0o750); err != nil {
		t.Fatalf("mkdir .git: %v", err)
	}
	repo := &GitRepo{Dir: repoDir, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}

	var processStderr bytes.Buffer
	err := withCapturedStderr(&processStderr, func() error {
		_, err := repo.headHash(context.Background())
		return err
	})
	if err == nil {
		t.Fatal("headHash(fake git output) error = nil")
	}
	for _, leaked := range []string{`C:\Users\Admin\feed-data\repo`, "/var/lib/packmon/feed-data/repo", "secret-token"} {
		if strings.Contains(err.Error(), leaked) {
			t.Fatalf("headHash error leaked %q: %v", leaked, err)
		}
		if strings.Contains(processStderr.String(), leaked) {
			t.Fatalf("headHash process stderr leaked %q: %s", leaked, processStderr.String())
		}
	}
	if processStderr.Len() != 0 {
		t.Fatalf("headHash wrote to process stderr: %s", processStderr.String())
	}
}

func TestGitRepoRunUsesCommandTimeout(t *testing.T) {
	oldGitExecutable := gitExecutable
	oldGitExecutableArgs := gitExecutableArgs
	gitExecutable = os.Args[0]
	gitExecutableArgs = []string{"-test.run=^TestGitRepoFakeGitSleep$", "--"}
	t.Cleanup(func() {
		gitExecutable = oldGitExecutable
		gitExecutableArgs = oldGitExecutableArgs
	})
	t.Setenv("PACKMON_FAKE_GIT_SLEEP", "1")

	repo := &GitRepo{
		Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		CommandTimeout: 20 * time.Millisecond,
	}
	err := repo.run(context.Background(), t.TempDir(), "status")
	if err == nil {
		t.Fatal("run(fake slow git) error = nil, want deadline")
	}
	if !errors.Is(err, context.DeadlineExceeded) && !strings.Contains(err.Error(), "deadline") {
		t.Fatalf("run(fake slow git) error = %v, want deadline", err)
	}
}

func TestGitRepoFakeGitSleep(t *testing.T) {
	if os.Getenv("PACKMON_FAKE_GIT_SLEEP") != "1" {
		t.Skip("helper process only")
	}
	time.Sleep(2 * time.Second)
}

func TestGitRepoFakeGitOutput(t *testing.T) {
	if os.Getenv("PACKMON_FAKE_GIT_OUTPUT") != "1" {
		t.Skip("helper process only")
	}
	_, _ = os.Stdout.WriteString("stdout includes /var/lib/packmon/feed-data/repo and secret-token\n")
	_, _ = os.Stderr.WriteString(`fatal: cannot access C:\Users\Admin\feed-data\repo: token=super-secret` + "\n")
	os.Exit(2)
}

func TestGitRepoFakeGitSuccessfulPull(t *testing.T) {
	if os.Getenv("PACKMON_FAKE_GIT_SUCCESSFUL_PULL") != "1" {
		t.Skip("helper process only")
	}
	var gitArgs []string
	for i, arg := range os.Args {
		if arg == "--" {
			gitArgs = os.Args[i+1:]
			break
		}
	}
	if len(gitArgs) == 0 {
		_, _ = os.Stderr.WriteString("missing fake git args\n")
		os.Exit(2)
	}
	switch gitArgs[0] {
	case "rev-parse":
		_, _ = os.Stdout.WriteString("1111111111111111111111111111111111111111\n")
	case "fetch", "reset", "diff":
	default:
		_, _ = os.Stderr.WriteString("unexpected fake git arg: " + gitArgs[0] + "\n")
		os.Exit(2)
	}
}

func withCapturedStderr(dst *bytes.Buffer, fn func() error) error {
	readPipe, writePipe, err := os.Pipe()
	if err != nil {
		return err
	}
	oldStderr := os.Stderr
	os.Stderr = writePipe
	defer func() {
		os.Stderr = oldStderr
		_ = readPipe.Close()
	}()

	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(dst, readPipe)
		close(done)
	}()
	runErr := fn()
	_ = writePipe.Close()
	<-done
	return runErr
}

func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()

	// #nosec G204 -- test helper executes git with fixed test-provided args.
	cmd := exec.Command("git", args...)
	if dir != "" {
		cmd.Dir = dir
	}
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=Packmon Test",
		"GIT_AUTHOR_EMAIL=packmon@example.test",
		"GIT_COMMITTER_NAME=Packmon Test",
		"GIT_COMMITTER_EMAIL=packmon@example.test",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v failed: %v\n%s", args, err, out)
	}
}
