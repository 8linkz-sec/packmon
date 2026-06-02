package feed

import (
	"context"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
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
	repo := &GitRepo{
		URL:    remote,
		Dir:    cloneDir,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
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
	if got, err := repo.HeadHash(ctx); err != nil || got != firstHash {
		t.Fatalf("HeadHash() = %q, %v; want %q", got, err, firstHash)
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

	newHash, changed, err := repo.PullWithChangedFiles(ctx)
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
	sameHash, noChanges, err := repo.PullWithChangedFiles(ctx)
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
	hash, changed, err := repo.PullWithChangedFiles(ctx)
	if err != nil {
		t.Fatalf("PullWithChangedFiles(fresh clone) error = %v", err)
	}
	if hash == "" || changed != nil {
		t.Fatalf("PullWithChangedFiles(fresh clone) = %q, %#v; want hash and nil changed files", hash, changed)
	}
}

func TestGitRepoHeadHashFailsOutsideRepo(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	repo := &GitRepo{Dir: t.TempDir(), Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if _, err := repo.HeadHash(context.Background()); err == nil {
		t.Fatal("HeadHash outside repo error = nil")
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
	}
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
