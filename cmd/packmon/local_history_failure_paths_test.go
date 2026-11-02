package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

const f036DeadlineFakeGitMode = "f036-deadline"

func init() {
	if os.Getenv(fakeGitModeEnv) != f036DeadlineFakeGitMode {
		return
	}
	ready := os.Getenv("PACKMON_F027_FAKE_GIT_READY")
	if ready == "" || os.WriteFile(ready, []byte("ready"), 0o600) != nil { //nolint:gosec // The parent test owns the temporary marker path.
		os.Exit(99)
	}
	for {
		time.Sleep(time.Hour)
	}
}

func TestHistoryEnabledAcceptsEveryDocumentedAlias(t *testing.T) {
	tests := []struct {
		value string
		want  bool
	}{
		{value: "1", want: true},
		{value: " true ", want: true},
		{value: "\tYeS\n", want: true},
		{value: " ON ", want: true},
		{value: " 1\t", want: true},
		{value: "TRUE", want: true},
		{value: " yes ", want: true},
		{value: "oN", want: true},
		{value: "0", want: false},
		{value: " false ", want: false},
		{value: "\tNo\n", want: false},
		{value: " OFF ", want: false},
		{value: " 0\t", want: false},
		{value: "FALSE", want: false},
		{value: " no ", want: false},
		{value: "oFf", want: false},
	}

	for index, test := range tests {
		t.Run(fmt.Sprintf("case_%02d", index), func(t *testing.T) {
			t.Setenv("PACKMON_HISTORY_ENABLED", test.value)

			got, err := historyEnabled()
			if err != nil {
				t.Fatalf("historyEnabled(%q) error = %v", test.value, err)
			}
			if got != test.want {
				t.Fatalf("historyEnabled(%q) = %t, want %t", test.value, got, test.want)
			}
		})
	}
}

func TestScanRepoMetadataFallsBackToLocalAtFilesystemRoot(t *testing.T) {
	root := filepath.VolumeName(t.TempDir()) + string(filepath.Separator)
	original := gitCommandOutput
	t.Cleanup(func() { gitCommandOutput = original })

	var calls [][]string
	gitCommandOutput = func(_ context.Context, args ...string) ([]byte, error) {
		calls = append(calls, append([]string(nil), args...))
		return nil, errors.New("not a git repository")
	}

	repoName, branch, commit := scanRepoMetadata(root)
	if repoName != "local" || branch != "" || commit != "" {
		t.Fatalf("scanRepoMetadata(root) = %q, %q, %q; want local with no branch or commit", repoName, branch, commit)
	}
	wantCalls := [][]string{{"-C", root, "rev-parse", "--show-toplevel"}}
	if !reflect.DeepEqual(calls, wantCalls) {
		t.Fatalf("git calls = %#v, want %#v", calls, wantCalls)
	}
}

func TestScanRepoMetadataPreservesAvailablePartialGitMetadata(t *testing.T) {
	t.Run("detached HEAD preserves exact commit", func(t *testing.T) {
		if _, err := exec.LookPath("git"); err != nil {
			t.Skip("git not available")
		}

		repoDir := filepath.Join(t.TempDir(), "detached-repo")
		if err := os.MkdirAll(repoDir, 0o750); err != nil {
			t.Fatalf("create repository: %v", err)
		}
		runLocalHistoryGit(t, repoDir, "init")
		runLocalHistoryGit(t, repoDir, "commit", "--allow-empty", "-m", "initial")
		wantCommit := localHistoryGitOutput(t, repoDir, "rev-parse", "HEAD")
		runLocalHistoryGit(t, repoDir, "checkout", "--detach", "HEAD")

		repoName, branch, commit := scanRepoMetadata(repoDir)
		if repoName != "detached-repo" || branch != "" || commit != wantCommit {
			t.Fatalf("scanRepoMetadata(detached) = %q, %q, %q; want detached-repo, empty branch, %q", repoName, branch, commit, wantCommit)
		}
	})

	for _, test := range []struct {
		name       string
		failProbe  string
		wantBranch string
		wantCommit string
	}{
		{name: "branch failure preserves commit", failProbe: "branch", wantCommit: "0123456789abcdef0123456789abcdef01234567"},
		{name: "commit failure preserves branch", failProbe: "commit", wantBranch: "main"},
	} {
		t.Run(test.name, func(t *testing.T) {
			scanDir := filepath.Join(t.TempDir(), "scan")
			gitRoot := filepath.Join(t.TempDir(), "repository")
			if err := os.MkdirAll(scanDir, 0o750); err != nil {
				t.Fatalf("create scan directory: %v", err)
			}

			original := gitCommandOutput
			t.Cleanup(func() { gitCommandOutput = original })
			probeErr := errors.New("probe failed")
			var calls [][]string
			gitCommandOutput = func(_ context.Context, args ...string) ([]byte, error) {
				calls = append(calls, append([]string(nil), args...))
				switch len(calls) {
				case 1:
					return []byte(gitRoot + "\n"), nil
				case 2:
					if test.failProbe == "branch" {
						return nil, probeErr
					}
					return []byte("main\n"), nil
				case 3:
					if test.failProbe == "commit" {
						return nil, probeErr
					}
					return []byte(test.wantCommit + "\n"), nil
				default:
					t.Fatalf("unexpected git call %d: %v", len(calls), args)
					return nil, nil
				}
			}

			repoName, branch, commit := scanRepoMetadata(scanDir)
			if repoName != "repository" || branch != test.wantBranch || commit != test.wantCommit {
				t.Fatalf("scanRepoMetadata(partial) = %q, %q, %q; want repository, %q, %q", repoName, branch, commit, test.wantBranch, test.wantCommit)
			}
			wantCalls := [][]string{
				{"-C", scanDir, "rev-parse", "--show-toplevel"},
				{"-C", gitRoot, "branch", "--show-current"},
				{"-C", gitRoot, "rev-parse", "HEAD"},
			}
			if !reflect.DeepEqual(calls, wantCalls) {
				t.Fatalf("git calls = %#v, want %#v", calls, wantCalls)
			}
		})
	}
}

func TestScanRepoMetadataCancelsStartedGitProbeAtDeadline(t *testing.T) {
	helperArgs := installFakeGit(t)
	ready := filepath.Join(t.TempDir(), "started")
	t.Setenv(fakeGitModeEnv, f036DeadlineFakeGitMode)
	t.Setenv("PACKMON_F027_FAKE_GIT_READY", ready)

	repoDir := filepath.Join(t.TempDir(), "repo")
	if err := os.MkdirAll(repoDir, 0o750); err != nil {
		t.Fatalf("create repository directory: %v", err)
	}
	originalOutput := gitCommandOutput
	originalTimeout := gitMetadataTimeout
	t.Cleanup(func() {
		gitCommandOutput = originalOutput
		gitMetadataTimeout = originalTimeout
	})

	gitMetadataTimeout = 5 * time.Second
	var calls [][]string
	var commandErr error
	var commandContextErr error
	gitCommandOutput = func(ctx context.Context, args ...string) ([]byte, error) {
		calls = append(calls, append([]string(nil), args...))
		combinedArgs := append(append([]string(nil), helperArgs...), args...)
		output, err := defaultGitCommandOutput(ctx, combinedArgs...)
		commandErr = err
		commandContextErr = ctx.Err()
		return output, err
	}

	started := time.Now()
	repoName, branch, commit := scanRepoMetadata(repoDir)
	elapsed := time.Since(started)
	readyContents, readyErr := os.ReadFile(ready) //nolint:gosec // The parent test owns the temporary marker path.

	if repoName != "repo" || branch != "" || commit != "" {
		t.Fatalf("scanRepoMetadata(deadline) = %q, %q, %q; want repo with no branch or commit", repoName, branch, commit)
	}
	if readyErr != nil || string(readyContents) != "ready" {
		t.Fatalf("fake git start marker = %q, %v; want a started child", readyContents, readyErr)
	}
	if commandErr == nil {
		t.Fatal("git command error = nil after deadline")
	}
	if !errors.Is(commandContextErr, context.DeadlineExceeded) {
		t.Fatalf("git command context error = %v, want %v", commandContextErr, context.DeadlineExceeded)
	}
	wantCalls := [][]string{{"-C", repoDir, "rev-parse", "--show-toplevel"}}
	if !reflect.DeepEqual(calls, wantCalls) {
		t.Fatalf("git calls = %#v, want %#v", calls, wantCalls)
	}
	if elapsed >= 10*time.Second {
		t.Fatalf("deadline-bound git probe took %s, want less than 10s", elapsed)
	}
}

func localHistoryGitOutput(t *testing.T, dir string, args ...string) string {
	t.Helper()

	cmd := exec.Command("git", args...) // #nosec G204 -- test helper invokes fixed git binary with test-controlled arguments.
	cmd.Dir = dir
	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("git %v failed: %v", args, err)
	}
	return strings.TrimSpace(string(output))
}
