//go:build aix || android || darwin || dragonfly || freebsd || illumos || ios || linux || netbsd || openbsd || solaris

package main

import (
	"context"
	"errors"
	"os"
	"reflect"
	"testing"
)

func TestScanRepoMetadataRetainsRelativePathWhenAbsFails(t *testing.T) {
	originalWorkingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatalf("get original working directory: %v", err)
	}
	restored := false
	t.Cleanup(func() {
		if !restored {
			_ = os.Chdir(originalWorkingDirectory)
		}
	})

	deletedWorkingDirectory := t.TempDir()
	if err := os.Chdir(deletedWorkingDirectory); err != nil {
		t.Fatalf("change to temporary working directory: %v", err)
	}
	if err := os.Remove(deletedWorkingDirectory); err != nil {
		_ = os.Chdir(originalWorkingDirectory)
		restored = true
		t.Fatalf("remove active working directory: %v", err)
	}

	originalOutput := gitCommandOutput
	t.Cleanup(func() { gitCommandOutput = originalOutput })
	var calls [][]string
	gitCommandOutput = func(_ context.Context, args ...string) ([]byte, error) {
		calls = append(calls, append([]string(nil), args...))
		return nil, errors.New("not a git repository")
	}

	repoName, branch, commit := scanRepoMetadata("relative-repo")
	restoreErr := os.Chdir(originalWorkingDirectory)
	restored = restoreErr == nil
	if restoreErr != nil {
		t.Fatalf("restore original working directory: %v", restoreErr)
	}

	if repoName != "relative-repo" || branch != "" || commit != "" {
		t.Fatalf("scanRepoMetadata(relative path) = %q, %q, %q; want relative-repo with no branch or commit", repoName, branch, commit)
	}
	wantCalls := [][]string{{"-C", "relative-repo", "rev-parse", "--show-toplevel"}}
	if !reflect.DeepEqual(calls, wantCalls) {
		t.Fatalf("git calls = %#v, want %#v", calls, wantCalls)
	}
}
