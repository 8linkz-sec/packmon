package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

const fakeGitModeEnv = "PACKMON_F027_FAKE_GIT_MODE"

func TestGitOutputBufferBoundaryAndCopy(t *testing.T) {
	var buffer gitOutputBuffer
	initial := bytes.Repeat([]byte{'a'}, maxGitCommandOutputBytes)
	if written, err := buffer.Write(initial); err != nil || written != len(initial) {
		t.Fatalf("Write(exact capacity) = (%d, %v), want (%d, nil)", written, err, len(initial))
	}

	copyOne, err := buffer.Bytes()
	if err != nil {
		t.Fatalf("Bytes() before overflow: %v", err)
	}
	copyOne[0] = 'x'
	copyTwo, err := buffer.Bytes()
	if err != nil {
		t.Fatalf("Bytes() after caller mutation: %v", err)
	}
	if copyTwo[0] != 'a' {
		t.Fatalf("Bytes() exposed internal buffer: first byte = %q, want %q", copyTwo[0], byte('a'))
	}

	if written, err := buffer.Write([]byte("overflow")); err != nil || written != len("overflow") {
		t.Fatalf("Write(overflow) = (%d, %v), want (%d, nil)", written, err, len("overflow"))
	}
	if written, err := buffer.Write(nil); err != nil || written != 0 {
		t.Fatalf("Write(empty) = (%d, %v), want (0, nil)", written, err)
	}

	got, err := buffer.Bytes()
	if !errors.Is(err, errGitCommandOutputTooLarge) {
		t.Fatalf("Bytes() error = %v, want %v", err, errGitCommandOutputTooLarge)
	}
	if len(got) != maxGitCommandOutputBytes || !bytes.Equal(got, initial) {
		t.Fatalf("Bytes() after overflow retained %d bytes equal=%t, want exact original cap", len(got), bytes.Equal(got, initial))
	}
}

func TestDefaultGitCommandOutputFailsWithoutGit(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	if runtime.GOOS == "windows" {
		t.Setenv("PATHEXT", ".COM;.EXE;.BAT;.CMD")
	}

	output, err := defaultGitCommandOutput(context.Background(), "status")
	if err == nil {
		t.Fatal("defaultGitCommandOutput() error = nil, want git lookup failure")
	}
	if output != nil {
		t.Fatalf("defaultGitCommandOutput() output = %q, want nil", output)
	}
}

func TestDefaultGitCommandOutputStreamSizePrecedence(t *testing.T) {
	helperArgs := installFakeGit(t)
	cases := []struct {
		name string
		mode string
	}{
		{name: "failing oversized stderr", mode: "oversized-stderr-fail"},
		{name: "successful oversized stderr", mode: "oversized-stderr-success"},
		{name: "successful oversized stdout", mode: "oversized-stdout-success"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(fakeGitModeEnv, tc.mode)
			output, err := defaultGitCommandOutput(context.Background(), helperArgs...)
			if !errors.Is(err, errGitCommandOutputTooLarge) {
				t.Fatalf("defaultGitCommandOutput() error = %v, want %v", err, errGitCommandOutputTooLarge)
			}
			if output != nil {
				t.Fatalf("defaultGitCommandOutput() output length = %d, want nil", len(output))
			}
		})
	}
}

func TestDefaultGitCommandOutputReturnsChildFailure(t *testing.T) {
	helperArgs := installFakeGit(t)
	t.Setenv(fakeGitModeEnv, "failure")

	output, err := defaultGitCommandOutput(context.Background(), helperArgs...)
	if err == nil {
		t.Fatal("defaultGitCommandOutput() error = nil, want child failure")
	}
	if errors.Is(err, errGitCommandOutputTooLarge) {
		t.Fatalf("defaultGitCommandOutput() error = %v, want process failure", err)
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("defaultGitCommandOutput() error = %T %v, want *exec.ExitError", err, err)
	}
	if strings.Contains(err.Error(), "fake git failure") {
		t.Fatalf("defaultGitCommandOutput() error unexpectedly exposes terminal stderr: %v", err)
	}
	if output != nil {
		t.Fatalf("defaultGitCommandOutput() output = %q, want nil", output)
	}
}

func TestDefaultGitCommandOutputReturnsStdout(t *testing.T) {
	helperArgs := installFakeGit(t)
	t.Setenv(fakeGitModeEnv, "success")

	output, err := defaultGitCommandOutput(context.Background(), helperArgs...)
	if err != nil {
		t.Fatalf("defaultGitCommandOutput() error: %v", err)
	}
	if got, want := string(output), "metadata\n"; got != want {
		t.Fatalf("defaultGitCommandOutput() output = %q, want %q", got, want)
	}
}

func TestDefaultGitCommandOutputCancelsStartedChild(t *testing.T) {
	helperArgs := installFakeGit(t)
	ready := filepath.Join(t.TempDir(), "started")
	t.Setenv(fakeGitModeEnv, "cancel")
	t.Setenv("PACKMON_F027_FAKE_GIT_READY", ready)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	type result struct {
		output []byte
		err    error
	}
	done := make(chan result, 1)
	go func() {
		output, err := defaultGitCommandOutput(ctx, helperArgs...)
		done <- result{output: output, err: err}
	}()
	waitForFakeGitReady(t, ready)
	cancel()

	select {
	case result := <-done:
		if result.err == nil {
			t.Fatal("defaultGitCommandOutput() error = nil after cancellation")
		}
		if result.output != nil {
			t.Fatalf("defaultGitCommandOutput() output = %q, want nil", result.output)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("defaultGitCommandOutput() did not return after cancellation")
	}
	if !errors.Is(ctx.Err(), context.Canceled) {
		t.Fatalf("caller context error = %v, want %v", ctx.Err(), context.Canceled)
	}
}

func TestDefaultGitCommandOutputLimitsPipeDrain(t *testing.T) {
	helperArgs := installFakeGit(t)
	t.Setenv(fakeGitModeEnv, "linger-parent")

	started := time.Now()
	output, err := defaultGitCommandOutput(context.Background(), helperArgs...)
	elapsed := time.Since(started)
	if !errors.Is(err, exec.ErrWaitDelay) {
		t.Fatalf("defaultGitCommandOutput() error = %v, want %v", err, exec.ErrWaitDelay)
	}
	if output != nil {
		t.Fatalf("defaultGitCommandOutput() output = %q, want nil", output)
	}
	if elapsed >= gitMetadataTimeout {
		t.Fatalf("defaultGitCommandOutput() took %s, want less than metadata timeout %s", elapsed, gitMetadataTimeout)
	}
}

func TestGitCommandOutputFakeGit(t *testing.T) {
	mode := os.Getenv(fakeGitModeEnv)
	if mode == "" {
		return
	}

	switch mode {
	case "oversized-stderr-fail":
		writeFakeGitBytes(os.Stderr, maxGitCommandOutputBytes+1)
		os.Exit(23)
	case "oversized-stderr-success":
		writeFakeGitBytes(os.Stderr, maxGitCommandOutputBytes+1)
		os.Exit(0)
	case "oversized-stdout-success":
		writeFakeGitBytes(os.Stdout, maxGitCommandOutputBytes+1)
		os.Exit(0)
	case "failure":
		if _, err := os.Stderr.WriteString("fake git failure\n"); err != nil {
			os.Exit(99)
		}
		os.Exit(23)
	case "success":
		if _, err := os.Stdout.WriteString("metadata\n"); err != nil {
			os.Exit(99)
		}
		if _, err := os.Stderr.WriteString("non-terminal diagnostic\n"); err != nil {
			os.Exit(99)
		}
		os.Exit(0)
	case "cancel":
		ready := os.Getenv("PACKMON_F027_FAKE_GIT_READY")
		if ready == "" || os.WriteFile(ready, []byte("ready"), 0o600) != nil { //nolint:gosec // G703: temp path chosen by the parent test.
			os.Exit(99)
		}
		select {}
	case "linger-parent":
		cmd := exec.Command(os.Args[0], "-test.run=^TestGitCommandOutputFakeGit$") //nolint:gosec // G204/G702: test helper re-executes its own test binary.
		cmd.Env = replaceFakeGitMode(os.Environ(), "linger-child")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err != nil {
			os.Exit(99)
		}
		os.Exit(0)
	case "linger-child":
		time.Sleep(3 * time.Second)
		os.Exit(0)
	default:
		os.Exit(99)
	}
}

func installFakeGit(t *testing.T) []string {
	t.Helper()

	testBinary, err := os.Executable()
	if err != nil {
		t.Fatalf("locate test binary: %v", err)
	}
	dir := t.TempDir()
	name := "git"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	fakeGit := filepath.Join(dir, name)
	copyTestExecutable(t, testBinary, fakeGit)
	t.Setenv("PATH", dir)
	if runtime.GOOS == "windows" {
		t.Setenv("PATHEXT", ".COM;.EXE;.BAT;.CMD")
	}
	return []string{"-test.run=^TestGitCommandOutputFakeGit$", "--"}
}

func copyTestExecutable(t *testing.T, source, destination string) {
	t.Helper()
	in, err := os.Open(source) //nolint:gosec // G304: path built by the test itself, not from request data.
	if err != nil {
		t.Fatalf("open test binary: %v", err)
	}
	defer func() {
		if err := in.Close(); err != nil {
			t.Errorf("close test binary: %v", err)
		}
	}()
	out, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o700) //nolint:gosec // G302: the copied test binary must be executable.
	if err != nil {
		t.Fatalf("create fake git: %v", err)
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		t.Fatalf("copy fake git: %v", err)
	}
	if err := out.Close(); err != nil {
		t.Fatalf("close fake git: %v", err)
	}
}

func waitForFakeGitReady(t *testing.T, ready string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(ready); err == nil {
			return
		} else if !os.IsNotExist(err) {
			t.Fatalf("stat fake git ready marker: %v", err)
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("fake git did not report that it started")
}

func replaceFakeGitMode(env []string, mode string) []string {
	prefix := fakeGitModeEnv + "="
	filtered := make([]string, 0, len(env)+1)
	for _, entry := range env {
		if len(entry) >= len(prefix) && entry[:len(prefix)] == prefix {
			continue
		}
		filtered = append(filtered, entry)
	}
	return append(filtered, prefix+mode)
}

func writeFakeGitBytes(file *os.File, count int) {
	chunk := bytes.Repeat([]byte{'x'}, 32*1024)
	for count > 0 {
		part := chunk
		if count < len(part) {
			part = part[:count]
		}
		written, err := file.Write(part)
		if err != nil || written != len(part) {
			os.Exit(99)
		}
		count -= written
	}
}
