//go:build !windows

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

const outdatedAbsolutePathFailureHelperEnv = "PACKMON_TEST_OUTDATED_ABSOLUTE_PATH_FAILURE_HELPER"

type boundedCommandOutput struct {
	mu    sync.Mutex
	data  []byte
	limit int
}

func (w *boundedCommandOutput) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	remaining := w.limit - len(w.data)
	if remaining > 0 {
		w.data = append(w.data, p[:min(len(p), remaining)]...)
	}
	return len(p), nil
}

func (w *boundedCommandOutput) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return string(w.data)
}

func finiteTestWait(t *testing.T, maximum time.Duration) time.Duration {
	t.Helper()
	if deadline, ok := t.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining <= 2*time.Second {
			t.Fatalf("test deadline leaves only %s for bounded subprocess work", remaining)
		}
		if derived := remaining / 2; derived < maximum {
			return derived
		}
	}
	return maximum
}

func TestRunOutdatedReportsAbsolutePathFailure(t *testing.T) {
	timeout := finiteTestWait(t, 15*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	childArgs := []string{"-test.run=^TestRunOutdatedReportsAbsolutePathFailureHelper$"}
	for _, arg := range os.Args[1:] {
		if strings.HasPrefix(arg, "-test.gocoverdir=") {
			childArgs = append(childArgs, arg)
			break
		}
	}
	cmd := exec.CommandContext(ctx, os.Args[0], childArgs...) // #nosec G204,G702 -- reexecutes this exact test binary with fixed helper arguments.
	cmd.Env = append(os.Environ(), outdatedAbsolutePathFailureHelperEnv+"=1")
	output := &boundedCommandOutput{limit: 32 << 10}
	cmd.Stdout = output
	cmd.Stderr = output
	err := cmd.Run()
	if ctx.Err() != nil {
		t.Fatalf("absolute-path helper exceeded %s; bounded output:\n%s", timeout, output.String())
	}
	if err != nil {
		t.Fatalf("absolute-path helper failed: %v; bounded output:\n%s", err, output.String())
	}
}

func TestRunOutdatedReportsAbsolutePathFailureHelper(t *testing.T) {
	if os.Getenv(outdatedAbsolutePathFailureHelperEnv) != "1" {
		return
	}

	original, err := os.Getwd()
	if err != nil {
		t.Fatalf("get original working directory: %v", err)
	}
	removedCWD := t.TempDir()
	if err := os.Chdir(removedCWD); err != nil {
		t.Fatalf("change to test-owned working directory: %v", err)
	}
	restored := false
	defer func() {
		if !restored {
			if restoreErr := os.Chdir(original); restoreErr != nil {
				t.Errorf("restore original working directory: %v", restoreErr)
			}
		}
	}()
	if err := os.Remove(removedCWD); err != nil {
		t.Fatalf("remove current test-owned working directory: %v", err)
	}
	if _, err := os.Getwd(); err == nil {
		t.Fatal("Getwd() error = nil after removing current directory")
	}

	runErr := runOutdatedWithOptions(nil, outdatedOptions{Context: context.Background()})
	if runErr == nil || exitCodeForError(runErr) != ExitOperational {
		t.Fatalf("runOutdatedWithOptions(removed cwd) = %v (exit %d), want operational exit %d", runErr, exitCodeForError(runErr), ExitOperational)
	}
	if !strings.Contains(runErr.Error(), "resolve path:") {
		t.Fatalf("removed-cwd error = %q, want resolve-path context", runErr)
	}

	if err := os.Chdir(original); err != nil {
		t.Fatalf("restore original working directory: %v", err)
	}
	restored = true
}

func TestWriteOutdatedHTMLReportsRenderFailureWhenPipeReaderCloses(t *testing.T) {
	// The repository may live on a mounted Windows filesystem under WSL,
	// where named pipes are unsupported. Keep this kernel primitive on the
	// native POSIX temporary filesystem.
	pipeDir, err := os.MkdirTemp("/tmp", "packmon-outdated-fifo-")
	if err != nil {
		t.Fatalf("create native temporary FIFO directory: %v", err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(pipeDir); err != nil {
			t.Errorf("remove native temporary FIFO directory: %v", err)
		}
	})
	pipePath := filepath.Join(pipeDir, "outdated.html")
	if err := syscall.Mkfifo(pipePath, 0o600); err != nil {
		t.Fatalf("create HTML output FIFO: %v", err)
	}

	keeperFD, err := syscall.Open(pipePath, syscall.O_RDWR|syscall.O_NONBLOCK, 0)
	if err != nil {
		t.Fatalf("open nonblocking FIFO keeper: %v", err)
	}
	keeper := os.NewFile(uintptr(keeperFD), pipePath)
	reader, err := os.OpenFile(pipePath, os.O_RDONLY, 0) //nolint:gosec // G304: pipePath is test-owned.
	if err != nil {
		_ = keeper.Close()
		t.Fatalf("open consuming FIFO reader: %v", err)
	}

	var cleanupErrors []error
	readerOpen := true
	closeReader := func() {
		if !readerOpen {
			return
		}
		readerOpen = false
		if closeErr := reader.Close(); closeErr != nil {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("close consuming FIFO reader: %w", closeErr))
		}
	}
	keeperOpen := true
	closeKeeper := func() {
		if !keeperOpen {
			return
		}
		keeperOpen = false
		if closeErr := keeper.Close(); closeErr != nil {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("close FIFO keeper: %w", closeErr))
		}
	}

	type readResult struct {
		count int
		err   error
	}
	readDone := make(chan readResult, 1)
	writeDone := make(chan error, 1)
	go func() {
		one := make([]byte, 1)
		count, readErr := reader.Read(one)
		readDone <- readResult{count: count, err: readErr}
	}()
	go func() {
		writeDone <- writeOutdatedHTML(pipePath, outdatedReport{
			Target:      strings.Repeat("A", 8<<20),
			PackageWord: "packages",
		})
	}()

	wait := finiteTestWait(t, 10*time.Second)
	var failures []string
	var read readResult
	readJoined := false
	select {
	case read = <-readDone:
		readJoined = true
	case <-time.After(wait):
		failures = append(failures, fmt.Sprintf("FIFO reader did not receive the first HTML byte within %s", wait))
	}

	// The product writer has entered its streaming render once the consuming
	// reader receives a byte. Closing both readers then forces the pending
	// multi-MiB template write to return EPIPE.
	closeReader()
	closeKeeper()

	if !readJoined {
		select {
		case read = <-readDone:
			readJoined = true
		case <-time.After(2 * time.Second):
			failures = append(failures, "FIFO reader did not stop after its file was closed")
		}
	}

	var writeErr error
	writeJoined := false
	select {
	case writeErr = <-writeDone:
		writeJoined = true
	case <-time.After(wait):
		failures = append(failures, fmt.Sprintf("HTML writer did not stop within %s after both FIFO readers closed", wait))
	}
	if !writeJoined {
		select {
		case writeErr = <-writeDone:
			writeJoined = true
		case <-time.After(2 * time.Second):
			failures = append(failures, "HTML writer remained blocked after bounded cleanup")
		}
	}

	if readJoined && (read.err != nil || read.count != 1) {
		failures = append(failures, fmt.Sprintf("first HTML read = (%d, %v), want (1, nil)", read.count, read.err))
	}
	if writeJoined {
		if writeErr == nil {
			failures = append(failures, "writeOutdatedHTML() error = nil, want broken-pipe render failure")
		} else {
			if !strings.Contains(writeErr.Error(), "html: render outdated report") {
				failures = append(failures, fmt.Sprintf("writeOutdatedHTML() error = %q, want render context", writeErr))
			}
			if !errors.Is(writeErr, syscall.EPIPE) {
				failures = append(failures, fmt.Sprintf("writeOutdatedHTML() error = %v, want errors.Is(EPIPE)", writeErr))
			}
		}
	}
	for _, cleanupErr := range cleanupErrors {
		failures = append(failures, cleanupErr.Error())
	}
	if len(failures) > 0 {
		t.Fatal(strings.Join(failures, "; "))
	}
}
