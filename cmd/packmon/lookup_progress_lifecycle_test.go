package main

import (
	"bytes"
	"fmt"
	"sync"
	"testing"
	"time"
)

type gatedProgressWrite struct {
	line    string
	release chan struct{}
}

type gatedProgressWriter struct {
	mu        sync.Mutex
	output    bytes.Buffer
	writes    chan gatedProgressWrite
	abortCh   chan struct{}
	abortOnce sync.Once
}

func newGatedProgressWriter() *gatedProgressWriter {
	return &gatedProgressWriter{
		writes:  make(chan gatedProgressWrite),
		abortCh: make(chan struct{}),
	}
}

func (w *gatedProgressWriter) Write(p []byte) (int, error) {
	line := string(append([]byte(nil), p...))
	w.mu.Lock()
	_, _ = w.output.WriteString(line)
	w.mu.Unlock()

	write := gatedProgressWrite{line: line, release: make(chan struct{})}
	select {
	case w.writes <- write:
	case <-w.abortCh:
		return len(p), nil
	}
	select {
	case <-write.release:
	case <-w.abortCh:
	}
	return len(p), nil
}

func (w *gatedProgressWriter) abort() {
	w.abortOnce.Do(func() { close(w.abortCh) })
}

func (w *gatedProgressWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.output.String()
}

func waitForProgressWrite(t *testing.T, writer *gatedProgressWriter) gatedProgressWrite {
	t.Helper()
	select {
	case write := <-writer.writes:
		return write
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for progress write")
		return gatedProgressWrite{}
	}
}

func waitForProgressSignal(t *testing.T, signal <-chan struct{}, description string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", description)
	}
}

func TestLookupProgressStopIsConcurrentAndIdempotent(t *testing.T) {
	writer := newGatedProgressWriter()
	progress := startLookupProgress(writer, 7, false, 20*time.Millisecond)
	if progress == nil {
		t.Fatal("startLookupProgress returned nil")
	}
	t.Cleanup(func() {
		writer.abort()
		progress.stop()
	})

	write := waitForProgressWrite(t, writer)
	if write.line != "  0/7 packages checked\n" {
		t.Fatalf("first progress line = %q, want exact 0/7 line", write.line)
	}

	const callers = 32
	start := make(chan struct{})
	entered := make(chan struct{}, callers)
	returned := make(chan struct{}, callers)
	for range callers {
		go func() {
			<-start
			entered <- struct{}{}
			progress.stop()
			returned <- struct{}{}
		}()
	}
	close(start)
	for range callers {
		waitForProgressSignal(t, entered, "stop caller entry")
	}
	waitForProgressSignal(t, progress.stopCh, "progress stop channel")
	select {
	case <-returned:
		t.Fatal("stop returned while the progress writer was blocked")
	default:
	}

	close(write.release)
	for range callers {
		waitForProgressSignal(t, returned, "concurrent stop return")
	}
	progress.stop()
	progress.increment()
	progress.stop()
	if got, want := writer.String(), "  0/7 packages checked\n"; got != want {
		t.Fatalf("progress output after repeated stop/increment = %q, want %q", got, want)
	}
}

func TestLookupProgressReportsExactUpdatedCounts(t *testing.T) {
	writer := newGatedProgressWriter()
	progress := startLookupProgress(writer, 3, false, 50*time.Millisecond)
	if progress == nil {
		t.Fatal("startLookupProgress returned nil")
	}
	t.Cleanup(func() {
		writer.abort()
		progress.stop()
	})

	first := waitForProgressWrite(t, writer)
	if first.line != "  0/3 packages checked\n" {
		t.Fatalf("first progress line = %q, want exact 0/3 line", first.line)
	}
	progress.increment()
	progress.increment()
	close(first.release)

	second := waitForProgressWrite(t, writer)
	if second.line != "  2/3 packages checked\n" {
		t.Fatalf("second progress line = %q, want exact 2/3 line", second.line)
	}
	stopReturned := make(chan struct{})
	go func() {
		progress.stop()
		close(stopReturned)
	}()
	waitForProgressSignal(t, progress.stopCh, "progress stop channel")
	select {
	case <-stopReturned:
		t.Fatal("stop returned while the second progress write was blocked")
	default:
	}
	close(second.release)
	waitForProgressSignal(t, stopReturned, "progress stop return")

	if got, want := writer.String(), "  0/3 packages checked\n  2/3 packages checked\n"; got != want {
		t.Fatalf("progress output = %q, want %q", got, want)
	}
}

func TestLookupProgressCountsConcurrentIncrements(t *testing.T) {
	const increments = 64
	writer := newGatedProgressWriter()
	progress := startLookupProgress(writer, increments, false, 50*time.Millisecond)
	if progress == nil {
		t.Fatal("startLookupProgress returned nil")
	}
	t.Cleanup(func() {
		writer.abort()
		progress.stop()
	})

	first := waitForProgressWrite(t, writer)
	wantFirst := fmt.Sprintf("  0/%d packages checked\n", increments)
	if first.line != wantFirst {
		t.Fatalf("first progress line = %q, want %q", first.line, wantFirst)
	}

	start := make(chan struct{})
	var startOnce sync.Once
	var incrementWG sync.WaitGroup
	t.Cleanup(func() {
		startOnce.Do(func() { close(start) })
		incrementWG.Wait()
	})
	ready := make(chan struct{}, increments)
	done := make(chan struct{}, increments)
	for range increments {
		incrementWG.Add(1)
		go func() {
			defer incrementWG.Done()
			ready <- struct{}{}
			<-start
			progress.increment()
			done <- struct{}{}
		}()
	}
	for range increments {
		waitForProgressSignal(t, ready, "increment caller readiness")
	}
	startOnce.Do(func() { close(start) })
	for range increments {
		waitForProgressSignal(t, done, "increment completion")
	}
	if got := progress.done.Load(); got != increments {
		t.Fatalf("completed lookup count = %d, want %d", got, increments)
	}
	close(first.release)

	second := waitForProgressWrite(t, writer)
	wantSecond := fmt.Sprintf("  %d/%d packages checked\n", increments, increments)
	if second.line != wantSecond {
		t.Fatalf("second progress line = %q, want %q", second.line, wantSecond)
	}
	stopReturned := make(chan struct{})
	go func() {
		progress.stop()
		close(stopReturned)
	}()
	waitForProgressSignal(t, progress.stopCh, "progress stop channel")
	close(second.release)
	waitForProgressSignal(t, stopReturned, "progress stop return")

	if got, want := writer.String(), wantFirst+wantSecond; got != want {
		t.Fatalf("progress output = %q, want %q", got, want)
	}
}
