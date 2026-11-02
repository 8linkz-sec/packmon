//go:build !windows

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/domain"
)

func TestWriteListAllHTMLReportsRenderFailureWhenPipeReaderCloses(t *testing.T) {
	pipePath := filepath.Join(t.TempDir(), "list-all.html")
	if err := syscall.Mkfifo(pipePath, 0o600); err != nil {
		t.Fatalf("create HTML output FIFO: %v", err)
	}

	// A nonblocking reader lets the product writer open the FIFO while the
	// blocking reader below synchronizes on that writer and consumes one byte.
	keeper, err := os.OpenFile(pipePath, os.O_RDONLY|syscall.O_NONBLOCK, 0) //nolint:gosec // G304: pipePath is test-owned.
	if err != nil {
		t.Fatalf("open nonblocking FIFO keeper: %v", err)
	}
	keeperOpen := true
	closeKeeper := func() {
		if keeperOpen {
			keeperOpen = false
			if err := keeper.Close(); err != nil {
				t.Errorf("close FIFO keeper: %v", err)
			}
		}
	}
	t.Cleanup(closeKeeper)

	type readResult struct {
		count int
		err   error
	}
	readDone := make(chan readResult, 1)
	writeDone := make(chan error, 1)
	go func() {
		reader, openErr := os.Open(pipePath) //nolint:gosec // G304: pipePath is test-owned.
		if openErr != nil {
			readDone <- readResult{err: fmt.Errorf("open blocking FIFO reader: %w", openErr)}
			return
		}
		defer reader.Close()
		one := make([]byte, 1)
		count, readErr := reader.Read(one)
		readDone <- readResult{count: count, err: readErr}
	}()
	go func() {
		writeDone <- writeListAllHTML(
			pipePath,
			strings.Repeat("A", 4<<20),
			&domain.ScanResult{Mode: "local"},
			listAllPackageReport{},
		)
	}()

	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	var read readResult
	select {
	case read = <-readDone:
	case <-deadline.C:
		closeKeeper()
		select {
		case err := <-writeDone:
			t.Fatalf("blocking FIFO reader timed out; writer returned %v", err)
		case <-time.After(2 * time.Second):
			t.Fatal("blocking FIFO reader and HTML writer did not stop after active FIFO cleanup")
		}
	}
	if read.err != nil {
		closeKeeper()
		<-writeDone
		t.Fatalf("read first HTML byte: %v", read.err)
	}
	if read.count != 1 {
		closeKeeper()
		<-writeDone
		t.Fatalf("HTML FIFO read count = %d, want 1", read.count)
	}

	// With both readers closed, the still-streaming template render must see
	// the broken pipe instead of completing successfully or hanging.
	closeKeeper()
	select {
	case err = <-writeDone:
	case <-time.After(10 * time.Second):
		t.Fatal("HTML writer did not report the closed FIFO reader")
	}
	if err == nil {
		t.Fatal("writeListAllHTML() error = nil, want broken-pipe render failure")
	}
	if !strings.Contains(err.Error(), "html: render list-all report") {
		t.Fatalf("writeListAllHTML() error = %q, want render context", err)
	}
	if !errors.Is(err, syscall.EPIPE) {
		t.Fatalf("writeListAllHTML() error = %v, want errors.Is(EPIPE)", err)
	}
}
