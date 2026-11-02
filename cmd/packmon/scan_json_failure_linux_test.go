//go:build linux

package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/domain"
)

func TestWriteJSONFileReportsBrokenPipeWriteFailure(t *testing.T) {
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatalf("create pipe: %v", err)
	}
	defer func() { _ = write.Close() }()
	if err := read.Close(); err != nil {
		t.Fatalf("close pipe reader: %v", err)
	}

	path := fmt.Sprintf("/proc/self/fd/%d", write.Fd())
	err = writeJSONFile(path, &domain.ScanResult{ScannedAt: time.Now().UTC()})
	if err == nil || !strings.Contains(err.Error(), "write file "+path+":") {
		t.Fatalf("writeJSONFile() error = %v, want contextual write failure", err)
	}
	if !errors.Is(err, syscall.EPIPE) {
		t.Fatalf("writeJSONFile() error = %v, want errors.Is(err, syscall.EPIPE)", err)
	}
}
