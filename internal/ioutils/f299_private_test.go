package ioutils

import (
	"errors"
	"os"
	"runtime"
	"testing"
)

func TestF299OpenPrivateFileReturnsChmodErrorForWindowsDevice(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows device files provide the deterministic post-open chmod failure")
	}

	file, err := OpenPrivateFile(`\\.\NUL`)
	if err == nil {
		CloseSilently(file)
		t.Fatal("OpenPrivateFile(NUL) error = nil, want chmod failure")
	}
	if file != nil {
		CloseSilently(file)
		t.Fatalf("OpenPrivateFile(NUL) file = %v, want nil on chmod failure", file)
	}
	var pathErr *os.PathError
	if !errors.As(err, &pathErr) || pathErr.Op != "chmod" {
		t.Fatalf("OpenPrivateFile(NUL) error = %T %v, want *os.PathError with Op chmod", err, err)
	}
}
