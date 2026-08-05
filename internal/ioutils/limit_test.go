package ioutils

import (
	"errors"
	"io"
	"strings"
	"testing"
)

var errSizeLimit = errors.New("size limit exceeded")

func TestSizeLimitReaderAllowsExactLimit(t *testing.T) {
	reader := NewSizeLimitReader(strings.NewReader("a"), 1, func() error {
		return errSizeLimit
	})
	buf := make([]byte, 2)
	n, err := reader.Read(buf)
	if n != 1 || err != nil {
		t.Fatalf("first Read() = %d, %v; want 1, nil", n, err)
	}
	n, err = reader.Read(buf)
	if n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("second Read() = %d, %v; want 0, EOF", n, err)
	}
}

func TestSizeLimitReaderRejectsBytePastLimit(t *testing.T) {
	reader := NewSizeLimitReader(strings.NewReader("ab"), 1, func() error {
		return errSizeLimit
	})
	buf := make([]byte, 2)
	n, err := reader.Read(buf)
	if n != 1 || err != nil {
		t.Fatalf("first Read() = %d, %v; want 1, nil", n, err)
	}
	n, err = reader.Read(buf)
	if n != 0 || !errors.Is(err, errSizeLimit) {
		t.Fatalf("second Read() = %d, %v; want size-limit error", n, err)
	}
}
