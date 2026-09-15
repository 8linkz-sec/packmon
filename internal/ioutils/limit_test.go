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

func TestSizeLimitReaderRejectsFirstByteWhenLimitIsZero(t *testing.T) {
	reader := NewSizeLimitReader(strings.NewReader("a"), 0, func() error {
		return errSizeLimit
	})

	n, err := reader.Read(make([]byte, 1))
	if n != 0 || !errors.Is(err, errSizeLimit) {
		t.Fatalf("first Read() = %d, %v; want 0, size-limit error", n, err)
	}

	n, err = reader.Read(make([]byte, 1))
	if n != 0 || !errors.Is(err, errSizeLimit) {
		t.Fatalf("second Read() = %d, %v; want sticky size-limit error", n, err)
	}
}

func TestSizeLimitReaderRejectsNegativeLimitBeforeReadingSource(t *testing.T) {
	reader := NewSizeLimitReader(panicReader{}, -1, func() error {
		return errSizeLimit
	})

	n, err := reader.Read(make([]byte, 1))
	if n != 0 || !errors.Is(err, errSizeLimit) {
		t.Fatalf("Read() = %d, %v; want 0, size-limit error", n, err)
	}
}

func TestSizeLimitReaderPreservesEmptyReadError(t *testing.T) {
	wantErr := errors.New("temporary read error")
	reader := NewSizeLimitReader(emptyErrorReader{err: wantErr}, 1, func() error {
		return errSizeLimit
	})

	n, err := reader.Read(make([]byte, 1))
	if n != 0 || !errors.Is(err, wantErr) {
		t.Fatalf("Read() = %d, %v; want 0, temporary read error", n, err)
	}
}

type emptyErrorReader struct {
	err error
}

func (r emptyErrorReader) Read([]byte) (int, error) {
	return 0, r.err
}

type panicReader struct{}

func (panicReader) Read([]byte) (int, error) {
	panic("unexpected source read")
}
