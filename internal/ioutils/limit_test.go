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

func TestSizeLimitReaderTruncatesSourceReadToLimitPlusSentinel(t *testing.T) {
	source := &recordingReader{data: []byte("abcdef")}
	reader := NewSizeLimitReader(source, 2, func() error {
		return errSizeLimit
	})
	buf := make([]byte, 8)

	n, err := reader.Read(buf)
	if n != 2 || err != nil || string(buf[:n]) != "ab" {
		t.Fatalf("first Read() = %d, %v, %q; want 2, nil, ab", n, err, buf[:n])
	}
	if len(source.readSizes) != 1 || source.readSizes[0] != 3 {
		t.Fatalf("source read sizes = %v, want [3]", source.readSizes)
	}

	n, err = reader.Read(buf)
	if n != 0 || !errors.Is(err, errSizeLimit) {
		t.Fatalf("second Read() = %d, %v; want 0, size-limit error", n, err)
	}
	if len(source.readSizes) != 1 {
		t.Fatalf("source read sizes after sticky error = %v, want one source read", source.readSizes)
	}
}

func TestSizeLimitReaderReturnsAllowedBytesBeforeStickyErrorAfterPartialRead(t *testing.T) {
	source := io.MultiReader(strings.NewReader("a"), strings.NewReader("bcd"))
	reader := NewSizeLimitReader(source, 3, func() error {
		return errSizeLimit
	})
	buf := make([]byte, 8)

	n, err := reader.Read(buf)
	if n != 1 || err != nil || string(buf[:n]) != "a" {
		t.Fatalf("first Read() = %d, %v, %q; want 1, nil, a", n, err, buf[:n])
	}

	n, err = reader.Read(buf)
	if n != 2 || err != nil || string(buf[:n]) != "bc" {
		t.Fatalf("second Read() = %d, %v, %q; want 2, nil, bc", n, err, buf[:n])
	}

	n, err = reader.Read(buf)
	if n != 0 || !errors.Is(err, errSizeLimit) {
		t.Fatalf("third Read() = %d, %v; want 0, sticky size-limit error", n, err)
	}
}

func TestSizeLimitReaderHandlesDataWithSourceError(t *testing.T) {
	wantErr := errors.New("source read error")
	tests := []struct {
		name        string
		limit       int64
		wantErr     error
		wantNextErr error
	}{
		{name: "within limit preserves source error", limit: 2, wantErr: wantErr},
		{name: "crossing limit returns data before limit error", limit: 1, wantNextErr: errSizeLimit},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := NewSizeLimitReader(dataErrorReader{data: []byte("ab"), err: wantErr}, tt.limit, func() error {
				return errSizeLimit
			})
			buf := make([]byte, 2)

			n, err := reader.Read(buf)
			if n != int(tt.limit) || !errors.Is(err, tt.wantErr) || string(buf[:n]) != "ab"[:n] {
				t.Fatalf("first Read() = %d, %v, %q; want %d, %v, %q", n, err, buf[:n], tt.limit, tt.wantErr, "ab"[:n])
			}

			if tt.wantNextErr != nil {
				n, err = reader.Read(buf)
				if n != 0 || !errors.Is(err, tt.wantNextErr) {
					t.Fatalf("second Read() = %d, %v; want 0, %v", n, err, tt.wantNextErr)
				}
			}
		})
	}
}

type emptyErrorReader struct {
	err error
}

func (r emptyErrorReader) Read([]byte) (int, error) {
	return 0, r.err
}

type recordingReader struct {
	data      []byte
	readSizes []int
}

func (r *recordingReader) Read(p []byte) (int, error) {
	r.readSizes = append(r.readSizes, len(p))
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}

type dataErrorReader struct {
	data []byte
	err  error
}

func (r dataErrorReader) Read(p []byte) (int, error) {
	return copy(p, r.data), r.err
}

type panicReader struct{}

func (panicReader) Read([]byte) (int, error) {
	panic("unexpected source read")
}
