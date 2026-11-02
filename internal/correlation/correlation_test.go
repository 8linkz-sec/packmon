package correlation

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
)

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) {
	return 0, errors.New("entropy unavailable")
}

type fixedChunkReader struct {
	data      []byte
	chunkSize int
}

func (r *fixedChunkReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := min(len(r.data), min(len(p), r.chunkSize))
	copy(p, r.data[:n])
	r.data = r.data[n:]
	return n, nil
}

type fixedErrorReader struct {
	err error
}

func (r fixedErrorReader) Read([]byte) (int, error) {
	return 0, r.err
}

func TestNewIDAndFallbackAreValidUUIDs(t *testing.T) {
	id, err := NewID()
	if err != nil {
		t.Fatalf("NewID() error = %v", err)
	}
	if !Valid(id) {
		t.Fatalf("NewID() = %q, want valid correlation ID", id)
	}

	fallback := FallbackID()
	if !Valid(fallback) {
		t.Fatalf("FallbackID() = %q, want valid correlation ID", fallback)
	}
	if fallback == FallbackID() {
		t.Fatal("FallbackID() returned the same value twice")
	}
}

func TestNewIDReportsEntropyFailure(t *testing.T) {
	id, err := NewIDFromReader(failingReader{})
	if err == nil {
		t.Fatal("NewIDFromReader(failing) error = nil")
	}
	if id != "" {
		t.Fatalf("NewIDFromReader(failing) id = %q, want empty", id)
	}
	if !strings.Contains(err.Error(), "correlation id entropy") {
		t.Fatalf("NewIDFromReader(failing) error = %v, want correlation context", err)
	}
}

func TestValidRejectsMalformedIDs(t *testing.T) {
	for _, raw := range []string{
		"",
		"not-a-uuid",
		"11111111-2222-4333-8444-55555555555",
		"11111111-2222-4333-8444-555555555555\nx",
		"11111111-2222-4333-8444-55555555555Z",
	} {
		if Valid(raw) {
			t.Fatalf("Valid(%q) = true", raw)
		}
	}
}

func TestNewIDFromReaderRequiresFullEntropy(t *testing.T) {
	if id, err := NewIDFromReader(io.LimitReader(strings.NewReader("short"), 5)); err == nil || id != "" {
		t.Fatalf("NewIDFromReader(short) = %q, %v; want error and empty id", id, err)
	}
}

func TestNewIDFromReaderFormatsDeterministicUUIDV4(t *testing.T) {
	source := [16]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0xaf, 0x77, 0xff, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	id, err := NewIDFromReader(bytes.NewReader(source[:]))
	if err != nil {
		t.Fatalf("NewIDFromReader() error = %v", err)
	}
	const want = "00112233-4455-4f77-bf99-aabbccddeeff"
	if id != want {
		t.Fatalf("NewIDFromReader() = %q, want %q", id, want)
	}
	if id[14] != '4' {
		t.Fatalf("UUID version nibble = %q, want 4", id[14])
	}
	if !strings.ContainsRune("89ab", rune(id[19])) {
		t.Fatalf("UUID variant nibble = %q, want RFC 4122 variant", id[19])
	}
	if !bytes.Equal(source[:6], []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}) ||
		!bytes.Equal(source[9:], []byte{0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}) {
		t.Fatalf("source bytes outside version and variant positions changed: %x", source)
	}
}

func TestNewIDFromReaderAccumulatesChunksAndPreservesErrorCauses(t *testing.T) {
	t.Run("chunked successful reads accumulate full entropy", func(t *testing.T) {
		reader := &fixedChunkReader{data: []byte("0123456789abcdef"), chunkSize: 3}
		id, err := NewIDFromReader(reader)
		if err != nil {
			t.Fatalf("NewIDFromReader(chunked) error = %v", err)
		}
		if id != "30313233-3435-4637-b839-616263646566" {
			t.Fatalf("NewIDFromReader(chunked) = %q", id)
		}
		if len(reader.data) != 0 {
			t.Fatalf("unread entropy bytes = %d, want 0", len(reader.data))
		}
	})

	t.Run("wrapped sentinel error preserves cause", func(t *testing.T) {
		sentinel := errors.New("entropy sentinel")
		id, err := NewIDFromReader(fixedErrorReader{err: sentinel})
		if id != "" || !errors.Is(err, sentinel) {
			t.Fatalf("NewIDFromReader(sentinel) = %q, %v; want empty ID wrapping sentinel", id, err)
		}
	})

	t.Run("empty reader preserves EOF", func(t *testing.T) {
		id, err := NewIDFromReader(strings.NewReader(""))
		if id != "" || !errors.Is(err, io.EOF) {
			t.Fatalf("NewIDFromReader(empty) = %q, %v; want empty ID wrapping EOF", id, err)
		}
	})

	t.Run("short reader preserves unexpected EOF", func(t *testing.T) {
		id, err := NewIDFromReader(strings.NewReader("short"))
		if id != "" || !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("NewIDFromReader(short) = %q, %v; want empty ID wrapping unexpected EOF", id, err)
		}
	})
}

func TestValidCorrelationIDShapeMatrix(t *testing.T) {
	tests := []struct {
		name string
		id   string
		want bool
	}{
		{name: "canonical lowercase version 4", id: "11111111-2222-4333-8444-555555555555", want: true},
		{name: "canonical lowercase non-version-4 shape", id: "11111111-2222-1333-7444-555555555555", want: true},
		{name: "uppercase hex", id: "AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE"},
		{name: "surrounding whitespace", id: " 11111111-2222-4333-8444-555555555555 "},
		{name: "trailing newline only", id: "11111111-2222-4333-8444-555555555555\n"},
		{name: "missing final hex digit", id: "11111111-2222-4333-8444-55555555555"},
		{name: "extra final hex digit", id: "11111111-2222-4333-8444-5555555555555"},
		{name: "non-hex character", id: "11111111-2222-4333-8444-55555555555z"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Valid(tt.id); got != tt.want {
				t.Fatalf("Valid(%q) = %v, want %v", tt.id, got, tt.want)
			}
		})
	}
}

func TestFallbackIDConcurrentUniqueness(t *testing.T) {
	const workers = 128
	previousCounter := fallbackCounter.Load()
	fallbackCounter.Store(0)
	t.Cleanup(func() {
		fallbackCounter.Store(previousCounter)
	})

	start := make(chan struct{})
	ids := make(chan string, workers)
	var wait sync.WaitGroup
	wait.Add(workers)
	for range workers {
		go func() {
			defer wait.Done()
			<-start
			ids <- FallbackID()
		}()
	}
	close(start)
	wait.Wait()
	close(ids)

	seenIDs := make(map[string]struct{}, workers)
	seenCounterSuffixes := make(map[string]struct{}, workers)
	for id := range ids {
		if !Valid(id) {
			t.Fatalf("FallbackID() = %q, want canonical lowercase UUID shape", id)
		}
		if _, duplicate := seenIDs[id]; duplicate {
			t.Fatalf("duplicate fallback ID %q", id)
		}
		seenIDs[id] = struct{}{}
		seenCounterSuffixes[id[len(id)-12:]] = struct{}{}
	}
	if len(seenIDs) != workers {
		t.Fatalf("unique fallback IDs = %d, want %d", len(seenIDs), workers)
	}
	for counter := 1; counter <= workers; counter++ {
		suffix := fmt.Sprintf("%012x", counter)
		if _, ok := seenCounterSuffixes[suffix]; !ok {
			t.Fatalf("missing process-local counter suffix %q", suffix)
		}
	}
}
