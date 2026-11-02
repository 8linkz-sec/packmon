package correlation

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"strconv"
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

type readerStep struct {
	data []byte
	err  error
}

type scriptedReader struct {
	steps []readerStep
}

func (r *scriptedReader) Read(p []byte) (int, error) {
	if len(r.steps) == 0 {
		return 0, io.EOF
	}
	step := r.steps[0]
	r.steps = r.steps[1:]
	n := copy(p, step.data)
	return n, step.err
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
	source := [16]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
	original := source
	id, err := NewIDFromReader(bytes.NewReader(source[:]))
	if err != nil {
		t.Fatalf("NewIDFromReader() error = %v", err)
	}
	const want = "00010203-0405-4607-8809-0a0b0c0d0e0f"
	if id != want {
		t.Fatalf("NewIDFromReader() = %q, want %q", id, want)
	}
	if source != original {
		t.Fatalf("entropy input changed from %x to %x", original, source)
	}
	formattedBytes, err := hex.DecodeString(strings.ReplaceAll(id, "-", ""))
	if err != nil {
		t.Fatalf("decode formatted UUID: %v", err)
	}
	if len(formattedBytes) != len(source) {
		t.Fatalf("formatted UUID bytes = %d, want %d", len(formattedBytes), len(source))
	}
	for i := range source {
		if i != 6 && i != 8 && formattedBytes[i] != source[i] {
			t.Errorf("formatted byte %d = %02x, want source byte %02x", i, formattedBytes[i], source[i])
		}
	}
	if got := formattedBytes[6] >> 4; got != 4 {
		t.Errorf("UUID version bits = %04b, want 0100", got)
	}
	if got, wantLow := formattedBytes[6]&0x0f, source[6]&0x0f; got != wantLow {
		t.Errorf("UUID version byte low bits = %04b, want source bits %04b", got, wantLow)
	}
	if got := formattedBytes[8] >> 6; got != 2 {
		t.Errorf("UUID variant bits = %02b, want 10", got)
	}
	if got, wantLow := formattedBytes[8]&0x3f, source[8]&0x3f; got != wantLow {
		t.Errorf("UUID variant byte low bits = %06b, want source bits %06b", got, wantLow)
	}
}

func TestNewIDFromReaderAccumulatesChunksAndPreservesErrorCauses(t *testing.T) {
	t.Run("one-byte and bounded empty reads accumulate full entropy", func(t *testing.T) {
		const want = "30313233-3435-4637-b839-616263646566"
		entropy := []byte("0123456789abcdef")
		oneByteReader := &fixedChunkReader{data: append([]byte(nil), entropy...), chunkSize: 1}
		id, err := NewIDFromReader(oneByteReader)
		if err != nil {
			t.Fatalf("NewIDFromReader(one-byte chunks) error = %v", err)
		}
		if id != want {
			t.Fatalf("NewIDFromReader(one-byte chunks) = %q, want %q", id, want)
		}
		if len(oneByteReader.data) != 0 {
			t.Fatalf("unread one-byte entropy = %d bytes, want 0", len(oneByteReader.data))
		}

		zeroThenSuccess := &scriptedReader{steps: []readerStep{{}, {data: entropy}}}
		id, err = NewIDFromReader(zeroThenSuccess)
		if err != nil || id != want {
			t.Fatalf("NewIDFromReader(zero then success) = %q, %v; want %q, nil", id, err, want)
		}
	})

	t.Run("bounded empty and partial read preserves sentinel cause", func(t *testing.T) {
		sentinel := errors.New("entropy sentinel")
		reader := &scriptedReader{steps: []readerStep{{}, {data: []byte("partial"), err: sentinel}}}
		id, err := NewIDFromReader(reader)
		if id != "" || !errors.Is(err, sentinel) {
			t.Fatalf("NewIDFromReader(zero, partial, sentinel) = %q, %v; want empty ID wrapping sentinel", id, err)
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
	const workers = 512
	const counterBase uint64 = 0xc000000000001000
	const lower62Mask uint64 = 1<<62 - 1
	previousCounter := fallbackCounter.Load()
	fallbackCounter.Store(counterBase)
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
	seenLowerCounters := make(map[uint64]struct{}, workers)
	for id := range ids {
		if !Valid(id) {
			t.Fatalf("FallbackID() = %q, want canonical lowercase UUID shape", id)
		}
		if _, duplicate := seenIDs[id]; duplicate {
			t.Fatalf("duplicate fallback ID %q", id)
		}
		seenIDs[id] = struct{}{}
		counterHex := id[19:23] + id[24:]
		formattedCounter, err := strconv.ParseUint(counterHex, 16, 64)
		if err != nil {
			t.Fatalf("parse fallback counter %q: %v", counterHex, err)
		}
		if got := formattedCounter >> 62; got != 2 {
			t.Fatalf("formatted counter variant bits = %02b, want 10", got)
		}
		lowerCounter := formattedCounter & lower62Mask
		if _, duplicate := seenLowerCounters[lowerCounter]; duplicate {
			t.Fatalf("duplicate lower-62 counter value %x", lowerCounter)
		}
		seenLowerCounters[lowerCounter] = struct{}{}
	}
	if len(seenIDs) != workers {
		t.Fatalf("unique fallback IDs = %d, want %d", len(seenIDs), workers)
	}
	if len(seenLowerCounters) != workers {
		t.Fatalf("unique lower-62 counters = %d, want %d", len(seenLowerCounters), workers)
	}
	for increment := uint64(1); increment <= workers; increment++ {
		want := (counterBase + increment) & lower62Mask
		if _, ok := seenLowerCounters[want]; !ok {
			t.Fatalf("missing lower-62 counter value %x", want)
		}
	}
}
