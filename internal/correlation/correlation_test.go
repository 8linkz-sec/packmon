package correlation

import (
	"errors"
	"io"
	"strings"
	"testing"
)

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) {
	return 0, errors.New("entropy unavailable")
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
