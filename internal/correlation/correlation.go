// Package correlation defines Packmon correlation-ID primitives shared by
// clients, server middleware, and handlers.
package correlation

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"regexp"
	"sync/atomic"
	"time"
)

// Header is the canonical HTTP header for request correlation IDs.
const Header = "X-Correlation-ID"

var idPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

var fallbackCounter atomic.Uint64

// Valid reports whether id is a canonical lowercase UUID-shaped correlation ID.
func Valid(id string) bool {
	return idPattern.MatchString(id)
}

// NewID returns a new random UUID v4 correlation ID.
func NewID() (string, error) {
	return NewIDFromReader(rand.Reader)
}

// NewIDFromReader returns a UUID v4 generated from r. It exists for tests and
// for callers that need to verify entropy-failure handling explicitly.
func NewIDFromReader(r io.Reader) (string, error) {
	var b [16]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return "", fmt.Errorf("correlation id entropy: %w", err)
	}
	return formatUUIDV4(b), nil
}

// FallbackID returns a UUID-shaped ID for rare entropy failures. It is not
// cryptographically random, but includes wall-clock time and a process-local
// counter to avoid the all-zero collision failure mode.
func FallbackID() string {
	var b [16]byte
	binary.BigEndian.PutUint64(b[0:8], uint64(time.Now().UnixNano()))
	binary.BigEndian.PutUint64(b[8:16], fallbackCounter.Add(1))
	return formatUUIDV4(b)
}

func formatUUIDV4(b [16]byte) string {
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf(
		"%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16],
	)
}
