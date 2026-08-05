package ci

import (
	"strings"
	"testing"
)

// assertSubstringOrder fails when either marker is missing from text or when
// before does not appear ahead of after.
func assertSubstringOrder(t *testing.T, text, before, after string) {
	t.Helper()

	beforeIndex := strings.Index(text, before)
	if beforeIndex == -1 {
		t.Fatalf("missing ordered marker %q", before)
	}
	afterIndex := strings.Index(text, after)
	if afterIndex == -1 {
		t.Fatalf("missing ordered marker %q", after)
	}
	if beforeIndex > afterIndex {
		t.Fatalf("marker %q must appear before %q", before, after)
	}
}
