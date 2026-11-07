package feed

import (
	"errors"
	"strings"
	"testing"
)

func TestSafeDiagnosticErrorRedactsPathsURLsAndTokens(t *testing.T) {
	t.Parallel()

	err := errors.New(`git failed in C:\Users\Admin\feed-data\repo; remote https://user-secret:pass-secret@example.test/repo.git?token=query-secret; stderr token=super-secret`)
	got := SafeDiagnosticError(err)

	for _, leaked := range []string{
		`C:\Users\Admin\feed-data\repo`,
		"user-secret",
		"pass-secret",
		"query-secret",
		"super-secret",
	} {
		if strings.Contains(got, leaked) {
			t.Fatalf("SafeDiagnosticError leaked %q in %q", leaked, got)
		}
	}
	for _, want := range []string{"(redacted-path)", "https://example.test/...", "token=[redacted]"} {
		if !strings.Contains(got, want) {
			t.Fatalf("SafeDiagnosticError missing %q in %q", want, got)
		}
	}
}

func TestSafeDiagnosticErrorReturnsEmptyForNil(t *testing.T) {
	t.Parallel()

	if got := SafeDiagnosticError(nil); got != "" {
		t.Fatalf("SafeDiagnosticError(nil) = %q, want empty diagnostic", got)
	}
}

func TestSafeDiagnosticMessageHandlesRenderedValuesDirectly(t *testing.T) {
	t.Parallel()

	t.Run("short message", func(t *testing.T) {
		if got, want := SafeDiagnosticMessage("  upstream rejected request  "), "upstream rejected request"; got != want {
			t.Fatalf("SafeDiagnosticMessage(short) = %q, want %q", got, want)
		}
	})

	t.Run("redacted exact byte bound", func(t *testing.T) {
		const secret = "f271-rendered-secret" // #nosec G101 -- fake secret the test proves is redacted.
		raw := "sync failed password=" + secret + " " + strings.Repeat("x", maxFeedDiagnosticBytes*2)
		got := SafeDiagnosticMessage(raw)
		if len(got) != maxFeedDiagnosticBytes {
			t.Fatalf("SafeDiagnosticMessage(long) length = %d, want exactly %d bytes", len(got), maxFeedDiagnosticBytes)
		}
		if strings.Contains(got, secret) || !strings.Contains(got, "password=[redacted]") {
			t.Fatalf("SafeDiagnosticMessage(long) redaction = %q", got)
		}
		if !strings.HasSuffix(got, "...[truncated]") {
			t.Fatalf("SafeDiagnosticMessage(long) suffix = %q, want truncation marker", got[len(got)-32:])
		}
	})
}
