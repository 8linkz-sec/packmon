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
