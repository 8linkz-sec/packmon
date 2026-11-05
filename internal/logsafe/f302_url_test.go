package logsafe

import "testing"

func TestF302DiagnosticSnippetCountsRunesAfterByteCheck(t *testing.T) {
	t.Parallel()

	if got := diagnosticSnippet("é", 1); got != "é" {
		t.Fatalf("diagnosticSnippet(multibyte rune) = %q, want untruncated rune", got)
	}
}

func TestF302SplitPathSegmentsEmptyPath(t *testing.T) {
	t.Parallel()

	if got := splitPathSegments("///"); got != nil {
		t.Fatalf("splitPathSegments(empty path) = %#v, want nil", got)
	}
}
