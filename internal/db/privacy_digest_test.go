package db

import (
	"strings"
	"testing"
)

// TestPrivacyExportSelectorDigestIsStableAndNonReversible covers the selector
// digest recorded in the audit trail for a privacy export. The whole point is to
// log *which* subject was exported without logging the subject itself, so the
// digest must never contain the raw value and must be reproducible across runs.
func TestPrivacyExportSelectorDigestIsStableAndNonReversible(t *testing.T) {
	t.Parallel()

	selector := PrivacyExportSelector{Type: PrivacySelectorClientIP, Value: "203.0.113.7"}
	digest := selector.Digest()

	if !strings.HasPrefix(digest, "sha256:") {
		t.Fatalf("digest = %q, want it to name its algorithm", digest)
	}
	if strings.Contains(digest, "203.0.113.7") {
		t.Fatalf("digest = %q, want the subject value not to appear", digest)
	}
	if digest != selector.Digest() {
		t.Fatal("the digest is not reproducible for the same selector")
	}
}

// TestPrivacyExportSelectorDigestIgnoresSurroundingWhitespace keeps two spellings
// of the same subject from producing different audit entries.
func TestPrivacyExportSelectorDigestIgnoresSurroundingWhitespace(t *testing.T) {
	t.Parallel()

	plain := PrivacyExportSelector{Type: PrivacySelectorRepoName, Value: "packmon"}
	padded := PrivacyExportSelector{Type: "  " + PrivacySelectorRepoName + "  ", Value: "  packmon  "}

	if plain.Digest() != padded.Digest() {
		t.Fatal("padding changed the selector digest")
	}
}

// TestPrivacyExportSelectorDigestSeparatesTypeFromValue guards the field
// separator. Without it a selector of type "ab"/value "c" and one of type
// "a"/value "bc" would share a digest, so two different subjects would be
// indistinguishable in the audit log.
func TestPrivacyExportSelectorDigestSeparatesTypeFromValue(t *testing.T) {
	t.Parallel()

	first := PrivacyExportSelector{Type: "ab", Value: "c"}
	second := PrivacyExportSelector{Type: "a", Value: "bc"}

	if first.Digest() == second.Digest() {
		t.Fatal("two different selectors collided on the same digest")
	}
}

// TestCanRetryRefreshStatusAllowsOnlySettledJobs covers the guard behind the
// admin retry button. Retrying a job that is still pending or processing would
// duplicate work; refusing a failed one would leave it stuck.
func TestCanRetryRefreshStatusAllowsOnlySettledJobs(t *testing.T) {
	t.Parallel()

	for _, status := range []string{RefreshStatusDone, RefreshStatusError, RefreshStatusPaused} {
		if !CanRetryRefreshStatus(status) {
			t.Errorf("CanRetryRefreshStatus(%q) = false, want it retryable", status)
		}
		// Normalisation applies here too.
		if !CanRetryRefreshStatus("  " + strings.ToUpper(status) + "  ") {
			t.Errorf("CanRetryRefreshStatus(padded %q) = false, want it retryable", status)
		}
	}
	for _, status := range []string{RefreshStatusPending, RefreshStatusProcessing, "", "not-a-status"} {
		if CanRetryRefreshStatus(status) {
			t.Errorf("CanRetryRefreshStatus(%q) = true, want it refused", status)
		}
	}
}

// TestRefreshStatusLabelNamesEveryStatus pins the human-readable label used on
// the admin queue page. An unmapped status would surface as a raw enum token.
func TestRefreshStatusLabelNamesEveryStatus(t *testing.T) {
	t.Parallel()

	for status, want := range map[string]string{
		RefreshStatusPending:    "Pending",
		RefreshStatusProcessing: "Processing",
		RefreshStatusPaused:     "Paused",
		RefreshStatusDone:       "Done",
		RefreshStatusError:      "Error",
	} {
		if got := RefreshStatusLabel(status); got != want {
			t.Errorf("RefreshStatusLabel(%q) = %q, want %q", status, got, want)
		}
		if got := RefreshStatusLabel("  " + strings.ToUpper(status) + "  "); got != want {
			t.Errorf("RefreshStatusLabel(padded %q) = %q, want %q", status, got, want)
		}
	}

	// An unrecognised status is echoed, trimmed, rather than turned into an
	// empty cell that would hide the row's state entirely.
	if got := RefreshStatusLabel("  brand-new  "); got != "brand-new" {
		t.Errorf("RefreshStatusLabel(unknown) = %q, want the trimmed raw value", got)
	}
	if got := RefreshStatusLabel(""); got != "" {
		t.Errorf("RefreshStatusLabel(empty) = %q, want empty", got)
	}
}
