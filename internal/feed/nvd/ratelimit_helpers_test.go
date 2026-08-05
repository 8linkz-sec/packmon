package nvd

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// TestNoteWindowElapsedResetsTheBudget covers the accounting fix applied after a
// 429 forces a Retry-After pause. The caller has already waited out a full
// window outside the limiter, so without this the limiter would believe its
// budget is still spent and add a second full window on the next request --
// doubling the delay of an already rate-limited sync.
func TestNoteWindowElapsedResetsTheBudget(t *testing.T) {
	t.Parallel()

	limiter := &nvdRequestRateLimiter{sent: 5}
	limiter.noteWindowElapsed()

	if limiter.sent != 0 {
		t.Fatalf("sent = %d after noteWindowElapsed, want the budget reset", limiter.sent)
	}

	// Calling it again on an already-reset limiter must stay a no-op.
	limiter.noteWindowElapsed()
	if limiter.sent != 0 {
		t.Fatalf("sent = %d on a second call, want 0", limiter.sent)
	}
}

// TestRateLimitRetryWaitErrorStaysTransparent covers the wrapper used when a
// context is cancelled while waiting out an NVD rate limit. It has to name the
// situation for the operator while remaining matchable by errors.Is, so the
// caller can still tell a cancelled sync apart from a failed one.
func TestRateLimitRetryWaitErrorStaysTransparent(t *testing.T) {
	t.Parallel()

	wrapped := &rateLimitRetryWaitError{err: context.Canceled}

	message := wrapped.Error()
	if !strings.Contains(message, "rate limit") {
		t.Errorf("Error() = %q, want it to name the rate limit wait", message)
	}
	if !errors.Is(wrapped, context.Canceled) {
		t.Error("errors.Is could not see through rateLimitRetryWaitError")
	}
	if got := wrapped.Unwrap(); !errors.Is(got, context.Canceled) {
		t.Errorf("Unwrap() = %v, want the wrapped cause", got)
	}
}

// TestNVDOperationErrorCollectorSummarisesWithoutFlooding covers the error
// aggregation across a batch of CVE lookups. A sync over thousands of CVEs must
// report that failures happened and show a few examples, not join thousands of
// errors into one unreadable log line.
func TestNVDOperationErrorCollectorSummarisesWithoutFlooding(t *testing.T) {
	t.Parallel()

	var collector nvdOperationErrorCollector
	if err := collector.err(); err != nil {
		t.Fatalf("err() on an empty collector = %v, want nil", err)
	}

	for i := range maxOperationErrorSamples + 5 {
		collector.add(errors.New("lookup failed " + string(rune('a'+i%26))))
	}

	err := collector.err()
	if err == nil {
		t.Fatal("err() = nil after recording failures")
	}
	if len(collector.samples) != maxOperationErrorSamples {
		t.Fatalf("collector kept %d samples, want it capped at %d",
			len(collector.samples), maxOperationErrorSamples)
	}
	if !strings.Contains(err.Error(), "showing first") {
		t.Errorf("error = %v, want it to say the sample list is truncated", err)
	}
}

// TestNVDOperationErrorCollectorReportsTheExactCountWhenNotTruncated covers the
// other message form, where every failure fits in the sample list.
func TestNVDOperationErrorCollectorReportsTheExactCountWhenNotTruncated(t *testing.T) {
	t.Parallel()

	var collector nvdOperationErrorCollector
	first := errors.New("first failure")
	collector.add(first)
	collector.add(errors.New("second failure"))

	err := collector.err()
	if err == nil {
		t.Fatal("err() = nil after recording failures")
	}
	if strings.Contains(err.Error(), "showing first") {
		t.Errorf("error = %v, want no truncation notice for a short list", err)
	}
	if !errors.Is(err, first) {
		t.Error("the joined error no longer matches its first cause")
	}
}

// TestNVDOperationErrorCollectorFlagsRateLimiting covers the flag that decides
// whether a failed run may be retried immediately. Retrying straight into an
// active 429 would deepen the rate limit rather than recover from it.
func TestNVDOperationErrorCollectorFlagsRateLimiting(t *testing.T) {
	t.Parallel()

	var ordinary nvdOperationErrorCollector
	ordinary.add(errors.New("connection reset"))
	if ordinary.rateLimited {
		t.Error("an ordinary failure was classified as rate limiting")
	}

	var limited nvdOperationErrorCollector
	limited.add(errors.New("connection reset"))
	limited.add(&rateLimitError{})
	if !limited.rateLimited {
		t.Error("a rate-limit failure was not flagged")
	}
}
