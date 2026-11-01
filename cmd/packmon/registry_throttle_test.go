package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// throttleRecorder swaps in a registryThrottle with a fake clock so tests can
// observe the spacing decisions without spending real wall-clock time.
func throttleRecorder(t *testing.T, interval time.Duration) *[]time.Duration {
	t.Helper()

	clock := time.Unix(0, 0).UTC()
	slept := make([]time.Duration, 0, 4)

	original := registryRequestThrottle
	t.Cleanup(func() { registryRequestThrottle = original })

	registryRequestThrottle = &registryThrottle{
		interval: interval,
		now:      func() time.Time { return clock },
		sleep: func(_ context.Context, d time.Duration) bool {
			slept = append(slept, d)
			clock = clock.Add(d)
			return true
		},
	}
	return &slept
}

// TestNPMLatestLookupIsThrottled covers the gap that made a single --list-all
// run trip npm's abuse throttle: only crates.io requests were spaced, so npm
// received the full request burst. Removing the throttle call from the shared
// registry helper makes this test record zero delays.
func TestNPMLatestLookupIsThrottled(t *testing.T) {
	slept := throttleRecorder(t, 100*time.Millisecond)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"version":"1.2.3"}`))
	}))
	defer server.Close()

	for _, name := range []string{"alpha", "beta", "gamma"} {
		if got := fetchNPMLatestFromBase(context.Background(), server.URL, name); got != "1.2.3" {
			t.Fatalf("fetchNPMLatestFromBase(%q) = %q, want 1.2.3", name, got)
		}
	}

	want := []time.Duration{100 * time.Millisecond, 100 * time.Millisecond}
	if len(*slept) != len(want) {
		t.Fatalf("recorded delays = %v, want %v (npm requests must be spaced)", *slept, want)
	}
	for i, d := range want {
		if (*slept)[i] != d {
			t.Fatalf("delay[%d] = %v, want %v (all: %v)", i, (*slept)[i], d, *slept)
		}
	}
}

// TestNPMMetadataLookupIsThrottled pins the heavier of the two npm calls. The
// packument fetch runs once per package and once per parent, so leaving it
// unthrottled would still produce the request burst.
func TestNPMMetadataLookupIsThrottled(t *testing.T) {
	slept := throttleRecorder(t, 50*time.Millisecond)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"versions":{"1.0.0":{"version":"1.0.0"}}}`))
	}))
	defer server.Close()

	for _, name := range []string{"alpha", "beta"} {
		if _, ok := fetchNPMMetadataFromBase(context.Background(), server.URL, name); !ok {
			t.Fatalf("fetchNPMMetadataFromBase(%q) failed", name)
		}
	}

	if len(*slept) != 1 || (*slept)[0] != 50*time.Millisecond {
		t.Fatalf("recorded delays = %v, want one 50ms delay between the two packument requests", *slept)
	}
}

// TestRegistryRequestsIdentifyPackmon covers the second half of the throttling
// problem: an anonymous Go-http-client is throttled harder than an identified
// one, and every server-side feed syncer already sends an identifying
// User-Agent. Only crates.io did so on the CLI side.
func TestRegistryRequestsIdentifyPackmon(t *testing.T) {
	var got string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("User-Agent")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"version":"1.0.0"}`))
	}))
	defer server.Close()

	if v := fetchNPMLatestFromBase(context.Background(), server.URL, "alpha"); v != "1.0.0" {
		t.Fatalf("lookup = %q, want 1.0.0", v)
	}
	if !strings.HasPrefix(got, "packmon/") {
		t.Fatalf("User-Agent = %q, want a packmon/... identifier", got)
	}
}

// TestExplicitUserAgentWins keeps the crates.io policy header intact: a caller
// that sets its own User-Agent must not have it replaced by the default.
func TestExplicitUserAgentWins(t *testing.T) {
	var got string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("User-Agent")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	headers := http.Header{}
	headers.Set("User-Agent", "custom-agent/9.9")
	if _, err := registryGetLimitedWithHeaders(context.Background(), server.URL, maxRegistryResponseSize, headers); err != nil {
		t.Fatalf("request: %v", err)
	}
	if got != "custom-agent/9.9" {
		t.Fatalf("User-Agent = %q, want the caller's explicit value", got)
	}
}

// TestRegistryRequestThrottleHasNonZeroDefaultInterval guards the default. A
// zero interval would make the limiter inert and silently reintroduce the
// unthrottled burst.
func TestRegistryRequestThrottleHasNonZeroDefaultInterval(t *testing.T) {
	if registryRequestThrottle == nil {
		t.Fatal("registryRequestThrottle must be configured")
	}
	if registryRequestThrottle.interval <= 0 {
		t.Fatalf("default registry throttle interval = %v, want a positive delay", registryRequestThrottle.interval)
	}
}

// TestThrottledRegistryRequestHonoursCancellation proves a cancelled scan stops
// waiting instead of sleeping through the remaining request budget.
func TestThrottledRegistryRequestHonoursCancellation(t *testing.T) {
	original := registryRequestThrottle
	t.Cleanup(func() { registryRequestThrottle = original })
	registryRequestThrottle = &registryThrottle{
		interval: time.Hour,
		now:      time.Now,
		sleep:    func(_ context.Context, _ time.Duration) bool { return false },
	}

	var hits int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"version":"1.0.0"}`))
	}))
	defer server.Close()

	// The first call primes the throttle and is expected to reach the server.
	if got := fetchNPMLatestFromBase(context.Background(), server.URL, "alpha"); got != "1.0.0" {
		t.Fatalf("primed lookup = %q, want 1.0.0", got)
	}
	// The second has to wait, and the aborted wait must stop the request.
	if got := fetchNPMLatestFromBase(context.Background(), server.URL, "beta"); got != "" {
		t.Fatalf("lookup after an aborted throttle wait = %q, want empty", got)
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("registry received %d requests, want 1 (the aborted wait must not issue one)", got)
	}
}

// TestRegistryPerRequestTimeoutStartsAfterThrottleWait pins the order of the
// two bounds: --timeout limits one registry request, so queueing behind the
// shared rate limiter must not use it up. With a small timeout and heavy
// contention the request used to expire before it was sent and the row ended
// up unknown without any warning.
func TestRegistryPerRequestTimeoutStartsAfterThrottleWait(t *testing.T) {
	original := registryRequestThrottle
	t.Cleanup(func() { registryRequestThrottle = original })
	registryRequestThrottle = &registryThrottle{
		interval: time.Hour,
		last:     time.Now(),
		now:      time.Now,
		// A queue position that outlasts the 1s per-request timeout.
		sleep: func(ctx context.Context, _ time.Duration) bool {
			return sleepWithContext(ctx, 1500*time.Millisecond)
		},
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"version":"1.0.0"}`))
	}))
	defer server.Close()

	ctx, phase := withRegistryLookupPhase(context.Background(), 1)
	data, err := registryGet(ctx, server.URL)
	if err != nil {
		t.Fatalf("registryGet() after a long throttle wait error = %v, want the request to be sent", err)
	}
	if string(data) != `{"version":"1.0.0"}` {
		t.Fatalf("registryGet() = %q", data)
	}
	if got := phase.refusedCount(); got != 0 {
		t.Fatalf("refusedCount() = %d, want 0", got)
	}
}

// TestRegistryThrottleWaitAbortIsVisible covers a throttle wait that ends
// without a user cancellation, here a caller deadline that expires while the
// request is still queued: the lookup gets no answer, so it must reach the
// refused total behind the stderr warning and the list-all hint. Nothing was
// sent, so it says nothing about reachability and must not advance the
// breaker streak. A cancelled phase (Ctrl-C) stays silent.
func TestRegistryThrottleWaitAbortIsVisible(t *testing.T) {
	original := registryRequestThrottle
	t.Cleanup(func() { registryRequestThrottle = original })
	registryRequestThrottle = &registryThrottle{
		interval: time.Hour,
		last:     time.Now(),
		now:      time.Now,
		sleep:    sleepWithContext,
	}
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	phaseCtx, phase := withRegistryLookupPhase(context.Background(), 30)
	deadlineCtx, cancelDeadline := context.WithTimeout(phaseCtx, 50*time.Millisecond)
	defer cancelDeadline()
	if _, err := registryGet(deadlineCtx, server.URL); err == nil {
		t.Fatal("registryGet() whose deadline expired in the throttle queue returned no error")
	}
	if got := phase.refusedCount(); got != 1 {
		t.Fatalf("refusedCount() = %d, want 1 (an expired queued request got no answer)", got)
	}
	if got := phase.consecutive.Load(); got != 0 {
		t.Fatalf("consecutive failures = %d, want 0 (nothing was sent)", got)
	}

	canceledCtx, cancel := context.WithCancel(phaseCtx)
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	if _, err := registryGet(canceledCtx, server.URL); err == nil {
		t.Fatal("registryGet() cancelled in the throttle queue returned no error")
	}
	if got := phase.refusedCount(); got != 1 {
		t.Fatalf("refusedCount() after a cancellation = %d, want 1 (a cancelled phase is no refusal)", got)
	}
	if got := hits.Load(); got != 0 {
		t.Fatalf("registry received %d requests, want 0", got)
	}
}

// TestCratesIOThrottleWaitAbortIsVisible keeps the dedicated crates.io queue
// consistent with the shared one: an expired queued lookup is a refusal.
func TestCratesIOThrottleWaitAbortIsVisible(t *testing.T) {
	originalShared, originalCrates := registryRequestThrottle, cratesIOThrottle
	t.Cleanup(func() {
		registryRequestThrottle = originalShared
		cratesIOThrottle = originalCrates
	})
	registryRequestThrottle = &registryThrottle{}
	cratesIOThrottle = &registryThrottle{
		interval: time.Hour,
		last:     time.Now(),
		now:      time.Now,
		sleep:    sleepWithContext,
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"crate":{"max_stable_version":"1.0.0"}}`))
	}))
	defer server.Close()

	phaseCtx, phase := withRegistryLookupPhase(context.Background(), 30)
	ctx, cancel := context.WithTimeout(phaseCtx, 50*time.Millisecond)
	defer cancel()
	if got := fetchCratesLatestFromBase(ctx, server.URL, "serde"); got != "" {
		t.Fatalf("fetchCratesLatestFromBase() = %q, want empty after an expired queue wait", got)
	}
	if got := phase.refusedCount(); got != 1 {
		t.Fatalf("refusedCount() = %d, want 1", got)
	}
}
