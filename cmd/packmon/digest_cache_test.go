package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"github.com/8linkz-sec/packmon/internal/dockerimage"
	"github.com/8linkz-sec/packmon/internal/domain"
)

// countingDigestResolver records how often the registry was actually consulted.
type countingDigestResolver struct {
	mu     sync.Mutex
	calls  int
	digest string
	err    error
	block  chan struct{}
}

func (r *countingDigestResolver) ResolveDigest(context.Context, dockerimage.Ref) (string, error) {
	r.mu.Lock()
	r.calls++
	r.mu.Unlock()
	if r.block != nil {
		<-r.block
	}
	return r.digest, r.err
}

func (r *countingDigestResolver) callCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

// TestCachedDockerDigestLookupResolvesEachReferenceOnce covers the point of the
// cache. A scan lists the same base image many times, and every extra lookup is
// a registry round trip that counts against the rate limit.
func TestCachedDockerDigestLookupResolvesEachReferenceOnce(t *testing.T) {
	t.Parallel()

	resolver := &countingDigestResolver{digest: "sha256:abc"}
	lookup := newCachedDockerDigestLookup(resolver)
	ref := dockerimage.Ref{Registry: "registry-1.docker.io", Repository: "library/alpine", Reference: "3.24"}

	for range 5 {
		digest, err := lookup.ResolveDigest(context.Background(), ref)
		if err != nil {
			t.Fatalf("ResolveDigest: %v", err)
		}
		if digest != "sha256:abc" {
			t.Fatalf("digest = %q, want the resolver's answer", digest)
		}
	}
	if got := resolver.callCount(); got != 1 {
		t.Fatalf("the registry was consulted %d times, want 1", got)
	}
}

// TestCachedDockerDigestLookupCachesFailuresToo pins that a failed lookup is
// remembered as well. Retrying a failing registry once per image would multiply
// the delay across a large scan.
func TestCachedDockerDigestLookupCachesFailuresToo(t *testing.T) {
	t.Parallel()

	lookupErr := errors.New("registry unavailable")
	resolver := &countingDigestResolver{err: lookupErr}
	lookup := newCachedDockerDigestLookup(resolver)
	ref := dockerimage.Ref{Registry: "ghcr.io", Repository: "org/app", Reference: "v1"}

	for range 3 {
		if _, err := lookup.ResolveDigest(context.Background(), ref); !errors.Is(err, lookupErr) {
			t.Fatalf("error = %v, want the resolver failure", err)
		}
	}
	if got := resolver.callCount(); got != 1 {
		t.Fatalf("a failing lookup was retried %d times, want it cached after 1", got)
	}
}

// TestCachedDockerDigestLookupCollapsesConcurrentLookups covers the in-flight
// map. Without it a parallel scan would fire one request per goroutine for the
// same image, which is exactly what triggers registry throttling.
func TestCachedDockerDigestLookupCollapsesConcurrentLookups(t *testing.T) {
	t.Parallel()

	resolver := &countingDigestResolver{digest: "sha256:abc", block: make(chan struct{})}
	lookup := newCachedDockerDigestLookup(resolver)
	ref := dockerimage.Ref{Registry: "quay.io", Repository: "org/app", Reference: "latest"}

	const goroutines = 8
	var started, done sync.WaitGroup
	started.Add(goroutines)
	done.Add(goroutines)
	results := make([]string, goroutines)
	errs := make([]error, goroutines)

	for i := range goroutines {
		go func() {
			defer done.Done()
			started.Done()
			results[i], errs[i] = lookup.ResolveDigest(context.Background(), ref)
		}()
	}
	started.Wait()
	close(resolver.block)
	done.Wait()

	for i := range goroutines {
		if errs[i] != nil {
			t.Fatalf("goroutine %d: %v", i, errs[i])
		}
		if results[i] != "sha256:abc" {
			t.Fatalf("goroutine %d digest = %q, want the shared answer", i, results[i])
		}
	}
	if got := resolver.callCount(); got != 1 {
		t.Fatalf("%d concurrent lookups produced %d registry calls, want 1", goroutines, got)
	}
}

// TestCachedDockerDigestLookupHonoursCancellationWhileWaiting covers the wait on
// an in-flight call. A cancelled scan must not block behind another goroutine's
// registry request.
func TestCachedDockerDigestLookupHonoursCancellationWhileWaiting(t *testing.T) {
	t.Parallel()

	resolver := &countingDigestResolver{digest: "sha256:abc", block: make(chan struct{})}
	lookup := newCachedDockerDigestLookup(resolver)
	ref := dockerimage.Ref{Registry: "quay.io", Repository: "org/app", Reference: "latest"}

	leader := make(chan struct{})
	go func() {
		defer close(leader)
		_, _ = lookup.ResolveDigest(context.Background(), ref)
	}()

	// Wait until the leader is inside the resolver and holds the in-flight slot.
	for resolver.callCount() == 0 {
		runtime.Gosched()
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := lookup.ResolveDigest(ctx, ref); !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}

	close(resolver.block)
	<-leader
}

// TestCachedDockerDigestLookupBypassesTheCacheForIncompleteRefs covers the key
// guard. A reference missing a component cannot be cached without risking a
// collision, so it must go straight to the resolver every time.
func TestCachedDockerDigestLookupBypassesTheCacheForIncompleteRefs(t *testing.T) {
	t.Parallel()

	resolver := &countingDigestResolver{digest: "sha256:abc"}
	lookup := newCachedDockerDigestLookup(resolver)

	incomplete := dockerimage.Ref{Repository: "library/alpine", Reference: "3.24"}
	for range 3 {
		if _, err := lookup.ResolveDigest(context.Background(), incomplete); err != nil {
			t.Fatalf("ResolveDigest: %v", err)
		}
	}
	if got := resolver.callCount(); got != 3 {
		t.Fatalf("an uncacheable ref was resolved %d times, want every call forwarded", got)
	}
}

// TestDockerDigestLookupCacheKeyRequiresEveryComponent pins the key builder. All
// three components identify the image, so a key built from a subset would let
// one image's digest answer for another.
func TestDockerDigestLookupCacheKeyRequiresEveryComponent(t *testing.T) {
	t.Parallel()

	complete := dockerimage.Ref{Registry: "ghcr.io", Repository: "org/app", Reference: "v1"}
	key, ok := dockerDigestLookupCacheKey(complete)
	if !ok {
		t.Fatal("a complete ref produced no cache key")
	}
	if key.registry != "ghcr.io" || key.repository != "org/app" || key.reference != "v1" {
		t.Fatalf("key = %+v, want every component carried over", key)
	}

	for _, ref := range []dockerimage.Ref{
		{Repository: "org/app", Reference: "v1"},
		{Registry: "ghcr.io", Reference: "v1"},
		{Registry: "ghcr.io", Repository: "org/app"},
		{},
	} {
		if _, ok := dockerDigestLookupCacheKey(ref); ok {
			t.Errorf("dockerDigestLookupCacheKey(%+v) reported a usable key", ref)
		}
	}
}

// TestNewCachedDockerDigestLookupSuppliesADefaultResolver covers the nil paths.
// The lookup is constructed from optional config, and a nil resolver must not
// turn into a panic mid-scan.
func TestNewCachedDockerDigestLookupSuppliesADefaultResolver(t *testing.T) {
	t.Parallel()

	lookup := newCachedDockerDigestLookup(nil)
	if lookup == nil || lookup.resolver == nil {
		t.Fatal("newCachedDockerDigestLookup(nil) produced no usable resolver")
	}
}

// TestOverlayCLILogConfigOnlyOverridesSetFields covers the config merge. An
// empty field in the higher-priority layer means "not specified", so overwriting
// with it would discard the value the user configured elsewhere.
func TestOverlayCLILogConfigOnlyOverridesSetFields(t *testing.T) {
	t.Parallel()

	base := cliLogConfig{Level: "info", Format: "text", File: "packmon.log"}

	unchanged := base
	overlayCLILogConfig(&unchanged, cliLogConfig{})
	if unchanged != base {
		t.Fatalf("an empty overlay changed the config: %+v", unchanged)
	}

	partial := base
	overlayCLILogConfig(&partial, cliLogConfig{Level: "debug"})
	if partial.Level != "debug" {
		t.Errorf("Level = %q, want the overlay value", partial.Level)
	}
	if partial.Format != "text" || partial.File != "packmon.log" {
		t.Errorf("config = %+v, want the unspecified fields preserved", partial)
	}

	full := base
	overlayCLILogConfig(&full, cliLogConfig{Level: "warn", Format: "json", File: "other.log"})
	if full != (cliLogConfig{Level: "warn", Format: "json", File: "other.log"}) {
		t.Errorf("config = %+v, want every field overridden", full)
	}
}

// TestWriteJSONFileCreatesTheDirectoryAndAPrivateFile covers the JSON artifact
// writer. Scan results can name packages and repository paths, so the file is
// created with owner-only permissions rather than at the process umask.
func TestWriteJSONFileCreatesTheDirectoryAndAPrivateFile(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "reports", "nested", "scan.json")
	result := &domain.ScanResult{Mode: domain.ScanModeRemote, FeedStatus: "healthy"}

	if err := writeJSONFile(path, result); err != nil {
		t.Fatalf("writeJSONFile: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("output file missing: %v", err)
	}
	if runtime.GOOS != "windows" {
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("permissions = %o, want 0600", perm)
		}
	}

	data, err := os.ReadFile(path) // #nosec G304 -- test-controlled temp path.
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	var decoded domain.ScanResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, data)
	}
	if decoded.Mode != domain.ScanModeRemote {
		t.Errorf("decoded mode = %q, want the scan result round-tripped", decoded.Mode)
	}

	// Overwriting an existing report must not append to it.
	if err := writeJSONFile(path, result); err != nil {
		t.Fatalf("second writeJSONFile: %v", err)
	}
	again, err := os.ReadFile(path) // #nosec G304 -- test-controlled temp path.
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if len(again) != len(data) {
		t.Fatalf("rewritten file is %d bytes, want %d -- the writer appended", len(again), len(data))
	}
}

// TestWriteJSONFileReportsAnUnusableDestination keeps a failed artifact write
// visible instead of leaving the user with a silently missing report.
func TestWriteJSONFileReportsAnUnusableDestination(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("seed blocker: %v", err)
	}

	// A regular file where a directory is needed cannot be created into.
	err := writeJSONFile(filepath.Join(blocker, "scan.json"), &domain.ScanResult{})
	if err == nil {
		t.Fatal("writeJSONFile into a file path = nil, want an error")
	}
}

// TestOutdatedReportEmptyStateClassFlagsUnknowns covers the empty-state styling.
// A report where every package resolved is genuinely clean; one with unknowns is
// not, and must not be presented with the same reassuring styling.
func TestOutdatedReportEmptyStateClassFlagsUnknowns(t *testing.T) {
	t.Parallel()

	if got := (outdatedReport{UpToDate: 12}).EmptyStateClass(); got != "empty" {
		t.Errorf("class without unknowns = %q, want empty", got)
	}
	if got := (outdatedReport{UpToDate: 12, Unknown: 1}).EmptyStateClass(); got != "empty empty-unknown" {
		t.Errorf("class with unknowns = %q, want the unknown variant", got)
	}
}
