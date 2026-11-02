package main

import (
	"bufio"
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/domain"
)

const f050TestTimeout = 2 * time.Second

type f050LookupResult struct {
	value string
	ok    bool
}

type f050ObservingContext struct {
	context.Context
	observed chan struct{}
	once     sync.Once
}

func (c *f050ObservingContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.observed) })
	return c.Context.Done()
}

func f050AwaitSignal(t *testing.T, signal <-chan struct{}, description string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(f050TestTimeout):
		t.Fatalf("timed out waiting for %s", description)
	}
}

func f050AwaitResult(t *testing.T, result <-chan f050LookupResult, description string) f050LookupResult {
	t.Helper()
	select {
	case got := <-result:
		return got
	case <-time.After(f050TestTimeout):
		t.Fatalf("timed out waiting for %s", description)
		return f050LookupResult{}
	}
}

func f050AssertFailedLookup(t *testing.T, got f050LookupResult) {
	t.Helper()
	if got.value != "" || got.ok {
		t.Fatalf("lookup result = %+v, want an empty failed result", got)
	}
}

func TestCachedPackageUpdateLookupSharesInflightFailures(t *testing.T) {
	tests := []struct {
		name     string
		resolver func(*atomic.Int32, chan<- struct{}, <-chan struct{}) packageUpdateResolver
		call     func(context.Context, packageUpdateLookup) f050LookupResult
	}{
		{
			name: "latest version",
			resolver: func(calls *atomic.Int32, started chan<- struct{}, release <-chan struct{}) packageUpdateResolver {
				return packageUpdateResolver{fetchLatest: func(context.Context, domain.Ecosystem, string) string {
					calls.Add(1)
					started <- struct{}{}
					<-release
					return ""
				}}
			},
			call: func(ctx context.Context, lookup packageUpdateLookup) f050LookupResult {
				return f050LookupResult{value: lookup.fetchLatest(ctx, domain.EcosystemNPM, "shared")}
			},
		},
		{
			name: "npm metadata",
			resolver: func(calls *atomic.Int32, started chan<- struct{}, release <-chan struct{}) packageUpdateResolver {
				return packageUpdateResolver{fetchNPMMetadata: func(context.Context, string) (npmRegistryMetadata, bool) {
					calls.Add(1)
					started <- struct{}{}
					<-release
					return npmRegistryMetadata{}, false
				}}
			},
			call: func(ctx context.Context, lookup packageUpdateLookup) f050LookupResult {
				_, ok := lookup.fetchNPMMetadata(ctx, "shared")
				return f050LookupResult{ok: ok}
			},
		},
		{
			name: "git tag commit",
			resolver: func(calls *atomic.Int32, started chan<- struct{}, release <-chan struct{}) packageUpdateResolver {
				return packageUpdateResolver{gitRemoteTagCommit: func(context.Context, string, string) (string, bool) {
					calls.Add(1)
					started <- struct{}{}
					<-release
					return "", false
				}}
			},
			call: func(ctx context.Context, lookup packageUpdateLookup) f050LookupResult {
				value, ok := lookup.gitRemoteTagCommit(ctx, "https://example.test/shared.git", "v1.0.0")
				return f050LookupResult{value: value, ok: ok}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var calls atomic.Int32
			started := make(chan struct{}, 1)
			release := make(chan struct{})
			var releaseOnce sync.Once
			t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
			lookup := newCachedPackageUpdateLookupWithResolver(tt.resolver(&calls, started, release))

			leader := make(chan f050LookupResult, 1)
			go func() { leader <- tt.call(context.Background(), lookup) }()
			f050AwaitSignal(t, started, "the leading resolver call")

			waiterObserved := make(chan struct{})
			waiterContext := &f050ObservingContext{Context: context.Background(), observed: waiterObserved}
			waiter := make(chan f050LookupResult, 1)
			go func() { waiter <- tt.call(waiterContext, lookup) }()
			f050AwaitSignal(t, waiterObserved, "the waiter to enter the in-flight select")

			releaseOnce.Do(func() { close(release) })
			f050AssertFailedLookup(t, f050AwaitResult(t, leader, "the leader result"))
			f050AssertFailedLookup(t, f050AwaitResult(t, waiter, "the waiter result"))
			f050AssertFailedLookup(t, tt.call(context.Background(), lookup))
			if got := calls.Load(); got != 1 {
				t.Fatalf("resolver calls = %d, want 1 for a cached failed result", got)
			}
		})
	}
}

func TestCachedPackageUpdateLookupWaitersHonorCancellation(t *testing.T) {
	tests := []struct {
		name     string
		resolver func(*atomic.Int32, chan<- struct{}, <-chan struct{}) packageUpdateResolver
		call     func(context.Context, packageUpdateLookup) f050LookupResult
	}{
		{
			name: "latest version",
			resolver: func(calls *atomic.Int32, started chan<- struct{}, release <-chan struct{}) packageUpdateResolver {
				return packageUpdateResolver{fetchLatest: func(context.Context, domain.Ecosystem, string) string {
					calls.Add(1)
					started <- struct{}{}
					<-release
					return "2.0.0"
				}}
			},
			call: func(ctx context.Context, lookup packageUpdateLookup) f050LookupResult {
				return f050LookupResult{value: lookup.fetchLatest(ctx, domain.EcosystemNPM, "cancelled")}
			},
		},
		{
			name: "npm metadata",
			resolver: func(calls *atomic.Int32, started chan<- struct{}, release <-chan struct{}) packageUpdateResolver {
				return packageUpdateResolver{fetchNPMMetadata: func(context.Context, string) (npmRegistryMetadata, bool) {
					calls.Add(1)
					started <- struct{}{}
					<-release
					return npmRegistryMetadata{}, true
				}}
			},
			call: func(ctx context.Context, lookup packageUpdateLookup) f050LookupResult {
				_, ok := lookup.fetchNPMMetadata(ctx, "cancelled")
				return f050LookupResult{ok: ok}
			},
		},
		{
			name: "git tag commit",
			resolver: func(calls *atomic.Int32, started chan<- struct{}, release <-chan struct{}) packageUpdateResolver {
				return packageUpdateResolver{gitRemoteTagCommit: func(context.Context, string, string) (string, bool) {
					calls.Add(1)
					started <- struct{}{}
					<-release
					return "1111111111111111111111111111111111111111", true
				}}
			},
			call: func(ctx context.Context, lookup packageUpdateLookup) f050LookupResult {
				value, ok := lookup.gitRemoteTagCommit(ctx, "https://example.test/cancelled.git", "v1.0.0")
				return f050LookupResult{value: value, ok: ok}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var calls atomic.Int32
			started := make(chan struct{}, 1)
			release := make(chan struct{})
			var releaseOnce sync.Once
			t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
			lookup := newCachedPackageUpdateLookupWithResolver(tt.resolver(&calls, started, release))

			leader := make(chan f050LookupResult, 1)
			go func() { leader <- tt.call(context.Background(), lookup) }()
			f050AwaitSignal(t, started, "the leading resolver call")

			waiterBase, cancelWaiter := context.WithCancel(context.Background())
			t.Cleanup(cancelWaiter)
			waiterObserved := make(chan struct{})
			waiterContext := &f050ObservingContext{Context: waiterBase, observed: waiterObserved}
			waiter := make(chan f050LookupResult, 1)
			go func() { waiter <- tt.call(waiterContext, lookup) }()
			f050AwaitSignal(t, waiterObserved, "the waiter to enter the in-flight select")
			cancelWaiter()
			f050AssertFailedLookup(t, f050AwaitResult(t, waiter, "the cancelled waiter result"))

			select {
			case got := <-leader:
				t.Fatalf("leader completed before release with %+v", got)
			default:
			}
			if got := calls.Load(); got != 1 {
				t.Fatalf("resolver calls = %d, want 1 while the leader is active", got)
			}

			releaseOnce.Do(func() { close(release) })
			_ = f050AwaitResult(t, leader, "the released leader result")
		})
	}
}

func TestCachedPackageUpdateLookupBoundsDuplicateWorkerPoolJobs(t *testing.T) {
	t.Run("duplicate keys", func(t *testing.T) {
		items := make([]string, maxConcurrentRegistryRequests*3)
		for i := range items {
			items[i] = "shared"
		}
		var calls atomic.Int32
		resolverStarted := make(chan struct{}, 1)
		release := make(chan struct{})
		var releaseOnce sync.Once
		t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
		lookup := newCachedPackageUpdateLookupWithResolver(packageUpdateResolver{
			fetchLatest: func(context.Context, domain.Ecosystem, string) string {
				calls.Add(1)
				resolverStarted <- struct{}{}
				<-release
				return "2.0.0"
			},
		})

		var workerStarts atomic.Int32
		workerPoolSaturated := make(chan struct{})
		var workerPoolOnce sync.Once
		done := make(chan []packageLatestStatus, 1)
		go func() {
			done <- resolveLatestWithWorkerPool(context.Background(), items, func(ctx context.Context, name string) packageLatestStatus {
				if workerStarts.Add(1) == maxConcurrentRegistryRequests {
					workerPoolOnce.Do(func() { close(workerPoolSaturated) })
				}
				return packageLatestStatus{Latest: lookup.fetchLatest(ctx, domain.EcosystemNPM, name), Update: "yes"}
			})
		}()

		f050AwaitSignal(t, resolverStarted, "the one resolver call")
		f050AwaitSignal(t, workerPoolSaturated, "the bounded worker pool to start")
		releaseOnce.Do(func() { close(release) })

		var results []packageLatestStatus
		select {
		case results = <-done:
		case <-time.After(f050TestTimeout):
			t.Fatal("duplicate-key worker pool did not finish")
		}
		if len(results) != len(items) {
			t.Fatalf("results = %d, want %d", len(results), len(items))
		}
		for i, got := range results {
			if got != (packageLatestStatus{Latest: "2.0.0", Update: "yes"}) {
				t.Fatalf("result[%d] = %+v, want the shared resolved status", i, got)
			}
		}
		if got := calls.Load(); got != 1 {
			t.Fatalf("resolver calls = %d, want 1 for duplicate keys", got)
		}
	})

	t.Run("empty input", func(t *testing.T) {
		var calls atomic.Int32
		results := resolveLatestWithWorkerPool(context.Background(), []string(nil), func(context.Context, string) packageLatestStatus {
			calls.Add(1)
			return packageLatestStatus{}
		})
		if len(results) != 0 {
			t.Fatalf("empty results = %+v, want no results", results)
		}
		if got := calls.Load(); got != 0 {
			t.Fatalf("empty input resolver calls = %d, want 0", got)
		}
	})
}

func TestResolveNPMWantedVersionFallbackContracts(t *testing.T) {
	parent := domain.PackageParent{Name: "parent", Version: "1.0.0", Ecosystem: domain.EcosystemNPM}
	parentMetadata := npmRegistryMetadata{Versions: map[string]npmVersionManifest{
		"1.0.0": {Dependencies: map[string]string{"child": ">=1.0.0 <3.0.0"}},
	}}

	tests := []struct {
		name      string
		installed string
		latest    string
		parents   []domain.PackageParent
		metadata  map[string]npmMetadataCacheEntry
		want      string
	}{
		{
			name:    "no usable parent ranges uses registry latest",
			latest:  "9.0.0",
			parents: []domain.PackageParent{{Name: "other", Version: "1.0.0", Ecosystem: domain.EcosystemPyPI}},
			want:    "9.0.0",
		},
		{
			name:    "missing child metadata uses registry latest",
			latest:  "9.0.0",
			parents: []domain.PackageParent{parent},
			metadata: map[string]npmMetadataCacheEntry{
				"parent": {value: parentMetadata, ok: true},
				"child":  {ok: false},
			},
			want: "9.0.0",
		},
		{
			name:    "empty child metadata uses registry latest",
			latest:  "9.0.0",
			parents: []domain.PackageParent{parent},
			metadata: map[string]npmMetadataCacheEntry{
				"parent": {value: parentMetadata, ok: true},
				"child":  {value: npmRegistryMetadata{}, ok: true},
			},
			want: "9.0.0",
		},
		{
			name:    "unsatisfiable ranges use registry latest",
			latest:  "9.0.0",
			parents: []domain.PackageParent{parent},
			metadata: map[string]npmMetadataCacheEntry{
				"parent": {value: parentMetadata, ok: true},
				"child": {value: npmRegistryMetadata{Versions: map[string]npmVersionManifest{
					"3.0.0": {Version: "3.0.0"},
				}}, ok: true},
			},
			want: "9.0.0",
		},
		{
			name:      "older highest allowed version does not downgrade",
			installed: "2.5.0",
			latest:    "9.0.0",
			parents:   []domain.PackageParent{parent},
			metadata: map[string]npmMetadataCacheEntry{
				"parent": {value: parentMetadata, ok: true},
				"child": {value: npmRegistryMetadata{Versions: map[string]npmVersionManifest{
					"1.5.0": {Version: "1.5.0"},
					"2.0.0": {Version: "2.0.0"},
				}}, ok: true},
			},
			want: "2.5.0",
		},
		{
			name:      "valid intersection selects highest satisfying version",
			installed: "1.0.0",
			latest:    "9.0.0",
			parents: []domain.PackageParent{
				parent,
				{Name: "second-parent", Version: "2.0.0", Ecosystem: domain.EcosystemNPM},
			},
			metadata: map[string]npmMetadataCacheEntry{
				"parent": {value: parentMetadata, ok: true},
				"second-parent": {value: npmRegistryMetadata{Versions: map[string]npmVersionManifest{
					"2.0.0": {Dependencies: map[string]string{"child": "^2.0.0"}},
				}}, ok: true},
				"child": {value: npmRegistryMetadata{Versions: map[string]npmVersionManifest{
					"1.9.0": {Version: "1.9.0"},
					"2.1.0": {Version: "2.1.0"},
					"2.8.0": {Version: "2.8.0"},
					"3.0.0": {Version: "3.0.0"},
				}}, ok: true},
			},
			want: "2.8.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lookup := packageUpdateLookup{fetchNPMMetadata: func(_ context.Context, name string) (npmRegistryMetadata, bool) {
				entry, ok := tt.metadata[name]
				if !ok {
					return npmRegistryMetadata{}, false
				}
				return entry.value, entry.ok
			}}
			if got := resolveNPMWantedVersionWithLookup(context.Background(), "child", tt.installed, tt.latest, tt.parents, lookup); got != tt.want {
				t.Fatalf("resolveNPMWantedVersionWithLookup() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNPMParentDependencyRangesSkipIncompleteAndDuplicateParents(t *testing.T) {
	parents := []domain.PackageParent{
		{Name: "foreign", Version: "1.0.0", Ecosystem: domain.EcosystemPyPI},
		{Name: " ", Version: "1.0.0", Ecosystem: domain.EcosystemNPM},
		{Name: "blank-version", Version: " ", Ecosystem: domain.EcosystemNPM},
		{Name: "failed", Version: "1.0.0", Ecosystem: domain.EcosystemNPM},
		{Name: "missing-version", Version: "1.0.0", Ecosystem: domain.EcosystemNPM},
		{Name: "no-child", Version: "1.0.0", Ecosystem: domain.EcosystemNPM},
		{Name: "dependency", Version: "1.0.0", Ecosystem: domain.EcosystemNPM},
		{Name: "optional", Version: "1.0.0", Ecosystem: domain.EcosystemNPM},
		{Name: "peer", Version: "1.0.0", Ecosystem: domain.EcosystemNPM},
		{Name: "duplicate", Version: "1.0.0", Ecosystem: domain.EcosystemNPM},
	}
	metadata := map[string]npmMetadataCacheEntry{
		"missing-version": {value: npmRegistryMetadata{Versions: map[string]npmVersionManifest{"2.0.0": {}}}, ok: true},
		"no-child": {value: npmRegistryMetadata{Versions: map[string]npmVersionManifest{
			"1.0.0": {Dependencies: map[string]string{"other": "*"}},
		}}, ok: true},
		"dependency": {value: npmRegistryMetadata{Versions: map[string]npmVersionManifest{
			"1.0.0": {Dependencies: map[string]string{"child": "^1.0.0"}},
		}}, ok: true},
		"optional": {value: npmRegistryMetadata{Versions: map[string]npmVersionManifest{
			"1.0.0": {OptionalDependencies: map[string]string{"child": "~2.0.0"}},
		}}, ok: true},
		"peer": {value: npmRegistryMetadata{Versions: map[string]npmVersionManifest{
			"1.0.0": {PeerDependencies: map[string]string{"child": ">=3.0.0"}},
		}}, ok: true},
		"duplicate": {value: npmRegistryMetadata{Versions: map[string]npmVersionManifest{
			"1.0.0": {Dependencies: map[string]string{"child": "^1.0.0"}},
		}}, ok: true},
	}
	lookup := packageUpdateLookup{fetchNPMMetadata: func(_ context.Context, name string) (npmRegistryMetadata, bool) {
		entry, ok := metadata[name]
		if !ok {
			return npmRegistryMetadata{}, false
		}
		return entry.value, entry.ok
	}}

	got := npmParentDependencyRangesWithLookup(context.Background(), "child", parents, lookup)
	want := []string{">=3.0.0", "^1.0.0", "~2.0.0"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("npmParentDependencyRangesWithLookup() = %v, want %v", got, want)
	}
}

func TestFetchMavenLatestFailureAndFallbackContracts(t *testing.T) {
	var requestCount atomic.Int32
	var pathsMu sync.Mutex
	paths := make(map[string]int)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		pathsMu.Lock()
		paths[r.URL.Path]++
		pathsMu.Unlock()

		switch r.URL.Path {
		case "/com/example/non200/maven-metadata.xml":
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
		case "/com/example/malformed/maven-metadata.xml":
			_, _ = w.Write([]byte("<metadata><versioning>"))
		case "/com/example/fallback/maven-metadata.xml":
			_, _ = w.Write([]byte(`<metadata><versioning><versions><version>1.9.0</version><version> 2.1.0 </version><version>2.0.0</version></versions></versioning></metadata>`))
		default:
			t.Errorf("unexpected Maven request path %q", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	if got := fetchMavenLatestFromBase(context.Background(), server.URL, "com..example:invalid"); got != "" {
		t.Fatalf("invalid dotted group result = %q, want empty", got)
	}
	if got := requestCount.Load(); got != 0 {
		t.Fatalf("requests after invalid dotted group = %d, want 0", got)
	}
	if got := fetchMavenLatestFromBase(context.Background(), server.URL, "com.example:non200"); got != "" {
		t.Fatalf("non-200 result = %q, want empty", got)
	}
	if got := fetchMavenLatestFromBase(context.Background(), server.URL, "com.example:malformed"); got != "" {
		t.Fatalf("malformed XML result = %q, want empty", got)
	}
	if got := fetchMavenLatestFromBase(context.Background(), server.URL, "com.example:fallback"); got != "2.1.0" {
		t.Fatalf("versions-only fallback result = %q, want 2.1.0", got)
	}

	wantPaths := map[string]int{
		"/com/example/non200/maven-metadata.xml":    1,
		"/com/example/malformed/maven-metadata.xml": 1,
		"/com/example/fallback/maven-metadata.xml":  1,
	}
	pathsMu.Lock()
	gotPaths := make(map[string]int, len(paths))
	for path, count := range paths {
		gotPaths[path] = count
	}
	pathsMu.Unlock()
	if got := requestCount.Load(); got != 3 {
		t.Fatalf("Maven requests = %d, want 3", got)
	}
	if !reflect.DeepEqual(gotPaths, wantPaths) {
		t.Fatalf("Maven request paths = %v, want %v", gotPaths, wantPaths)
	}
}

func TestGitRemoteScannersRejectOversizedTokens(t *testing.T) {
	original := gitCommandOutput
	t.Cleanup(func() { gitCommandOutput = original })
	var calls atomic.Int32
	oversized := []byte(strings.Repeat("a", bufio.MaxScanTokenSize+1) + " refs/tags/v1.0.0\n")
	gitCommandOutput = func(context.Context, ...string) ([]byte, error) {
		calls.Add(1)
		return oversized, nil
	}

	if tags, err := gitRemoteTags(context.Background(), "https://example.test/repo.git"); err == nil || len(tags) != 0 {
		t.Fatalf("gitRemoteTags() = %v, %v; want no tags and a scanner error", tags, err)
	}
	if commit, ok := gitRemoteTagCommit(context.Background(), "https://example.test/repo.git", "v1.0.0"); ok || commit != "" {
		t.Fatalf("gitRemoteTagCommit() = %q, %v; want empty, false after scanner failure", commit, ok)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("git command calls = %d, want 2", got)
	}
}

func TestUpdateLookupSimpleHelperContracts(t *testing.T) {
	counts := countSlowLookups([]domain.Ecosystem{
		domain.EcosystemNPM,
		domain.EcosystemCargo,
		domain.EcosystemChocolatey,
		domain.EcosystemCargo,
		domain.EcosystemPyPI,
	})
	if counts != (lookupSlowCounts{Cargo: 2, Chocolatey: 1}) {
		t.Fatalf("countSlowLookups() = %+v, want Cargo=2 Chocolatey=1", counts)
	}

	lookup := directPackageUpdateLookup()
	if lookup.fetchLatest == nil || lookup.fetchNPMMetadata == nil || lookup.gitRemoteTagCommit == nil {
		t.Fatalf("directPackageUpdateLookup() left resolver functions unset: %+v", lookup)
	}
}
