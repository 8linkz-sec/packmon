package main

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/domain"
)

// TestCachedPackageUpdateLookupReleasesInflightEntryOnResolverPanic covers the
// three single-flight caches: a resolver panic must not leave the in-flight
// entry behind, or every later caller for the same key waits forever on an
// uncanceled context.
func TestCachedPackageUpdateLookupReleasesInflightEntryOnResolverPanic(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// call performs one lookup for a fixed key and reports whether it
		// returned the resolver's non-panicking result.
		call func(packageUpdateLookup) bool
		// resolver panics on its first call and succeeds afterwards.
		resolver func(*atomic.Int32) packageUpdateResolver
	}{
		{
			name: "latest version",
			call: func(lookup packageUpdateLookup) bool {
				return lookup.fetchLatest(context.Background(), domain.EcosystemNPM, "pkg") == "2.0.0"
			},
			resolver: func(calls *atomic.Int32) packageUpdateResolver {
				return packageUpdateResolver{fetchLatest: func(context.Context, domain.Ecosystem, string) string {
					if calls.Add(1) == 1 {
						panic("latest resolver bug")
					}
					return "2.0.0"
				}}
			},
		},
		{
			name: "npm metadata",
			call: func(lookup packageUpdateLookup) bool {
				_, ok := lookup.fetchNPMMetadata(context.Background(), "pkg")
				return ok
			},
			resolver: func(calls *atomic.Int32) packageUpdateResolver {
				return packageUpdateResolver{fetchNPMMetadata: func(context.Context, string) (npmRegistryMetadata, bool) {
					if calls.Add(1) == 1 {
						panic("npm metadata resolver bug")
					}
					return npmRegistryMetadata{}, true
				}}
			},
		},
		{
			name: "git tag commit",
			call: func(lookup packageUpdateLookup) bool {
				_, ok := lookup.gitRemoteTagCommit(context.Background(), "https://example.test/repo.git", "v1.0.0")
				return ok
			},
			resolver: func(calls *atomic.Int32) packageUpdateResolver {
				return packageUpdateResolver{gitRemoteTagCommit: func(context.Context, string, string) (string, bool) {
					if calls.Add(1) == 1 {
						panic("tag commit resolver bug")
					}
					return "1111111111111111111111111111111111111111", true
				}}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var calls atomic.Int32
			lookup := newCachedPackageUpdateLookupWithResolver(tt.resolver(&calls))

			panicked := func() (recovered bool) {
				defer func() { recovered = recover() != nil }()
				tt.call(lookup)
				return false
			}()
			if !panicked {
				t.Fatal("resolver panic did not propagate to the caller")
			}

			done := make(chan bool, 1)
			go func() { done <- tt.call(lookup) }()
			select {
			case ok := <-done:
				if !ok {
					t.Fatal("lookup after a recovered resolver panic did not retry the resolver")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("lookup for the same key blocked on the in-flight entry left by a resolver panic")
			}
			if got := calls.Load(); got != 2 {
				t.Fatalf("resolver calls = %d, want 2 (panic is not cached)", got)
			}
		})
	}
}
