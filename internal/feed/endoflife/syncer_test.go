package endoflife

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/8linkz/packmon/internal/db"
)

type lifecycleStoreStub struct {
	db.Store
	status          *db.FeedSyncStatus
	statuses        []db.FeedSyncStatus
	products        []db.LifecycleProduct
	reconciledSlugs []string
	reconcileErr    error
}

func (s *lifecycleStoreStub) GetFeedSyncStatus(context.Context, string) (*db.FeedSyncStatus, error) {
	if s.status == nil {
		return nil, nil
	}
	copied := *s.status
	return &copied, nil
}

func (s *lifecycleStoreStub) UpsertFeedSyncStatus(_ context.Context, status *db.FeedSyncStatus) error {
	copied := *status
	s.statuses = append(s.statuses, copied)
	s.status = &copied
	return nil
}

func (s *lifecycleStoreStub) UpsertLifecycleProducts(_ context.Context, products []db.LifecycleProduct) error {
	s.products = append(s.products, products...)
	return nil
}

func (s *lifecycleStoreStub) DeleteLifecycleProductsNotIn(_ context.Context, productSlugs []string) (int, error) {
	s.reconciledSlugs = append([]string(nil), productSlugs...)
	return 0, s.reconcileErr
}

func TestFetchProductsFullSendsHeadersAndParsesResponse(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/products/full" {
			t.Fatalf("path = %q, want /api/v1/products/full", r.URL.Path)
		}
		if got := r.Header.Get("Accept"); got != "application/json" {
			t.Fatalf("Accept = %q, want application/json", got)
		}
		if got := r.Header.Get("User-Agent"); got != "packmon-server" {
			t.Fatalf("User-Agent = %q, want packmon-server", got)
		}
		if got := r.Header.Get("If-None-Match"); got != "old-etag" {
			t.Fatalf("If-None-Match = %q, want old-etag", got)
		}
		w.Header().Set("ETag", "fresh-etag")
		_, _ = w.Write([]byte(sampleProductsResponse()))
	}))
	defer server.Close()

	client := &Client{BaseURL: server.URL + "/api/v1", HTTPClient: server.Client()}
	resp, etag, notModified, err := client.FetchProductsFull(context.Background(), "old-etag")
	if err != nil {
		t.Fatalf("FetchProductsFull() error = %v", err)
	}
	if notModified {
		t.Fatal("FetchProductsFull() notModified = true, want false")
	}
	if etag != "fresh-etag" {
		t.Fatalf("etag = %q, want fresh-etag", etag)
	}
	if resp.SchemaVersion != "1.2.1" || resp.Total != 1 || len(resp.Result) != 1 {
		t.Fatalf("response envelope = %+v", resp)
	}
	release := resp.Result[0].Releases[0]
	if release.Name != "4.2" || release.Latest == nil || release.Latest.Name != "4.2.22" || !release.IsEOAS {
		t.Fatalf("release = %+v", release)
	}
}

func TestFetchProductsFullUsesConfiguredUserAgent(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("User-Agent"); got != "packmon-server/1.2.3" {
			t.Fatalf("User-Agent = %q, want configured value", got)
		}
		_, _ = w.Write([]byte(sampleProductsResponse()))
	}))
	defer server.Close()

	client := &Client{BaseURL: server.URL, UserAgent: "packmon-server/1.2.3", HTTPClient: server.Client()}
	if _, _, _, err := client.FetchProductsFull(context.Background(), ""); err != nil {
		t.Fatalf("FetchProductsFull() error = %v", err)
	}
}

func TestFetchProductsFullNotModified(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("ETag", "old-etag")
		w.WriteHeader(http.StatusNotModified)
	}))
	defer server.Close()

	client := &Client{BaseURL: server.URL, HTTPClient: server.Client()}
	_, etag, notModified, err := client.FetchProductsFull(context.Background(), "old-etag")
	if err != nil {
		t.Fatalf("FetchProductsFull(304) error = %v", err)
	}
	if !notModified || etag != "old-etag" {
		t.Fatalf("FetchProductsFull(304) notModified=%v etag=%q, want true old-etag", notModified, etag)
	}
}

func TestSyncerUpsertsProductsAndPackageMapsFromPURLs(t *testing.T) {
	t.Parallel()

	var sawIfNoneMatch string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawIfNoneMatch = r.Header.Get("If-None-Match")
		w.Header().Set("ETag", "fresh-etag")
		_, _ = w.Write([]byte(sampleProductsResponse()))
	}))
	defer server.Close()

	store := &lifecycleStoreStub{
		status: &db.FeedSyncStatus{
			FeedName: FeedName,
			Metadata: json.RawMessage(`{"etag":"old-etag"}`),
		},
	}
	syncer := NewSyncer(slog.Default(), WithBaseURL(server.URL), WithHTTPClient(server.Client()))
	result, err := syncer.Sync(context.Background(), store)
	if err != nil {
		t.Fatalf("Sync() error = %v", err)
	}
	if sawIfNoneMatch != "old-etag" {
		t.Fatalf("If-None-Match = %q, want old-etag", sawIfNoneMatch)
	}
	if result.EntriesSynced != 1 || result.EntriesTotal != 1 {
		t.Fatalf("Sync() result = %+v, want 1/1", result)
	}
	if len(store.products) != 1 {
		t.Fatalf("upserted products = %d, want 1", len(store.products))
	}
	product := store.products[0]
	if product.ProductSlug != "django" || product.Name != "Django" || product.Category != "framework" {
		t.Fatalf("product = %+v", product)
	}
	if len(product.PackageMaps) != 1 {
		t.Fatalf("package maps = %+v, want one purl-derived map", product.PackageMaps)
	}
	if got := product.PackageMaps[0]; got.Ecosystem != "pypi" || got.Name != "django" || got.PURLType != "pypi" || got.PURLName != "django" {
		t.Fatalf("package map = %+v, want pypi/django", got)
	}
	if len(product.Releases) != 1 || product.Releases[0].Cycle != "4.2" || product.Releases[0].Latest != "4.2.22" || !product.Releases[0].IsEOAS {
		t.Fatalf("releases = %+v", product.Releases)
	}
	if len(store.reconciledSlugs) != 1 || store.reconciledSlugs[0] != "django" {
		t.Fatalf("reconciled slugs = %+v, want django", store.reconciledSlugs)
	}
	if len(store.statuses) != 1 || store.statuses[0].LastSyncStatus != "success" || store.statuses[0].LastEtag != "fresh-etag" {
		t.Fatalf("status = %+v", store.statuses)
	}
	if !strings.Contains(string(store.statuses[0].Metadata), `"schema_version":"1.2.1"`) {
		t.Fatalf("metadata = %s, want schema_version", store.statuses[0].Metadata)
	}
}

func TestSyncerNotModifiedRecordsSuccessWithoutUpsert(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("ETag", "cached-etag")
		w.WriteHeader(http.StatusNotModified)
	}))
	defer server.Close()

	store := &lifecycleStoreStub{status: &db.FeedSyncStatus{FeedName: FeedName, LastEtag: "cached-etag"}}
	syncer := NewSyncer(nil, WithBaseURL(server.URL), WithHTTPClient(server.Client()))
	result, err := syncer.Sync(context.Background(), store)
	if err != nil {
		t.Fatalf("Sync(304) error = %v", err)
	}
	if result.EntriesSynced != 0 || result.EntriesTotal != 0 {
		t.Fatalf("Sync(304) result = %+v, want 0/0", result)
	}
	if len(store.products) != 0 {
		t.Fatalf("Sync(304) upserted products = %+v, want none", store.products)
	}
	if len(store.statuses) != 1 || store.statuses[0].LastSyncStatus != "success" || store.statuses[0].LastEtag != "cached-etag" {
		t.Fatalf("Sync(304) status = %+v", store.statuses)
	}
}

func TestSyncerHTTP429RecordsFailureWithoutUpsert(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()

	store := &lifecycleStoreStub{}
	syncer := NewSyncer(nil, WithBaseURL(server.URL), WithHTTPClient(server.Client()))
	result, err := syncer.Sync(context.Background(), store)
	if err == nil {
		t.Fatal("Sync(429) error = nil, want error")
	}
	if result != nil {
		t.Fatalf("Sync(429) result = %+v, want nil", result)
	}
	if len(store.products) != 0 {
		t.Fatalf("Sync(429) upserted products = %+v, want none", store.products)
	}
	if len(store.statuses) != 1 || store.statuses[0].LastSyncStatus != "error" || store.statuses[0].LastError == "" {
		t.Fatalf("Sync(429) status = %+v", store.statuses)
	}
	if !errors.Is(err, ErrHTTPStatus) {
		t.Fatalf("Sync(429) error = %v, want ErrHTTPStatus", err)
	}
}

func sampleProductsResponse() string {
	return `{
		"schema_version":"1.2.1",
		"generated_at":"2026-06-02T10:00:00Z",
		"total":1,
		"result":[{
			"name":"django",
			"label":"Django",
			"category":"framework",
			"identifiers":[{"type":"purl","id":"pkg:pypi/django"}],
			"releases":[{
				"name":"4.2",
				"releaseDate":"2023-04-03",
				"isLts":true,
				"ltsFrom":"2023-04-03",
				"isEoas":true,
				"eoasFrom":"2025-12-01",
				"isEol":false,
				"eolFrom":"2026-04-01",
				"isMaintained":true,
				"latest":{"name":"4.2.22","date":"2026-05-01","link":"https://example.test/django"}
			}]
		}]
	}`
}

func TestParseLifecycleDate(t *testing.T) {
	t.Parallel()

	got := parseLifecycleDate("2026-06-02")
	if got == nil || got.Format(time.DateOnly) != "2026-06-02" {
		t.Fatalf("parseLifecycleDate() = %v, want 2026-06-02", got)
	}
	if got := parseLifecycleDate(""); got != nil {
		t.Fatalf("parseLifecycleDate(empty) = %v, want nil", got)
	}
}
