package sqlite

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/8linkz-sec/packmon/internal/correlation"
	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/domain"
	lifecyclepolicy "github.com/8linkz-sec/packmon/internal/lifecycle"
)

type syncRoundTripFunc func(*http.Request) (*http.Response, error)

func (f syncRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestSyncHTTPClientRejectsHTTPSDowngradeRedirect(t *testing.T) {
	client := newSyncHTTPClient(time.Second)
	req, err := http.NewRequest(http.MethodGet, "http://packmon.example/api/v1/sync", nil)
	if err != nil {
		t.Fatal(err)
	}
	prev, err := http.NewRequest(http.MethodGet, "https://packmon.example/api/v1/sync", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer secret")

	if err := client.CheckRedirect(req, []*http.Request{prev}); err == nil {
		t.Fatal("CheckRedirect allowed HTTPS-to-HTTP downgrade")
	}
}

func TestSyncStatsAnyRemoved(t *testing.T) {
	t.Parallel()

	if (SyncStats{}).AnyRemoved() {
		t.Fatal("zero SyncStats reported removed rows")
	}
	stats := SyncStats{TombstoneDeleted: SyncRemovalStats{Reputation: 1}}
	if !stats.AnyRemoved() || !stats.TombstoneDeleted.Any() {
		t.Fatalf("SyncStats.AnyRemoved() = %v, TombstoneDeleted.Any() = %v; want true true", stats.AnyRemoved(), stats.TombstoneDeleted.Any())
	}
	stats = SyncStats{FullCleared: SyncRemovalStats{Lifecycle: 1}}
	if !stats.AnyRemoved() || !stats.FullCleared.Any() {
		t.Fatalf("SyncStats full clear removed = %+v, want true", stats)
	}
}

func TestValidateSyncConfig(t *testing.T) {
	t.Parallel()

	cfg, err := validateSyncConfig(SyncConfig{ServerURL: "https://packmon.example"})
	if err != nil {
		t.Fatalf("validateSyncConfig(default timeout) error = %v", err)
	}
	if cfg.Timeout != 60*time.Second {
		t.Fatalf("validateSyncConfig timeout = %v, want 60s", cfg.Timeout)
	}

	if _, err := validateSyncConfig(SyncConfig{}); err == nil || !strings.Contains(err.Error(), "no server URL configured") {
		t.Fatalf("validateSyncConfig(missing server) error = %v, want missing server URL", err)
	}
	if _, err := validateSyncConfig(SyncConfig{ServerURL: "http://packmon.example"}); err == nil || !strings.Contains(err.Error(), "refusing to use insecure server URL") {
		t.Fatalf("validateSyncConfig(insecure HTTP) error = %v, want insecure URL rejection", err)
	}
	if _, err := validateSyncConfig(SyncConfig{
		ServerURL:         "http://packmon.example",
		AllowInsecureHTTP: true,
		Full:              true,
		Ecosystems:        []string{"npm"},
	}); err == nil || !strings.Contains(err.Error(), "filtered full sync is not supported") {
		t.Fatalf("validateSyncConfig(filtered full) error = %v, want filtered full rejection", err)
	}
}

func TestLoadSyncCursorStateReadsIncrementalMetadataOnly(t *testing.T) {
	t.Parallel()

	store := newSQLiteTestStore(t)
	ctx := context.Background()
	if err := store.SetSyncMeta(ctx, syncMetaKeyLastSync, "2026-05-30T10:00:00Z"); err != nil {
		t.Fatalf("SetSyncMeta(last sync) error = %v", err)
	}
	if err := store.SetSyncMeta(ctx, syncMetaKeyLastSyncXID, "600"); err != nil {
		t.Fatalf("SetSyncMeta(last xid) error = %v", err)
	}

	delta, err := loadSyncCursorState(ctx, store, false)
	if err != nil {
		t.Fatalf("loadSyncCursorState(delta) error = %v", err)
	}
	if delta.Since != "2026-05-30T10:00:00Z" || delta.SinceXID != "600" {
		t.Fatalf("loadSyncCursorState(delta) = %+v, want durable sync metadata", delta)
	}

	full, err := loadSyncCursorState(ctx, store, true)
	if err != nil {
		t.Fatalf("loadSyncCursorState(full) error = %v", err)
	}
	if full.Since != "" || full.SinceXID != "" {
		t.Fatalf("loadSyncCursorState(full) = %+v, want empty since state", full)
	}
}

func TestSyncPaginatesWithCursorAndStableSnapshot(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newSQLiteTestStore(t)
	var mu sync.Mutex
	var requests []url.Values
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		mu.Lock()
		requests = append(requests, q)
		requestNumber := len(requests)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch requestNumber {
		case 1:
			_, _ = w.Write([]byte(`{
				"synced_at":"2026-05-30T10:00:00Z",
				"synced_xid":600,
				"truncated":true,
				"next_cursor":{"vulnerabilities":1},
				"vulnerabilities":[{
					"id":"GHSA-page-1",
					"ecosystem":"npm",
					"name":"page-one",
					"version_ranges":"[]",
					"versions_affected":"[]",
					"severity":"LOW"
				}]
			}`))
		case 2:
			_, _ = w.Write([]byte(`{
				"synced_at":"2026-05-30T10:00:00Z",
				"synced_xid":600,
				"vulnerabilities":[{
					"id":"GHSA-page-2",
					"ecosystem":"npm",
					"name":"page-two",
					"version_ranges":"[]",
					"versions_affected":"[]",
					"severity":"LOW"
				}]
			}`))
		default:
			t.Fatalf("unexpected sync request %d", requestNumber)
		}
	}))
	defer server.Close()

	if err := Sync(ctx, store, SyncConfig{
		ServerURL:         server.URL,
		AllowInsecureHTTP: true,
	}); err != nil {
		t.Fatalf("Sync() error = %v", err)
	}
	mu.Lock()
	gotRequests := append([]url.Values(nil), requests...)
	mu.Unlock()
	if len(gotRequests) != 2 {
		t.Fatalf("requests = %d, want 2", len(gotRequests))
	}
	if gotRequests[0].Get("snapshot") != "" || gotRequests[0].Get("vulnerabilities_offset") != "" {
		t.Fatalf("first request query = %v, want no snapshot or cursor offset", gotRequests[0])
	}
	if gotRequests[1].Get("snapshot") != "2026-05-30T10:00:00Z" || gotRequests[1].Get("snapshot_xid") != "600" || gotRequests[1].Get("vulnerabilities_offset") != "1" {
		t.Fatalf("second request query = %v, want pinned snapshot and advanced cursor", gotRequests[1])
	}
	for _, name := range []string{"page-one", "page-two"} {
		findings, err := store.FindVulnerabilities(ctx, "npm", name, "1.0.0")
		if err != nil {
			t.Fatalf("FindVulnerabilities(%s) error = %v", name, err)
		}
		if len(findings) != 1 {
			t.Fatalf("FindVulnerabilities(%s) findings = %+v, want one finding", name, findings)
		}
	}
}

func TestSyncAppliesIncrementalPageBeforeFetchingNextPageAndAccumulatesStats(t *testing.T) {
	t.Parallel()

	store := newSQLiteTestStore(t)
	ctx := context.Background()
	if _, err := applySync(ctx, store, true, &syncResponse{
		Vulnerabilities: []syncVulnerability{{
			ID:               "GHSA-delete-page-one",
			Ecosystem:        "npm",
			Name:             "delete-page-one",
			VersionRanges:    `[{"type":"SEMVER","events":[{"introduced":"0"}]}]`,
			VersionsAffected: `[]`,
			Severity:         "HIGH",
		}},
		Malicious: []syncMalicious{{
			ID:            "MAL-delete-page-two",
			Ecosystem:     "npm",
			Name:          "delete-page-two",
			VersionRanges: `[{"type":"SEMVER","events":[{"introduced":"0"}]}]`,
			Severity:      "CRITICAL",
			RiskType:      "malware",
		}},
	}); err != nil {
		t.Fatalf("applySync(seed) error = %v", err)
	}

	var handlerErr error
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Header().Set("Content-Type", "application/json")
		switch requests {
		case 1:
			_, _ = w.Write([]byte(`{
				"synced_at":"2026-05-30T10:00:00Z",
				"synced_xid":600,
				"truncated":true,
				"next_cursor":{"vulnerabilities":1,"malicious_done":true,"reputation_done":true,"lifecycle_done":true},
				"vulnerabilities":[
					{"id":"GHSA-delete-page-one","withdrawn":true},
					{
						"id":"GHSA-page-one-applied",
						"ecosystem":"npm",
						"name":"page-one-applied",
						"version_ranges":"[{\"type\":\"SEMVER\",\"events\":[{\"introduced\":\"0\"}]}]",
						"versions_affected":"[]",
						"severity":"LOW"
					}
				]
			}`))
		case 2:
			deleted, err := store.FindVulnerabilities(ctx, "npm", "delete-page-one", "1.0.0")
			if err != nil {
				handlerErr = fmt.Errorf("find deleted page-one vulnerability: %w", err)
				http.Error(w, handlerErr.Error(), http.StatusInternalServerError)
				return
			}
			if len(deleted) != 0 {
				handlerErr = fmt.Errorf("page-one tombstone was not applied before page two: %+v", deleted)
				http.Error(w, handlerErr.Error(), http.StatusInternalServerError)
				return
			}
			inserted, err := store.FindVulnerabilities(ctx, "npm", "page-one-applied", "1.0.0")
			if err != nil {
				handlerErr = fmt.Errorf("find inserted page-one vulnerability: %w", err)
				http.Error(w, handlerErr.Error(), http.StatusInternalServerError)
				return
			}
			if len(inserted) != 1 || inserted[0].AdvisoryID != "GHSA-page-one-applied" {
				handlerErr = fmt.Errorf("page-one insert was not applied before page two: %+v", inserted)
				http.Error(w, handlerErr.Error(), http.StatusInternalServerError)
				return
			}
			_, _ = w.Write([]byte(`{
				"synced_at":"2026-05-30T10:00:00Z",
				"synced_xid":600,
				"malicious":[{"id":"MAL-delete-page-two","withdrawn":true}]
			}`))
		default:
			handlerErr = fmt.Errorf("unexpected sync request %d", requests)
			http.Error(w, handlerErr.Error(), http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	var stats SyncStats
	err := Sync(ctx, store, SyncConfig{
		ServerURL:         server.URL,
		AllowInsecureHTTP: true,
		Stats:             &stats,
	})
	if handlerErr != nil {
		t.Fatalf("server page-two observation failed: %v", handlerErr)
	}
	if err != nil {
		t.Fatalf("Sync() error = %v", err)
	}
	if requests != 2 {
		t.Fatalf("requests = %d, want 2", requests)
	}
	if stats.TombstoneDeleted != (SyncRemovalStats{Vulnerabilities: 1, Malicious: 1}) {
		t.Fatalf("tombstone stats = %+v, want page-one vulnerability and page-two malicious deletes", stats.TombstoneDeleted)
	}
}

func TestSyncFullClearsAndAppliesFirstPageBeforeFetchingNextPage(t *testing.T) {
	t.Parallel()

	store := newSQLiteTestStore(t)
	ctx := context.Background()
	seedLocalSyncRows(t, store)

	var handlerErr error
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Header().Set("Content-Type", "application/json")
		switch requests {
		case 1:
			if got := r.URL.Query().Get("since"); got != "" {
				handlerErr = fmt.Errorf("first full-sync request since = %q, want empty", got)
				http.Error(w, handlerErr.Error(), http.StatusInternalServerError)
				return
			}
			_, _ = w.Write([]byte(`{
				"synced_at":"2026-05-30T10:00:00Z",
				"synced_xid":600,
				"truncated":true,
				"next_cursor":{"vulnerabilities":1},
				"vulnerabilities":[{
					"id":"GHSA-full-page-one",
					"ecosystem":"npm",
					"name":"full-page-one",
					"version_ranges":"[{\"type\":\"SEMVER\",\"events\":[{\"introduced\":\"0\"}]}]",
					"versions_affected":"[]",
					"severity":"LOW"
				}]
			}`))
		case 2:
			oldRows, err := store.FindVulnerabilities(ctx, "npm", "left-pad", "1.0.0")
			if err != nil {
				handlerErr = fmt.Errorf("find preexisting vulnerability: %w", err)
				http.Error(w, handlerErr.Error(), http.StatusInternalServerError)
				return
			}
			if len(oldRows) != 0 {
				handlerErr = fmt.Errorf("full sync did not clear before page two: %+v", oldRows)
				http.Error(w, handlerErr.Error(), http.StatusInternalServerError)
				return
			}
			firstPage, err := store.FindVulnerabilities(ctx, "npm", "full-page-one", "1.0.0")
			if err != nil {
				handlerErr = fmt.Errorf("find first page vulnerability: %w", err)
				http.Error(w, handlerErr.Error(), http.StatusInternalServerError)
				return
			}
			if len(firstPage) != 1 || firstPage[0].AdvisoryID != "GHSA-full-page-one" {
				handlerErr = fmt.Errorf("full sync did not apply first page before page two: %+v", firstPage)
				http.Error(w, handlerErr.Error(), http.StatusInternalServerError)
				return
			}
			_, _ = w.Write([]byte(`{
				"synced_at":"2026-05-30T10:00:00Z",
				"synced_xid":600,
				"feed_status":"healthy",
				"vulnerabilities":[{
					"id":"GHSA-full-page-two",
					"ecosystem":"npm",
					"name":"full-page-two",
					"version_ranges":"[{\"type\":\"SEMVER\",\"events\":[{\"introduced\":\"0\"}]}]",
					"versions_affected":"[]",
					"severity":"LOW"
				}]
			}`))
		default:
			handlerErr = fmt.Errorf("unexpected sync request %d", requests)
			http.Error(w, handlerErr.Error(), http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	var stats SyncStats
	err := Sync(ctx, store, SyncConfig{
		ServerURL:         server.URL,
		Full:              true,
		AllowInsecureHTTP: true,
		Stats:             &stats,
	})
	if handlerErr != nil {
		t.Fatalf("server page-two observation failed: %v", handlerErr)
	}
	if err != nil {
		t.Fatalf("Sync(full) error = %v", err)
	}
	if requests != 2 {
		t.Fatalf("requests = %d, want 2", requests)
	}
	if stats.FullCleared != (SyncRemovalStats{Vulnerabilities: 1, Malicious: 1, Reputation: 1, Lifecycle: 1}) {
		t.Fatalf("full clear stats = %+v", stats.FullCleared)
	}
	for _, name := range []string{"full-page-one", "full-page-two"} {
		findings, err := store.FindVulnerabilities(ctx, "npm", name, "1.0.0")
		if err != nil {
			t.Fatalf("FindVulnerabilities(%s) error = %v", name, err)
		}
		if len(findings) != 1 {
			t.Fatalf("FindVulnerabilities(%s) findings = %+v, want one finding", name, findings)
		}
	}
}

func TestApplySyncPageKeepsFutureSnapshotOutOfFreshnessMetadata(t *testing.T) {
	t.Parallel()

	store := newSQLiteTestStore(t)
	ctx := context.Background()
	previousSync := "2026-05-30T09:00:00Z"
	if err := store.SetSyncMeta(ctx, syncMetaKeyLastSync, previousSync); err != nil {
		t.Fatalf("SetSyncMeta(last sync) error = %v", err)
	}
	if err := store.SetSyncMeta(ctx, syncMetaKeyLastSyncXID, "500"); err != nil {
		t.Fatalf("SetSyncMeta(last xid) error = %v", err)
	}
	if err := store.SetSyncMeta(ctx, syncMetaKeyFeedStatus, "healthy"); err != nil {
		t.Fatalf("SetSyncMeta(feed status) error = %v", err)
	}

	future := "2026-05-31T00:00:00Z"
	resp := &syncResponse{
		SyncedAt:     future,
		SyncedXID:    700,
		FeedStatus:   "degraded",
		FeedVersions: map[string]string{"osv": future},
		Vulnerabilities: []syncVulnerability{{
			ID:               "GHSA-helper-future",
			Ecosystem:        "npm",
			Name:             "helper-future",
			VersionRanges:    `[]`,
			VersionsAffected: `[]`,
			Severity:         "LOW",
		}},
	}
	metadata, err := freshSyncApplyMetadata(syncPageSnapshot{
		SyncedAt:  future,
		SyncedXID: "700",
	}, resp, time.Date(2026, 5, 30, 10, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("freshSyncApplyMetadata() error = %v", err)
	}
	stats, err := applySyncWithMetadata(ctx, store, false, resp, metadata)
	if err != nil {
		t.Fatalf("applySyncWithMetadata() error = %v", err)
	}
	if stats.AnyRemoved() {
		t.Fatalf("applySyncWithMetadata() stats = %+v, want no removals", stats)
	}
	findings, err := store.FindVulnerabilities(ctx, "npm", "helper-future", "1.0.0")
	if err != nil {
		t.Fatalf("FindVulnerabilities() error = %v", err)
	}
	if len(findings) != 1 || findings[0].AdvisoryID != "GHSA-helper-future" {
		t.Fatalf("future snapshot findings = %+v, want applied row", findings)
	}
	lastSync, err := store.GetSyncMeta(ctx, syncMetaKeyLastSync)
	if err != nil {
		t.Fatalf("GetSyncMeta(last sync) error = %v", err)
	}
	if lastSync != previousSync {
		t.Fatalf("last sync = %q, want preserved %q", lastSync, previousSync)
	}
	lastXID, err := store.GetSyncMeta(ctx, syncMetaKeyLastSyncXID)
	if err != nil {
		t.Fatalf("GetSyncMeta(last xid) error = %v", err)
	}
	if lastXID != "500" {
		t.Fatalf("last xid = %q, want preserved 500", lastXID)
	}
	feedStatus, err := store.GetSyncMeta(ctx, syncMetaKeyFeedStatus)
	if err != nil {
		t.Fatalf("GetSyncMeta(feed status) error = %v", err)
	}
	if feedStatus != "healthy" {
		t.Fatalf("feed status = %q, want preserved healthy", feedStatus)
	}
}

func TestSyncHTTPClientStripsAuthorizationOnCrossOriginRedirect(t *testing.T) {
	client := newSyncHTTPClient(time.Second)
	req, err := http.NewRequest(http.MethodGet, "https://other.example/api/v1/sync", nil)
	if err != nil {
		t.Fatal(err)
	}
	prev, err := http.NewRequest(http.MethodGet, "https://packmon.example/api/v1/sync", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer secret")

	if err := client.CheckRedirect(req, []*http.Request{prev}); err != nil {
		t.Fatalf("CheckRedirect same-scheme cross-origin error = %v", err)
	}
	if got := req.Header.Get("Authorization"); got != "" {
		t.Fatalf("Authorization after cross-origin redirect = %q, want stripped", got)
	}
}

func TestSyncUsesConfiguredCABundle(t *testing.T) {
	store := newSQLiteTestStore(t)
	ctx := context.Background()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/sync" {
			t.Fatalf("path = %q, want /api/v1/sync", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"synced_at":"` + time.Now().UTC().Format(time.RFC3339) + `",
			"vulnerabilities":[{"id":"GHSA-ca","ecosystem":"npm","name":"left-pad","version_ranges":"[]","severity":"LOW"}]
		}`))
	}))
	defer server.Close()

	caFile := filepath.Join(t.TempDir(), "server-ca.pem")
	writeSyncServerCertPEM(t, server, caFile)

	if err := Sync(ctx, store, SyncConfig{
		ServerURL:  server.URL,
		CACertFile: caFile,
		Timeout:    5 * time.Second,
	}); err != nil {
		t.Fatalf("Sync() with configured CA bundle error = %v", err)
	}

	findings, err := store.FindVulnerabilities(ctx, "npm", "left-pad", "1.0.0")
	if err != nil {
		t.Fatalf("FindVulnerabilities() error = %v", err)
	}
	if len(findings) != 1 || findings[0].AdvisoryID != "GHSA-ca" {
		t.Fatalf("synced findings = %+v, want GHSA-ca", findings)
	}
}

func writeSyncServerCertPEM(t *testing.T, server *httptest.Server, path string) {
	t.Helper()
	if server.TLS == nil || len(server.TLS.Certificates) == 0 {
		t.Fatal("test server has no TLS certificate")
	}
	var out []byte
	for _, cert := range server.TLS.Certificates {
		for _, der := range cert.Certificate {
			out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
		}
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatalf("write server certificate: %v", err)
	}
}

type syncedRowsFixture struct {
	store          *Store
	ctx            context.Context
	epssPercentile float64
}

func newSyncedRowsFixture(t *testing.T) syncedRowsFixture {
	t.Helper()

	store := newSQLiteTestStore(t)
	ctx := context.Background()
	cvss := 9.8
	epss := 0.42
	epssPercentile := 0.88
	resp := &syncResponse{
		Vulnerabilities: []syncVulnerability{{
			ID:               "GHSA-sync",
			Ecosystem:        "npm",
			Name:             "left-pad",
			VersionRanges:    `[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"2.0.0"}]}]`,
			VersionsAffected: `[]`,
			References:       `[{"type":"ADVISORY","url":"https://github.com/advisories/GHSA-sync"},{"type":"WEB","url":"https://osv.dev/vulnerability/GHSA-sync"}]`,
			Severity:         "HIGH",
			CVSSScore:        &cvss,
			EPSSScore:        &epss,
			EPSSPercentile:   &epssPercentile,
			CISAKEV:          true,
			Summary:          "sync vuln",
			Source:           "manual",
		}, {
			ID:               "GHSA-versions",
			Ecosystem:        "npm",
			Name:             "only-listed",
			VersionRanges:    `[]`,
			VersionsAffected: `["1.0.1"]`,
			Severity:         "MEDIUM",
			Summary:          "explicit versions",
		}},
		Malicious: []syncMalicious{{
			ID:            "MAL-sync",
			Ecosystem:     "npm",
			Name:          "evil",
			VersionRanges: `[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"2.0.0"}]}]`,
			Versions:      `["2.1.5-bad"]`,
			ReferenceURLs: `["https://example.test/malware/MAL-sync"]`,
			RiskType:      "malware",
			Severity:      "CRITICAL",
			Summary:       "bad",
			Source:        "manual",
		}},
	}
	if _, err := applySync(ctx, store, true, resp); err != nil {
		t.Fatalf("applySync() error = %v", err)
	}

	return syncedRowsFixture{
		store:          store,
		ctx:            ctx,
		epssPercentile: epssPercentile,
	}
}

func TestApplySyncVulnerabilityRowsPreserveMetadataAndBatchLookup(t *testing.T) {
	t.Parallel()

	fixture := newSyncedRowsFixture(t)
	store := fixture.store
	ctx := fixture.ctx

	vulns, err := store.FindVulnerabilities(ctx, "npm", "left-pad", "1.5.0")
	if err != nil {
		t.Fatalf("FindVulnerabilities() error = %v", err)
	}
	if len(vulns) != 1 || vulns[0].AdvisoryID != "GHSA-sync" || vulns[0].FixedVersion != ">= 2.0.0" {
		t.Fatalf("vulns = %+v, want synced vulnerability with fixed version", vulns)
	}
	if vulns[0].URL == "" || len(vulns[0].Resources) < 2 {
		t.Fatalf("vuln resources = url %q resources %+v, want synced links", vulns[0].URL, vulns[0].Resources)
	}
	if vulns[0].Source != "manual" {
		t.Fatalf("vuln source = %q, want manual", vulns[0].Source)
	}
	var storedPercentile float64
	if err := store.DB().QueryRowContext(ctx, `SELECT epss_percentile FROM vulnerabilities_local WHERE id = ?`, "GHSA-sync").Scan(&storedPercentile); err != nil {
		t.Fatalf("read synced EPSS percentile: %v", err)
	}
	if storedPercentile != fixture.epssPercentile {
		t.Fatalf("stored EPSS percentile = %v, want %v", storedPercentile, fixture.epssPercentile)
	}
	batchVulns, err := store.FindVulnerabilitiesBatch(ctx, []db.PackageQuery{{Ecosystem: "npm", Name: "left-pad", Version: "1.5.0"}})
	if err != nil {
		t.Fatalf("FindVulnerabilitiesBatch() error = %v", err)
	}
	if len(batchVulns) != 1 || batchVulns[0].Source != "manual" {
		t.Fatalf("batch vuln source = %+v, want manual source", batchVulns)
	}
}

func TestApplySyncVulnerabilityExplicitVersions(t *testing.T) {
	t.Parallel()

	fixture := newSyncedRowsFixture(t)
	store := fixture.store
	ctx := fixture.ctx

	vulns, err := store.FindVulnerabilities(ctx, "npm", "only-listed", "1.0.1")
	if err != nil {
		t.Fatalf("FindVulnerabilities(versions_affected hit) error = %v", err)
	}
	if len(vulns) != 1 || vulns[0].AdvisoryID != "GHSA-versions" {
		t.Fatalf("versions_affected hit = %+v, want GHSA-versions", vulns)
	}
	vulns, err = store.FindVulnerabilities(ctx, "npm", "only-listed", "1.0.2")
	if err != nil {
		t.Fatalf("FindVulnerabilities(versions_affected miss) error = %v", err)
	}
	if len(vulns) != 0 {
		t.Fatalf("versions_affected miss = %+v, want no findings", vulns)
	}
}

func TestApplySyncMaliciousRowsPreserveMetadataAndBatchLookup(t *testing.T) {
	t.Parallel()

	fixture := newSyncedRowsFixture(t)
	store := fixture.store
	ctx := fixture.ctx

	mal, err := store.FindMalicious(ctx, "npm", "evil", "1.5.0")
	if err != nil {
		t.Fatalf("FindMalicious() error = %v", err)
	}
	if len(mal) != 1 || mal[0].Type != domain.FindingTypeMalicious {
		t.Fatalf("malicious range hit = %+v, want synced malicious finding", mal)
	}
	if mal[0].Version != "1.5.0" {
		t.Fatalf("malicious range hit version = %q, want requested version", mal[0].Version)
	}
	if mal[0].AdvisoryID != "MAL-sync" || mal[0].URL != "https://example.test/malware/MAL-sync" {
		t.Fatalf("malicious link fields = %+v, want advisory id and URL", mal[0])
	}
	if mal[0].Source != "manual" {
		t.Fatalf("malicious source = %q, want manual", mal[0].Source)
	}
	batchMal, err := store.FindMaliciousBatch(ctx, []db.PackageQuery{{Ecosystem: "npm", Name: "evil", Version: "1.5.0"}})
	if err != nil {
		t.Fatalf("FindMaliciousBatch() error = %v", err)
	}
	if len(batchMal) != 1 || batchMal[0].Source != "manual" {
		t.Fatalf("batch malicious source = %+v, want manual source", batchMal)
	}
	mal, err = store.FindMalicious(ctx, "npm", "evil", "2.0.0")
	if err != nil {
		t.Fatalf("FindMalicious(range miss) error = %v", err)
	}
	if len(mal) != 0 {
		t.Fatalf("malicious range miss = %+v, want no finding at fixed version", mal)
	}
}

func TestApplySyncMaliciousExplicitVersions(t *testing.T) {
	t.Parallel()

	fixture := newSyncedRowsFixture(t)
	store := fixture.store
	ctx := fixture.ctx

	mal, err := store.FindMalicious(ctx, "npm", "evil", "2.1.5-bad")
	if err != nil {
		t.Fatalf("FindMalicious(explicit version hit) error = %v", err)
	}
	if len(mal) != 1 || mal[0].AdvisoryID != "MAL-sync" {
		t.Fatalf("malicious explicit hit = %+v, want synced malicious finding", mal)
	}
	if mal[0].Version != "2.1.5-bad" {
		t.Fatalf("malicious explicit hit version = %q, want requested version", mal[0].Version)
	}
}

func TestApplySyncTombstonesDeleteVulnerabilityAndMaliciousRows(t *testing.T) {
	t.Parallel()

	fixture := newSyncedRowsFixture(t)
	store := fixture.store
	ctx := fixture.ctx
	if _, err := applySync(ctx, store, false, &syncResponse{
		Vulnerabilities: []syncVulnerability{{ID: "GHSA-sync", Withdrawn: true}},
		Malicious:       []syncMalicious{{ID: "MAL-sync", Withdrawn: true}},
	}); err != nil {
		t.Fatalf("applySync(tombstones) error = %v", err)
	}
	vulns, _ := store.FindVulnerabilities(ctx, "npm", "left-pad", "1.5.0")
	mal, _ := store.FindMalicious(ctx, "npm", "evil", "1.5.0")
	if len(vulns) != 0 || len(mal) != 0 {
		t.Fatalf("rows after tombstones: vulns=%+v malicious=%+v", vulns, mal)
	}
}

func TestApplySyncNormalizesCaseInsensitivePackageNames(t *testing.T) {
	t.Parallel()

	store := newSQLiteTestStore(t)
	ctx := context.Background()
	resp := &syncResponse{
		Vulnerabilities: []syncVulnerability{{
			ID:               "PYSEC-normalized",
			Ecosystem:        "pypi",
			Name:             "My.Pkg_Name",
			VersionRanges:    `[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.0.0"}]}]`,
			VersionsAffected: `[]`,
			Severity:         "HIGH",
			Summary:          "pypi normalized vuln",
		}, {
			ID:               "GHSA-nuget-normalized",
			Ecosystem:        "nuget",
			Name:             "Newtonsoft.Json",
			VersionRanges:    `[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"14.0.0"}]}]`,
			VersionsAffected: `[]`,
			Severity:         "HIGH",
			Summary:          "nuget normalized vuln",
		}},
		Malicious: []syncMalicious{{
			ID:        "MAL-pypi-normalized",
			Ecosystem: "pypi",
			Name:      "Django",
			Versions:  `["4.2.11"]`,
			RiskType:  "malware",
			Severity:  "CRITICAL",
		}, {
			ID:        "MAL-nuget-normalized",
			Ecosystem: "nuget",
			Name:      "NuGet.Mixed_Case",
			Versions:  `["1.0.0"]`,
			RiskType:  "malware",
			Severity:  "CRITICAL",
		}},
	}
	if _, err := applySync(ctx, store, true, resp); err != nil {
		t.Fatalf("applySync() error = %v", err)
	}

	vulns, err := store.FindVulnerabilities(ctx, "pypi", "my-pkg-name", "1.5.0")
	if err != nil {
		t.Fatalf("FindVulnerabilities(pypi normalized) error = %v", err)
	}
	if len(vulns) != 1 || vulns[0].AdvisoryID != "PYSEC-normalized" || vulns[0].Name != "my-pkg-name" {
		t.Fatalf("pypi normalized findings = %+v, want canonical package match", vulns)
	}
	vulns, err = store.FindVulnerabilities(ctx, "nuget", "newtonsoft.json", "13.0.3")
	if err != nil {
		t.Fatalf("FindVulnerabilities(nuget normalized) error = %v", err)
	}
	if len(vulns) != 1 || vulns[0].AdvisoryID != "GHSA-nuget-normalized" || vulns[0].Name != "newtonsoft.json" {
		t.Fatalf("nuget normalized findings = %+v, want canonical package match", vulns)
	}

	malicious, err := store.FindMalicious(ctx, "pypi", "django", "4.2.11")
	if err != nil {
		t.Fatalf("FindMalicious(pypi normalized) error = %v", err)
	}
	if len(malicious) != 1 || malicious[0].AdvisoryID != "MAL-pypi-normalized" || malicious[0].Name != "django" {
		t.Fatalf("pypi malicious = %+v, want canonical package match", malicious)
	}
	malicious, err = store.FindMalicious(ctx, "nuget", "nuget.mixed_case", "1.0.0")
	if err != nil {
		t.Fatalf("FindMalicious(nuget normalized) error = %v", err)
	}
	if len(malicious) != 1 || malicious[0].AdvisoryID != "MAL-nuget-normalized" || malicious[0].Name != "nuget.mixed_case" {
		t.Fatalf("nuget malicious = %+v, want canonical package match", malicious)
	}

	batch, err := store.FindVulnerabilitiesBatch(ctx, []db.PackageQuery{
		{Ecosystem: "pypi", Name: "My_Pkg.Name", Version: "1.5.0"},
		{Ecosystem: "nuget", Name: "Newtonsoft.Json", Version: "13.0.3"},
	})
	if err != nil {
		t.Fatalf("FindVulnerabilitiesBatch(normalized) error = %v", err)
	}
	if len(batch) != 2 {
		t.Fatalf("FindVulnerabilitiesBatch(normalized) = %+v, want both normalized findings", batch)
	}
}

func TestApplySyncRejectsMalformedMaliciousVersions(t *testing.T) {
	t.Parallel()

	store := newSQLiteTestStore(t)
	ctx := context.Background()

	_, err := applySync(ctx, store, true, &syncResponse{
		Malicious: []syncMalicious{{
			ID:        "MAL-sync-invalid-versions",
			Ecosystem: "npm",
			Name:      "evil",
			Versions:  `{"introduced":"1.0.0"}`,
			RiskType:  "malware",
			Severity:  "CRITICAL",
			Summary:   "invalid versions",
		}},
	})
	if err == nil {
		t.Fatal("applySync() error = nil, want invalid malicious versions error")
	}
	if !strings.Contains(err.Error(), "MAL-sync-invalid-versions") {
		t.Fatalf("applySync() error = %q, want malicious finding ID", err)
	}

	findings, findErr := store.FindMaliciousBatch(ctx, []db.PackageQuery{
		{Ecosystem: "npm", Name: "evil", Version: "2.0.0"},
	})
	if findErr != nil {
		t.Fatalf("FindMaliciousBatch() error = %v", findErr)
	}
	if len(findings) != 0 {
		t.Fatalf("FindMaliciousBatch() = %+v, want rejected row absent", findings)
	}
}

func TestApplySyncRejectsMalformedMaliciousVersionRanges(t *testing.T) {
	t.Parallel()

	store := newSQLiteTestStore(t)
	ctx := context.Background()

	_, err := applySync(ctx, store, true, &syncResponse{
		Malicious: []syncMalicious{{
			ID:            "MAL-sync-invalid-version-ranges",
			Ecosystem:     "npm",
			Name:          "evil-ranges",
			VersionRanges: `{"introduced":"1.0.0"}`,
			RiskType:      "malware",
			Severity:      "CRITICAL",
			Summary:       "invalid version ranges",
		}},
	})
	if err == nil {
		t.Fatal("applySync() error = nil, want invalid malicious version_ranges error")
	}
	if !strings.Contains(err.Error(), "MAL-sync-invalid-version-ranges") || !strings.Contains(err.Error(), "version_ranges") {
		t.Fatalf("applySync() error = %q, want malicious finding ID and version_ranges", err)
	}

	findings, findErr := store.FindMaliciousBatch(ctx, []db.PackageQuery{
		{Ecosystem: "npm", Name: "evil-ranges", Version: "2.0.0"},
	})
	if findErr != nil {
		t.Fatalf("FindMaliciousBatch() error = %v", findErr)
	}
	if len(findings) != 0 {
		t.Fatalf("FindMaliciousBatch() = %+v, want rejected row absent", findings)
	}
}

func TestApplySyncRejectsMalformedVulnerabilityVersionJSON(t *testing.T) {
	t.Parallel()

	store := newSQLiteTestStore(t)
	ctx := context.Background()

	_, err := applySync(ctx, store, true, &syncResponse{
		Vulnerabilities: []syncVulnerability{{
			ID:               "GHSA-sync-invalid-version-ranges",
			Ecosystem:        "npm",
			Name:             "bad-vuln-range",
			VersionRanges:    `{"introduced":"1.0.0"}`,
			VersionsAffected: `[]`,
			Severity:         "HIGH",
			Summary:          "invalid vulnerability ranges",
		}},
	})
	if err == nil {
		t.Fatal("applySync() error = nil, want invalid vulnerability version_ranges error")
	}
	if !strings.Contains(err.Error(), "GHSA-sync-invalid-version-ranges") || !strings.Contains(err.Error(), "version_ranges") {
		t.Fatalf("applySync() error = %q, want vulnerability ID and version_ranges", err)
	}

	_, err = applySync(ctx, store, true, &syncResponse{
		Vulnerabilities: []syncVulnerability{{
			ID:               "GHSA-sync-invalid-versions-affected",
			Ecosystem:        "npm",
			Name:             "bad-vuln-versions",
			VersionRanges:    `[]`,
			VersionsAffected: `{"all":true}`,
			Severity:         "HIGH",
			Summary:          "invalid affected versions",
		}},
	})
	if err == nil {
		t.Fatal("applySync() error = nil, want invalid vulnerability versions_affected error")
	}
	if !strings.Contains(err.Error(), "GHSA-sync-invalid-versions-affected") || !strings.Contains(err.Error(), "versions_affected") {
		t.Fatalf("applySync() error = %q, want vulnerability ID and versions_affected", err)
	}

	findings, findErr := store.FindVulnerabilitiesBatch(ctx, []db.PackageQuery{
		{Ecosystem: "npm", Name: "bad-vuln-range", Version: "2.0.0"},
		{Ecosystem: "npm", Name: "bad-vuln-versions", Version: "2.0.0"},
	})
	if findErr != nil {
		t.Fatalf("FindVulnerabilitiesBatch() error = %v", findErr)
	}
	if len(findings) != 0 {
		t.Fatalf("FindVulnerabilitiesBatch() = %+v, want rejected rows absent", findings)
	}
}

func TestApplySyncLifecycleRowsAndFindings(t *testing.T) {
	t.Parallel()

	store := newSQLiteTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 6, 2, 12, 0, 0, 0, time.UTC)
	eolPast := now.AddDate(0, 0, -1)
	eoasPast := now.AddDate(0, 0, -7)
	eolSoon := now.AddDate(0, 0, 30)
	eolPastDate := eolPast.Format(time.DateOnly)
	eoasPastDate := eoasPast.Format(time.DateOnly)
	eolSoonDate := eolSoon.Format(time.DateOnly)

	resp := &syncResponse{
		Lifecycle: []syncLifecycleRelease{
			{
				ID:           "endoflife:pypi:django:django:3.2",
				Ecosystem:    "pypi",
				Name:         "django",
				ProductSlug:  "django",
				ProductLabel: "Django",
				Cycle:        "3.2",
				EOLFrom:      &eolPastDate,
			},
			{
				ID:           "endoflife:pypi:django:django:4",
				Ecosystem:    "pypi",
				Name:         "django",
				ProductSlug:  "django",
				ProductLabel: "Django",
				Cycle:        "4",
				IsEOL:        true,
			},
			{
				ID:           "endoflife:pypi:django:django:4.2",
				Ecosystem:    "pypi",
				Name:         "django",
				ProductSlug:  "django",
				ProductLabel: "Django",
				Cycle:        "4.2",
				IsEOAS:       true,
				EOASFrom:     &eoasPastDate,
			},
			{
				ID:           "endoflife:pypi:django:django:5.0",
				Ecosystem:    "pypi",
				Name:         "django",
				ProductSlug:  "django",
				ProductLabel: "Django",
				Cycle:        "5.0",
				EOLFrom:      &eolSoonDate,
			},
			{
				ID:           "endoflife:pypi:django:django:6.0",
				Ecosystem:    "pypi",
				Name:         "django",
				ProductSlug:  "django",
				ProductLabel: "Django",
				Cycle:        "6.0",
			},
		},
	}
	if _, err := applySync(ctx, store, true, resp); err != nil {
		t.Fatalf("applySync() error = %v", err)
	}

	findings, err := store.FindLifecycleFindingsBatch(ctx, []db.PackageQuery{
		{Ecosystem: "pypi", Name: "django", Version: "3.2.25"},
		{Ecosystem: "pypi", Name: "django", Version: "4.1.1"},
		{Ecosystem: "pypi", Name: "django", Version: "4.2.11"},
		{Ecosystem: "pypi", Name: "django", Version: "5.0.1"},
		{Ecosystem: "pypi", Name: "django", Version: "6.0.0"},
	}, now)
	if err != nil {
		t.Fatalf("FindLifecycleFindingsBatch() error = %v", err)
	}

	byVersion := make(map[string]domain.Finding, len(findings))
	for _, finding := range findings {
		byVersion[finding.Version] = finding
	}
	if len(byVersion) != 4 {
		t.Fatalf("FindLifecycleFindingsBatch() returned %d findings: %+v", len(findings), findings)
	}
	assertSQLiteLifecycleFinding(t, byVersion["3.2.25"], domain.FindingTypeSupplyChainRisk, domain.SeverityCritical, "eol")
	assertSQLiteLifecycleFinding(t, byVersion["4.1.1"], domain.FindingTypeSupplyChainRisk, domain.SeverityCritical, "eol")
	assertSQLiteLifecycleFinding(t, byVersion["4.2.11"], domain.FindingTypeLifecycle, domain.SeverityLow, "security_support_only")
	assertSQLiteLifecycleFinding(t, byVersion["5.0.1"], domain.FindingTypeLifecycle, domain.SeverityMedium, "eol_soon")
	if _, ok := byVersion["6.0.0"]; ok {
		t.Fatalf("6.0.0 produced lifecycle finding despite no lifecycle signal: %+v", byVersion["6.0.0"])
	}

	if _, err := applySync(ctx, store, false, &syncResponse{
		Lifecycle: []syncLifecycleRelease{{ID: "endoflife:pypi:django:django:4.2", Withdrawn: true}},
	}); err != nil {
		t.Fatalf("applySync(tombstone) error = %v", err)
	}
	findings, err = store.FindLifecycleFindingsBatch(ctx, []db.PackageQuery{
		{Ecosystem: "pypi", Name: "django", Version: "4.2.11"},
	}, now)
	if err != nil {
		t.Fatalf("FindLifecycleFindingsBatch(after tombstone) error = %v", err)
	}
	if len(findings) != 1 || findings[0].RiskType != "eol" {
		t.Fatalf("findings after 4.2 tombstone = %+v, want fallback 4.x EOL finding", findings)
	}
}

func TestFindLifecycleFindingsBatchNormalizesNuGetNames(t *testing.T) {
	t.Parallel()

	store := newSQLiteTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 6, 2, 12, 0, 0, 0, time.UTC)

	resp := &syncResponse{
		Lifecycle: []syncLifecycleRelease{
			{
				ID:           "endoflife:nuget:newtonsoft.json:newtonsoft-json:13",
				Ecosystem:    "nuget",
				Name:         "newtonsoft.json",
				ProductSlug:  "newtonsoft-json",
				ProductLabel: "Newtonsoft.Json",
				Cycle:        "13",
				IsEOL:        true,
			},
		},
	}
	if _, err := applySync(ctx, store, true, resp); err != nil {
		t.Fatalf("applySync() error = %v", err)
	}

	findings, err := store.FindLifecycleFindingsBatch(ctx, []db.PackageQuery{
		{Ecosystem: "nuget", Name: "Newtonsoft.Json", Version: "13.0.3"},
	}, now)
	if err != nil {
		t.Fatalf("FindLifecycleFindingsBatch() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("FindLifecycleFindingsBatch() returned %d findings: %+v", len(findings), findings)
	}
	if findings[0].Name != "newtonsoft.json" {
		t.Fatalf("finding name = %q, want normalized NuGet name", findings[0].Name)
	}
	assertSQLiteLifecycleFinding(t, findings[0], domain.FindingTypeSupplyChainRisk, domain.SeverityCritical, "eol")
}

func TestCollectLifecycleReleaseRowsFiltersRequestedBatch(t *testing.T) {
	t.Parallel()

	store := newSQLiteTestStore(t)
	ctx := context.Background()
	resp := &syncResponse{
		Lifecycle: []syncLifecycleRelease{
			{
				ID:           "endoflife:pypi:django:django:4.2",
				Ecosystem:    "pypi",
				Name:         "django",
				ProductSlug:  "django",
				ProductLabel: "Django",
				Cycle:        "4.2",
				Latest:       "4.2.11",
				IsEOL:        true,
			},
			{
				ID:           "endoflife:npm:react:react:18",
				Ecosystem:    "npm",
				Name:         "react",
				ProductSlug:  "react",
				ProductLabel: "React",
				Cycle:        "18",
				Latest:       "18.3.1",
				IsMaintained: true,
			},
			{
				ID:           "endoflife:pypi:flask:flask:3",
				Ecosystem:    "pypi",
				Name:         "flask",
				ProductSlug:  "flask",
				ProductLabel: "Flask",
				Cycle:        "3",
				Latest:       "3.0.0",
				IsEOL:        true,
			},
		},
	}
	if _, err := applySync(ctx, store, true, resp); err != nil {
		t.Fatalf("applySync() error = %v", err)
	}

	chunks := localPackagePredicateChunks([]db.PackageQuery{
		{Ecosystem: "pypi", Name: "django", Version: "4.2.1"},
		{Ecosystem: "npm", Name: "react", Version: "18.2.0"},
	}, localPackagePredicateChunkSize)
	if len(chunks) != 1 {
		t.Fatalf("localPackagePredicateChunks() returned %d chunks, want 1", len(chunks))
	}

	rowsByPackage := make(map[localPackageKey][]lifecyclepolicy.ReleaseRow)
	if err := store.collectLifecycleReleaseRows(ctx, chunks[0], rowsByPackage); err != nil {
		t.Fatalf("collectLifecycleReleaseRows() error = %v", err)
	}
	if got := rowsByPackage[localPackageKey{ecosystem: "pypi", name: "django"}]; len(got) != 1 || got[0].ID != "endoflife:pypi:django:django:4.2" {
		t.Fatalf("django rows = %+v, want requested django row", got)
	}
	if got := rowsByPackage[localPackageKey{ecosystem: "npm", name: "react"}]; len(got) != 1 || got[0].ID != "endoflife:npm:react:react:18" {
		t.Fatalf("react rows = %+v, want requested react row", got)
	}
	if got := rowsByPackage[localPackageKey{ecosystem: "pypi", name: "flask"}]; len(got) != 0 {
		t.Fatalf("flask rows = %+v, want unrequested package excluded", got)
	}
}

func TestFindLifecycleFindingsBatchErrorIncludesPackageContext(t *testing.T) {
	t.Parallel()

	store, err := New(t.TempDir() + "/packmon.db")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	_, err = store.FindLifecycleFindingsBatch(context.Background(), []db.PackageQuery{{
		Ecosystem: "npm",
		Name:      "django",
		Version:   "4.2.0",
	}}, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	if err == nil {
		t.Fatal("FindLifecycleFindingsBatch() error = nil, want closed-store error")
	}
	if !strings.Contains(err.Error(), "npm/django") {
		t.Fatalf("FindLifecycleFindingsBatch() error = %v, want package context", err)
	}
}

func assertSQLiteLifecycleFinding(t *testing.T, finding domain.Finding, typ domain.FindingType, severity domain.Severity, riskType string) {
	t.Helper()

	if finding.Type != typ || finding.Severity != severity || finding.RiskType != riskType {
		t.Fatalf("finding for %s = type %s severity %s risk %s, want type %s severity %s risk %s",
			finding.Version, finding.Type, finding.Severity, finding.RiskType, typ, severity, riskType)
	}
	if finding.Source != "endoflife.date" || finding.AdvisoryID == "" || finding.URL == "" {
		t.Fatalf("finding identity/source = %+v", finding)
	}
}

func TestSyncErrorBranches(t *testing.T) {
	t.Parallel()

	store := newSQLiteTestStore(t)
	if err := Sync(context.Background(), store, SyncConfig{}); err == nil || !strings.Contains(err.Error(), "no server URL") {
		t.Fatalf("Sync(no server) error = %v", err)
	}
	if err := Sync(context.Background(), store, SyncConfig{ServerURL: "://bad"}); err == nil || !strings.Contains(err.Error(), "parse server URL") {
		t.Fatalf("Sync(bad URL) error = %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, strings.Repeat("x", 250), http.StatusBadGateway)
	}))
	defer server.Close()
	if err := Sync(context.Background(), store, SyncConfig{ServerURL: server.URL, Full: true, AllowInsecureHTTP: true}); err == nil || !strings.Contains(err.Error(), "server returned 502") || !strings.Contains(err.Error(), "...") {
		t.Fatalf("Sync(server error) = %v", err)
	}

	truncated := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"truncated":true}`))
	}))
	defer truncated.Close()
	if err := Sync(context.Background(), store, SyncConfig{ServerURL: truncated.URL, Full: true, AllowInsecureHTTP: true}); err == nil || !strings.Contains(err.Error(), "truncated response missing synced_at") {
		t.Fatalf("Sync(truncated without snapshot) = %v", err)
	}

	invalidJSON := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`not json`))
	}))
	defer invalidJSON.Close()
	if err := Sync(context.Background(), store, SyncConfig{ServerURL: invalidJSON.URL, Full: true, AllowInsecureHTTP: true}); err == nil || !strings.Contains(err.Error(), "decode response") {
		t.Fatalf("Sync(invalid JSON) = %v", err)
	}
}

func TestSyncRetriesRateLimitedPage(t *testing.T) {
	t.Parallel()

	store := newSQLiteTestStore(t)
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		if requests == 1 {
			w.Header().Set("Retry-After", "0")
			http.Error(w, `{"error":"rate limit exceeded"}`, http.StatusTooManyRequests)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"synced_at":"2026-05-30T11:00:00Z","synced_xid":600,"feed_status":"healthy"}`))
	}))
	defer server.Close()

	if err := Sync(context.Background(), store, SyncConfig{ServerURL: server.URL, Full: true, AllowInsecureHTTP: true}); err != nil {
		t.Fatalf("Sync(rate limited once) error = %v", err)
	}
	if requests != 2 {
		t.Fatalf("requests = %d, want retry after one 429", requests)
	}
}

func TestSyncRetryAfterWaitHonorsConfiguredTimeout(t *testing.T) {
	store := newSQLiteTestStore(t)
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		if requests == 1 {
			w.Header().Set("Retry-After", "1")
			http.Error(w, `{"error":"rate limit exceeded"}`, http.StatusTooManyRequests)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"synced_at":"2026-05-30T11:00:00Z","synced_xid":600,"feed_status":"healthy"}`))
	}))
	defer server.Close()

	start := time.Now()
	err := Sync(context.Background(), store, SyncConfig{
		ServerURL:         server.URL,
		Full:              true,
		AllowInsecureHTTP: true,
		Timeout:           50 * time.Millisecond,
	})
	elapsed := time.Since(start)

	if err == nil || !strings.Contains(err.Error(), "context cancelled during rate limit wait") {
		t.Fatalf("Sync(long Retry-After) error = %v, want rate limit wait cancelled by timeout", err)
	}
	if requests != 1 {
		t.Fatalf("requests = %d, want no retry after timeout", requests)
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("Sync(long Retry-After) took %s, want timeout to stop wait before Retry-After", elapsed)
	}
}

func TestSyncRejectsPlainHTTPWithoutExplicitOptIn(t *testing.T) {
	t.Parallel()

	store := newSQLiteTestStore(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatal("Sync sent request over plain HTTP without opt-in")
	}))
	defer server.Close()

	err := Sync(context.Background(), store, SyncConfig{ServerURL: server.URL, APIKey: "secret"})
	if err == nil || !strings.Contains(err.Error(), "refusing to use insecure server URL") {
		t.Fatalf("Sync(insecure HTTP) error = %v", err)
	}
}

func TestSyncServerURLErrorsRedactSecretBearingURLValues(t *testing.T) {
	t.Parallel()

	rawURL := "http://user:server-secret@example.test/private?token=query-secret" //nolint:gosec // fake credential-bearing URL verifies redaction.
	store := newSQLiteTestStore(t)
	err := Sync(context.Background(), store, SyncConfig{ServerURL: rawURL})
	if err == nil || !strings.Contains(err.Error(), "refusing to use insecure server URL") {
		t.Fatalf("Sync(insecure secret URL) error = %v", err)
	}
	assertNoSecretURLLeak(t, err.Error())

	client := &http.Client{Transport: syncRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		return nil, &url.Error{
			Op:  "Get",
			URL: req.URL.String(),
			Err: errors.New("dial tcp: token=query-secret"),
		}
	})}
	_, err = fetchSyncPage(context.Background(), client, SyncConfig{
		ServerURL:         rawURL,
		AllowInsecureHTTP: true,
	}, "", "", syncCursor{}, "", "")
	if err == nil || !strings.Contains(err.Error(), "sync: server request") {
		t.Fatalf("fetchSyncPage(secret URL request error) = %v", err)
	}
	assertNoSecretURLLeak(t, err.Error())
}

func assertNoSecretURLLeak(t *testing.T, message string) {
	t.Helper()
	for _, leaked := range []string{"server-secret", "query-secret", "/private", "token=query-secret"} {
		if strings.Contains(message, leaked) {
			t.Fatalf("error leaked %q in %q", leaked, message)
		}
	}
}

func TestSyncIncrementalUsesSinceAuthorizationAndEcosystems(t *testing.T) {
	t.Parallel()

	store := newSQLiteTestStore(t)
	ctx := context.Background()
	const since = "2026-05-30T10:00:00Z"
	if err := store.SetSyncMeta(ctx, syncMetaKeyLastSync, since); err != nil {
		t.Fatalf("SetSyncMeta() error = %v", err)
	}
	if err := store.SetSyncMeta(ctx, syncMetaKeyLastSyncXID, "500"); err != nil {
		t.Fatalf("SetSyncMeta(xid) error = %v", err)
	}

	var gotSince, gotSinceXID, gotAuth, gotEcosystem string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSince = r.URL.Query().Get("since")
		gotSinceXID = r.URL.Query().Get("since_xid")
		gotAuth = r.Header.Get("Authorization")
		gotEcosystem = r.URL.Query().Get("ecosystem")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"synced_at":"2026-05-30T11:00:00Z","synced_xid":600}`))
	}))
	defer server.Close()

	if err := Sync(ctx, store, SyncConfig{
		ServerURL:         server.URL,
		APIKey:            "sync-key",
		Ecosystems:        []string{"npm", "go"},
		AllowInsecureHTTP: true,
	}); err != nil {
		t.Fatalf("Sync(incremental) error = %v", err)
	}
	if gotSince != since || gotSinceXID != "500" || gotAuth != "Bearer sync-key" || gotEcosystem != "npm,go" {
		t.Fatalf("request since=%q since_xid=%q auth=%q ecosystem=%q", gotSince, gotSinceXID, gotAuth, gotEcosystem)
	}
	lastSync, err := store.GetSyncMeta(ctx, syncMetaKeyLastSync)
	if err != nil {
		t.Fatalf("GetSyncMeta() error = %v", err)
	}
	if lastSync != "2026-05-30T11:00:00Z" {
		t.Fatalf("last sync = %q, want updated snapshot", lastSync)
	}
	lastXID, err := store.GetSyncMeta(ctx, syncMetaKeyLastSyncXID)
	if err != nil {
		t.Fatalf("GetSyncMeta(xid) error = %v", err)
	}
	if lastXID != "600" {
		t.Fatalf("last sync xid = %q, want 600", lastXID)
	}
}

func TestSyncSendsStableCorrelationIDAcrossPaginatedRequests(t *testing.T) {
	t.Parallel()

	store := newSQLiteTestStore(t)
	ctx := context.Background()
	var correlationIDs []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		correlationIDs = append(correlationIDs, r.Header.Get(correlation.Header))
		w.Header().Set("Content-Type", "application/json")
		if len(correlationIDs) == 1 {
			_, _ = w.Write([]byte(`{"synced_at":"2026-05-30T11:00:00Z","synced_xid":600,"truncated":true,"next_cursor":{"vulnerabilities_done":true,"malicious_done":true,"reputation_done":true,"lifecycle_done":true}}`))
			return
		}
		_, _ = w.Write([]byte(`{"synced_at":"2026-05-30T11:00:00Z","synced_xid":600}`))
	}))
	defer server.Close()

	if err := Sync(ctx, store, SyncConfig{
		ServerURL:         server.URL,
		AllowInsecureHTTP: true,
	}); err != nil {
		t.Fatalf("Sync(paginated) error = %v", err)
	}

	if len(correlationIDs) != 2 {
		t.Fatalf("sync requests = %d, want 2", len(correlationIDs))
	}
	if !correlation.Valid(correlationIDs[0]) || !correlation.Valid(correlationIDs[1]) {
		t.Fatalf("sync correlation IDs = %q, want valid UUID-shaped IDs", correlationIDs)
	}
	if correlationIDs[0] != correlationIDs[1] {
		t.Fatalf("sync correlation IDs = %q, want stable ID across one sync", correlationIDs)
	}
}

func TestSyncSerializesConcurrentCallsForSameDatabasePath(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	dbPath := filepath.Join(t.TempDir(), "packmon.db")
	firstStore, err := New(dbPath)
	if err != nil {
		t.Fatalf("New(first) error = %v", err)
	}
	t.Cleanup(func() { _ = firstStore.Close() })
	secondStore, err := New(dbPath)
	if err != nil {
		t.Fatalf("New(second) error = %v", err)
	}
	t.Cleanup(func() { _ = secondStore.Close() })

	firstRequestStarted := make(chan struct{})
	allowFirstResponse := make(chan struct{})
	secondRequestDone := make(chan struct{})
	var closeFirstOnce sync.Once
	var closeSecondOnce sync.Once
	var mu sync.Mutex
	requests := make([]string, 0, 2)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		since := r.URL.Query().Get("since")
		mu.Lock()
		requests = append(requests, since)
		requestNumber := len(requests)
		mu.Unlock()

		if requestNumber == 1 {
			closeFirstOnce.Do(func() { close(firstRequestStarted) })
			select {
			case <-allowFirstResponse:
			case <-r.Context().Done():
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"synced_at":"2026-05-30T11:00:00Z","synced_xid":600}`))
			return
		}

		closeSecondOnce.Do(func() { close(secondRequestDone) })
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"synced_at":"2026-05-30T12:00:00Z","synced_xid":700}`))
	}))
	defer server.Close()

	firstErr := make(chan error, 1)
	go func() {
		firstErr <- Sync(ctx, firstStore, SyncConfig{
			ServerURL:         server.URL,
			AllowInsecureHTTP: true,
		})
	}()

	select {
	case <-firstRequestStarted:
	case <-time.After(10 * time.Second):
		t.Fatal("first sync did not reach server")
	}

	secondErr := make(chan error, 1)
	go func() {
		secondErr <- Sync(ctx, secondStore, SyncConfig{
			ServerURL:         server.URL,
			AllowInsecureHTTP: true,
		})
	}()

	select {
	case <-secondRequestDone:
		close(allowFirstResponse)
		<-firstErr
		<-secondErr
		t.Fatal("second sync reached server before first sync completed")
	case <-time.After(100 * time.Millisecond):
	}

	close(allowFirstResponse)
	if err := <-firstErr; err != nil {
		t.Fatalf("first Sync() error = %v", err)
	}
	if err := <-secondErr; err != nil {
		t.Fatalf("second Sync() error = %v", err)
	}

	mu.Lock()
	gotRequests := append([]string(nil), requests...)
	mu.Unlock()
	if len(gotRequests) != 2 {
		t.Fatalf("sync requests = %+v, want two requests", gotRequests)
	}
	if gotRequests[0] != "" || gotRequests[1] != "2026-05-30T11:00:00Z" {
		t.Fatalf("sync request since values = %+v, want second request to observe first sync metadata", gotRequests)
	}

	lastSync, err := firstStore.GetSyncMeta(ctx, syncMetaKeyLastSync)
	if err != nil {
		t.Fatalf("GetSyncMeta(last sync) error = %v", err)
	}
	if lastSync != "2026-05-30T12:00:00Z" {
		t.Fatalf("last sync = %q, want second sync timestamp", lastSync)
	}
}

func TestSyncStoresFeedStateMetadata(t *testing.T) {
	t.Parallel()

	store := newSQLiteTestStore(t)
	ctx := context.Background()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"synced_at":"2026-05-30T11:00:00Z",
			"synced_xid":600,
			"feed_status":"degraded",
			"feed_versions":{"osv":"2026-05-30T10:00:00Z","ghsa":"2026-05-30T10:30:00Z"}
		}`))
	}))
	defer server.Close()

	if err := Sync(ctx, store, SyncConfig{
		ServerURL:         server.URL,
		Full:              true,
		AllowInsecureHTTP: true,
	}); err != nil {
		t.Fatalf("Sync(full) error = %v", err)
	}

	status, err := store.GetSyncMeta(ctx, syncMetaKeyFeedStatus)
	if err != nil {
		t.Fatalf("GetSyncMeta(feed status) error = %v", err)
	}
	if status != "degraded" {
		t.Fatalf("feed status meta = %q, want degraded", status)
	}

	rawVersions, err := store.GetSyncMeta(ctx, syncMetaKeyFeedVersions)
	if err != nil {
		t.Fatalf("GetSyncMeta(feed versions) error = %v", err)
	}
	var versions map[string]string
	if err := json.Unmarshal([]byte(rawVersions), &versions); err != nil {
		t.Fatalf("decode feed versions meta: %v", err)
	}
	if versions["osv"] != "2026-05-30T10:00:00Z" || versions["ghsa"] != "2026-05-30T10:30:00Z" {
		t.Fatalf("feed versions meta = %+v", versions)
	}
}

func TestSyncRollsBackFindingWritesWhenFeedMetadataFails(t *testing.T) {
	t.Parallel()

	store := newSQLiteTestStore(t)
	ctx := context.Background()
	if _, err := applySync(ctx, store, true, &syncResponse{
		Vulnerabilities: []syncVulnerability{{
			ID:               "GHSA-existing-metadata-failure",
			Ecosystem:        "npm",
			Name:             "existing-metadata-failure",
			VersionRanges:    `[{"type":"SEMVER","events":[{"introduced":"0"}]}]`,
			VersionsAffected: `[]`,
			Severity:         "HIGH",
			Summary:          "existing vulnerability",
		}},
	}); err != nil {
		t.Fatalf("applySync(existing) error = %v", err)
	}
	if err := store.SetSyncMeta(ctx, syncMetaKeyLastSync, "2026-05-30T09:00:00Z"); err != nil {
		t.Fatalf("SetSyncMeta(last sync) error = %v", err)
	}
	if err := store.SetSyncMeta(ctx, syncMetaKeyLastSyncXID, "500"); err != nil {
		t.Fatalf("SetSyncMeta(last xid) error = %v", err)
	}
	if err := store.SetSyncMeta(ctx, syncMetaKeyFeedStatus, "healthy"); err != nil {
		t.Fatalf("SetSyncMeta(feed status) error = %v", err)
	}
	if _, err := store.DB().ExecContext(ctx, `
		CREATE TRIGGER sync_meta_fail_feed_versions_insert
		BEFORE INSERT ON sync_meta
		WHEN NEW.key = 'feed_versions'
		BEGIN
			SELECT RAISE(FAIL, 'forced feed versions failure');
		END;
		CREATE TRIGGER sync_meta_fail_feed_versions_update
		BEFORE UPDATE OF value ON sync_meta
		WHEN NEW.key = 'feed_versions'
		BEGIN
			SELECT RAISE(FAIL, 'forced feed versions failure');
		END;
	`); err != nil {
		t.Fatalf("create failing feed metadata trigger: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"synced_at":"2026-05-30T11:00:00Z",
			"synced_xid":600,
			"feed_status":"degraded",
			"feed_versions":{"osv":"2026-05-30T10:00:00Z"},
			"vulnerabilities":[{
				"id":"GHSA-new-metadata-failure",
				"ecosystem":"npm",
				"name":"new-metadata-failure",
				"version_ranges":"[{\"type\":\"SEMVER\",\"events\":[{\"introduced\":\"0\"}]}]",
				"versions_affected":"[]",
				"severity":"CRITICAL",
				"summary":"new vulnerability"
			}]
		}`))
	}))
	defer server.Close()

	var stats SyncStats
	err := Sync(ctx, store, SyncConfig{
		ServerURL:         server.URL,
		Full:              true,
		AllowInsecureHTTP: true,
		Stats:             &stats,
	})
	if err == nil || !strings.Contains(err.Error(), "store feed versions") {
		t.Fatalf("Sync(feed metadata failure) error = %v, want feed versions storage error", err)
	}

	existing, err := store.FindVulnerabilities(ctx, "npm", "existing-metadata-failure", "1.0.0")
	if err != nil {
		t.Fatalf("FindVulnerabilities(existing) error = %v", err)
	}
	if len(existing) != 1 || existing[0].AdvisoryID != "GHSA-existing-metadata-failure" {
		t.Fatalf("existing findings after metadata failure = %+v, want preserved existing finding", existing)
	}
	newRows, err := store.FindVulnerabilities(ctx, "npm", "new-metadata-failure", "1.0.0")
	if err != nil {
		t.Fatalf("FindVulnerabilities(new) error = %v", err)
	}
	if len(newRows) != 0 {
		t.Fatalf("new findings after metadata failure = %+v, want rollback", newRows)
	}
	lastSync, err := store.GetSyncMeta(ctx, syncMetaKeyLastSync)
	if err != nil {
		t.Fatalf("GetSyncMeta(last sync) error = %v", err)
	}
	if lastSync != "2026-05-30T09:00:00Z" {
		t.Fatalf("last sync after metadata failure = %q, want previous timestamp", lastSync)
	}
	lastXID, err := store.GetSyncMeta(ctx, syncMetaKeyLastSyncXID)
	if err != nil {
		t.Fatalf("GetSyncMeta(last xid) error = %v", err)
	}
	if lastXID != "500" {
		t.Fatalf("last xid after metadata failure = %q, want previous xid", lastXID)
	}
	feedStatus, err := store.GetSyncMeta(ctx, syncMetaKeyFeedStatus)
	if err != nil {
		t.Fatalf("GetSyncMeta(feed status) error = %v", err)
	}
	if feedStatus != "healthy" {
		t.Fatalf("feed status after metadata failure = %q, want previous status", feedStatus)
	}
	if stats.AnyRemoved() {
		t.Fatalf("stats after failed sync = %+v, want zero-value stats", stats)
	}
}

func TestSyncFullRejectsEmptySnapshotBeforeClearingLocalData(t *testing.T) {
	t.Parallel()

	store := newSQLiteTestStore(t)
	ctx := context.Background()
	if _, err := applySync(ctx, store, true, &syncResponse{
		Vulnerabilities: []syncVulnerability{{
			ID:               "GHSA-existing-empty-full",
			Ecosystem:        "npm",
			Name:             "existing-empty-full",
			VersionRanges:    `[{"type":"SEMVER","events":[{"introduced":"0"}]}]`,
			VersionsAffected: `[]`,
			Severity:         "HIGH",
			Summary:          "existing vulnerability",
		}},
	}); err != nil {
		t.Fatalf("applySync(existing) error = %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	err := Sync(ctx, store, SyncConfig{
		ServerURL:         server.URL,
		Full:              true,
		AllowInsecureHTTP: true,
	})
	if err == nil || !strings.Contains(err.Error(), "response missing synced_at") {
		t.Fatalf("Sync(empty full snapshot) error = %v, want missing synced_at", err)
	}

	findings, err := store.FindVulnerabilities(ctx, "npm", "existing-empty-full", "1.0.0")
	if err != nil {
		t.Fatalf("FindVulnerabilities() error = %v", err)
	}
	if len(findings) != 1 || findings[0].AdvisoryID != "GHSA-existing-empty-full" {
		t.Fatalf("existing findings after rejected full sync = %+v", findings)
	}
}

func TestSyncRejectsFilteredFullSync(t *testing.T) {
	t.Parallel()

	store := newSQLiteTestStore(t)
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("filtered full sync should fail before contacting server")
	}))
	defer server.Close()

	err := Sync(context.Background(), store, SyncConfig{
		ServerURL:         server.URL,
		Full:              true,
		Ecosystems:        []string{"npm"},
		AllowInsecureHTTP: true,
	})
	if err == nil || !strings.Contains(err.Error(), "filtered full sync") {
		t.Fatalf("Sync(filtered full) error = %v, want clear rejection", err)
	}
}

func TestSyncStatsReportFullClearAndTombstoneDeletes(t *testing.T) {
	store := newSQLiteTestStore(t)
	ctx := context.Background()
	seedLocalSyncRows(t, store)

	fullServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"synced_at":"2026-05-30T10:00:00Z","feed_status":"healthy"}`))
	}))
	defer fullServer.Close()

	var fullStats SyncStats
	if err := Sync(ctx, store, SyncConfig{
		ServerURL:         fullServer.URL,
		Full:              true,
		AllowInsecureHTTP: true,
		Stats:             &fullStats,
	}); err != nil {
		t.Fatalf("Sync(full) error = %v", err)
	}
	if fullStats.FullCleared != (SyncRemovalStats{Vulnerabilities: 1, Malicious: 1, Reputation: 1, Lifecycle: 1}) {
		t.Fatalf("full clear stats = %+v", fullStats.FullCleared)
	}
	if fullStats.TombstoneDeleted.Any() {
		t.Fatalf("tombstone stats after full clear = %+v, want zero", fullStats.TombstoneDeleted)
	}

	seedLocalSyncRows(t, store)
	tombstoneServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"synced_at":"2026-05-30T11:00:00Z",
			"vulnerabilities":[{"id":"GHSA-existing","withdrawn":true}],
			"malicious":[{"id":"MAL-existing","withdrawn":true}],
			"reputation":[{"id":"REP-existing","withdrawn":true}],
			"lifecycle":[{"id":"LIFE-existing","withdrawn":true}]
		}`))
	}))
	defer tombstoneServer.Close()

	var tombstoneStats SyncStats
	if err := Sync(ctx, store, SyncConfig{
		ServerURL:         tombstoneServer.URL,
		AllowInsecureHTTP: true,
		Stats:             &tombstoneStats,
	}); err != nil {
		t.Fatalf("Sync(tombstones) error = %v", err)
	}
	if tombstoneStats.TombstoneDeleted != (SyncRemovalStats{Vulnerabilities: 1, Malicious: 1, Reputation: 1, Lifecycle: 1}) {
		t.Fatalf("tombstone stats = %+v", tombstoneStats.TombstoneDeleted)
	}
	if tombstoneStats.FullCleared.Any() {
		t.Fatalf("full clear stats after tombstones = %+v, want zero", tombstoneStats.FullCleared)
	}
}

func seedLocalSyncRows(t *testing.T, store *Store) {
	t.Helper()
	if _, err := store.DB().ExecContext(context.Background(), `
		DELETE FROM vulnerabilities_local;
		DELETE FROM malicious_local;
		DELETE FROM reputation_findings_local;
		DELETE FROM lifecycle_releases_local;
		INSERT INTO vulnerabilities_local(row_key, id, ecosystem, name, version_ranges, severity)
		VALUES('GHSA-existing|npm|left-pad', 'GHSA-existing', 'npm', 'left-pad', '[]', 'LOW');
		INSERT INTO malicious_local(id, ecosystem, name, risk_type, severity)
		VALUES('MAL-existing', 'npm', 'evil', 'malware', 'CRITICAL');
		INSERT INTO reputation_findings_local(id, ecosystem, name, version, type, risk_type, severity)
		VALUES('REP-existing', 'npm', 'removed', '1.0.0', 'supply_chain_risk', 'removed_package', 'LOW');
		INSERT INTO lifecycle_releases_local(id, ecosystem, name, product_slug, product_label, cycle, is_eol)
		VALUES('LIFE-existing', 'npm', 'oldlib', 'oldlib', 'oldlib', '1.0', 1);
	`); err != nil {
		t.Fatalf("seed local sync rows: %v", err)
	}
}

func TestSyncFullFailureAfterFirstPageDoesNotAdvanceFreshnessMetadata(t *testing.T) {
	t.Parallel()

	store := newSQLiteTestStore(t)
	ctx := context.Background()
	if _, err := applySync(ctx, store, true, &syncResponse{
		Vulnerabilities: []syncVulnerability{{
			ID:               "GHSA-existing",
			Ecosystem:        "npm",
			Name:             "existing",
			VersionRanges:    `[{"type":"SEMVER","events":[{"introduced":"0"}]}]`,
			VersionsAffected: `[]`,
			Severity:         "HIGH",
			Summary:          "existing vulnerability",
		}},
	}); err != nil {
		t.Fatalf("applySync(existing) error = %v", err)
	}
	if err := store.SetSyncMeta(ctx, syncMetaKeyLastSync, "2026-05-30T09:00:00Z"); err != nil {
		t.Fatalf("SetSyncMeta(existing) error = %v", err)
	}

	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if requests == 1 {
			if got := r.URL.Query().Get("since"); got != "" {
				t.Fatalf("first full-sync request since = %q, want empty", got)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"synced_at":"2026-05-30T10:00:00Z",
				"truncated":true,
				"next_cursor":{"vulnerabilities":1},
				"vulnerabilities":[{
					"id":"GHSA-new",
					"ecosystem":"npm",
					"name":"new",
					"version_ranges":"[{\"type\":\"SEMVER\",\"events\":[{\"introduced\":\"0\"}]}]",
					"versions_affected":"[]",
					"severity":"CRITICAL",
					"summary":"new vulnerability"
				}]
			}`))
			return
		}
		http.Error(w, "second page failed", http.StatusBadGateway)
	}))
	defer server.Close()

	err := Sync(ctx, store, SyncConfig{ServerURL: server.URL, Full: true, AllowInsecureHTTP: true})
	if err == nil || !strings.Contains(err.Error(), "server returned 502") {
		t.Fatalf("Sync(second page failure) error = %v", err)
	}
	if requests != 2 {
		t.Fatalf("requests = %d, want 2", requests)
	}

	existing, err := store.FindVulnerabilities(ctx, "npm", "existing", "1.0.0")
	if err != nil {
		t.Fatalf("FindVulnerabilities(existing) error = %v", err)
	}
	if len(existing) != 0 {
		t.Fatalf("existing findings after failed full sync = %+v, want cleared by first page", existing)
	}
	newRows, err := store.FindVulnerabilities(ctx, "npm", "new", "1.0.0")
	if err != nil {
		t.Fatalf("FindVulnerabilities(new) error = %v", err)
	}
	if len(newRows) != 1 || newRows[0].AdvisoryID != "GHSA-new" {
		t.Fatalf("new findings after failed full sync = %+v, want first page retained", newRows)
	}
	lastSync, err := store.GetSyncMeta(ctx, syncMetaKeyLastSync)
	if err != nil {
		t.Fatalf("GetSyncMeta() error = %v", err)
	}
	if lastSync != "2026-05-30T09:00:00Z" {
		t.Fatalf("last sync after failed full sync = %q, want previous timestamp", lastSync)
	}
}

func TestSyncDoesNotMarkFutureSyncedAtFresh(t *testing.T) {
	t.Parallel()

	store := newSQLiteTestStore(t)
	ctx := context.Background()
	previousSync := time.Now().UTC().Add(-24 * time.Hour).Format(time.RFC3339Nano)
	if err := store.SetSyncMeta(ctx, syncMetaKeyLastSync, previousSync); err != nil {
		t.Fatalf("SetSyncMeta(last sync) error = %v", err)
	}
	if err := store.SetSyncMeta(ctx, syncMetaKeyLastSyncXID, "123"); err != nil {
		t.Fatalf("SetSyncMeta(last xid) error = %v", err)
	}

	futureSync := time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339Nano)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("since"); got != previousSync {
			t.Fatalf("since = %q, want previous sync %q", got, previousSync)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"synced_at":"` + futureSync + `",
			"synced_xid":999,
			"vulnerabilities":[{
				"id":"GHSA-future-sync",
				"ecosystem":"npm",
				"name":"future-sync",
				"version_ranges":"[{\"type\":\"SEMVER\",\"events\":[{\"introduced\":\"0\"}]}]",
				"versions_affected":"[]",
				"severity":"LOW",
				"summary":"future synced_at should not mark freshness"
			}]
		}`))
	}))
	defer server.Close()

	if err := Sync(ctx, store, SyncConfig{ServerURL: server.URL, AllowInsecureHTTP: true}); err != nil {
		t.Fatalf("Sync() error = %v", err)
	}

	findings, err := store.FindVulnerabilities(ctx, "npm", "future-sync", "1.0.0")
	if err != nil {
		t.Fatalf("FindVulnerabilities() error = %v", err)
	}
	if len(findings) != 1 || findings[0].AdvisoryID != "GHSA-future-sync" {
		t.Fatalf("synced findings = %+v, want applied future-sync row", findings)
	}
	lastSync, err := store.GetSyncMeta(ctx, syncMetaKeyLastSync)
	if err != nil {
		t.Fatalf("GetSyncMeta(last sync) error = %v", err)
	}
	if lastSync != previousSync {
		t.Fatalf("last sync = %q, want preserved %q", lastSync, previousSync)
	}
	lastXID, err := store.GetSyncMeta(ctx, syncMetaKeyLastSyncXID)
	if err != nil {
		t.Fatalf("GetSyncMeta(last xid) error = %v", err)
	}
	if lastXID != "123" {
		t.Fatalf("last sync xid = %q, want preserved 123", lastXID)
	}
}

func TestFetchSyncPageReadErrorIncludesContext(t *testing.T) {
	t.Parallel()

	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("Authorization") != "Bearer read-key" || r.URL.Query().Get("vulnerabilities_cursor") != "after-vuln" || r.URL.Query().Get("snapshot") != "snap" {
			t.Fatalf("request headers/query = auth %q raw %q", r.Header.Get("Authorization"), r.URL.RawQuery)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       errReadCloser{},
			Header:     make(http.Header),
		}, nil
	})}

	_, err := fetchSyncPage(context.Background(), client, SyncConfig{
		ServerURL: "https://packmon.example",
		APIKey:    "read-key",
	}, "2026-05-30T10:00:00Z", "500", syncCursor{VulnerabilitiesCursor: "after-vuln"}, "snap", "600")
	if err == nil || !strings.Contains(err.Error(), "read response") {
		t.Fatalf("fetchSyncPage(read error) = %v", err)
	}
}

func TestFetchSyncPageRejectsOversizedResponses(t *testing.T) {
	t.Parallel()

	for name, status := range map[string]int{
		"success": http.StatusOK,
		"error":   http.StatusBadGateway,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(status)
				_, _ = w.Write([]byte(strings.Repeat("x", maxSyncResponseSize+1)))
			}))
			defer server.Close()

			_, err := fetchSyncPage(context.Background(), server.Client(), SyncConfig{
				ServerURL:         server.URL,
				AllowInsecureHTTP: true,
			}, "", "", syncCursor{}, "", "")
			if err == nil || !strings.Contains(err.Error(), "response too large") {
				t.Fatalf("fetchSyncPage(%s) error = %v, want response too large", name, err)
			}
		})
	}
}

func TestFetchSyncPageErrorSnippetTruncatesOnUTF8Boundary(t *testing.T) {
	t.Parallel()

	body := strings.Repeat("x", 199) + "ä" + strings.Repeat("y", 20)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()

	_, err := fetchSyncPage(context.Background(), server.Client(), SyncConfig{
		ServerURL:         server.URL,
		AllowInsecureHTTP: true,
	}, "", "", syncCursor{}, "", "")
	if err == nil || !strings.Contains(err.Error(), "server returned 502") {
		t.Fatalf("fetchSyncPage(non-200) error = %v, want status context", err)
	}
	if !utf8.ValidString(err.Error()) {
		t.Fatalf("fetchSyncPage(non-200) error is invalid UTF-8: %q", err.Error())
	}
	if !strings.Contains(err.Error(), "ä") {
		t.Fatalf("fetchSyncPage(non-200) error = %q, want readable multibyte diagnostic", err.Error())
	}
}

func TestFetchSyncPageErrorSnippetRedactsResponseBodySecrets(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "failed Authorization: Bearer leaked-sync-token api_key=leaked-sync-query", http.StatusInternalServerError)
	}))
	defer server.Close()

	_, err := fetchSyncPage(context.Background(), server.Client(), SyncConfig{
		ServerURL:         server.URL,
		AllowInsecureHTTP: true,
	}, "", "", syncCursor{}, "", "")
	if err == nil {
		t.Fatal("fetchSyncPage(non-200) error = nil, want status error")
	}
	msg := err.Error()
	for _, want := range []string{
		"server returned 500",
		"Bearer [redacted]",
		"api_key=[redacted]",
	} {
		if !strings.Contains(msg, want) {
			t.Fatalf("fetchSyncPage(non-200) error missing %q: %s", want, msg)
		}
	}
	for _, leaked := range []string{"leaked-sync-token", "leaked-sync-query"} {
		if strings.Contains(msg, leaked) {
			t.Fatalf("fetchSyncPage(non-200) error leaked %q: %s", leaked, msg)
		}
	}
}

func TestSQLiteSyncHelpersAndWebNoops(t *testing.T) {
	t.Parallel()

	if got := truncate("short", 10); got != "short" {
		t.Fatalf("truncate short = %q", got)
	}
	if got := truncate("abcdef", 3); got != "abc..." {
		t.Fatalf("truncate long = %q", got)
	}
	if got := syncVulnerabilityRowKey("GHSA", "npm", "left-pad"); got != "GHSA|npm|left-pad" {
		t.Fatalf("syncVulnerabilityRowKey = %q", got)
	}

	store := newSQLiteTestStore(t)
	statuses, err := store.ListFeedSyncStatuses(context.Background())
	if err != nil || len(statuses) != 0 {
		t.Fatalf("ListFeedSyncStatuses() = %+v, %v; want empty nil", statuses, err)
	}
	recent, err := store.ListRecentVulnerabilities(context.Background(), 7, 10)
	if err != nil || len(recent) != 0 {
		t.Fatalf("ListRecentVulnerabilities() = %+v, %v; want empty nil", recent, err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

type errReadCloser struct{}

func (errReadCloser) Read([]byte) (int, error) {
	return 0, errors.New("forced read error")
}

func (errReadCloser) Close() error {
	return nil
}
