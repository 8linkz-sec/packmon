//go:build integration

package integration

import (
	"archive/zip"
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/domain"
	"github.com/8linkz-sec/packmon/internal/feed/osv"
)

func TestOSVSyncerWritesVulnerabilitiesToPostgres(t *testing.T) {
	store := startPostgresStore(t)
	ctx := context.Background()

	entry := []byte(`{
		"id":"GHSA-packmon-osv-syncer-test",
		"summary":"OSV syncer integration vulnerability",
		"details":"Integration fixture served from httptest.",
		"aliases":["CVE-2026-4560"],
		"modified":"2026-06-29T08:00:00Z",
		"published":"2026-06-29T07:00:00Z",
		"severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
		"affected":[{
			"package":{"ecosystem":"npm","name":"packmon-osv-syncer-fixture"},
			"versions":[],
			"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.2.0"}]}]
		}],
		"references":[{"type":"ADVISORY","url":"https://example.test/advisories/GHSA-packmon-osv-syncer-test"}]
	}`)
	archive := createOSVSyncerArchive(t, "GHSA-packmon-osv-syncer-test.json", entry)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/npm/all.zip" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("ETag", `"packmon-osv-syncer-test"`)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(archive)
	}))
	defer srv.Close()

	var logs bytes.Buffer
	syncer := osv.NewSyncer(
		slog.New(slog.NewTextHandler(&logs, nil)),
		osv.WithBaseURL(srv.URL),
		osv.WithHTTPClient(srv.Client()),
	)

	result, err := syncer.Sync(ctx, store)
	if err != nil {
		t.Fatalf("Sync() error = %v\nlogs:\n%s", err, logs.String())
	}
	if result == nil {
		t.Fatal("Sync() result = nil")
	}
	if result.EntriesSynced != 1 || result.EntriesTotal != 1 {
		t.Fatalf("Sync() result = %+v, want one synced OSV entry", result)
	}

	findings, err := store.FindVulnerabilities(ctx, "npm", "packmon-osv-syncer-fixture", "1.1.0")
	if err != nil {
		t.Fatalf("FindVulnerabilities() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("FindVulnerabilities() = %+v, want one persisted finding", findings)
	}
	finding := findings[0]
	if finding.AdvisoryID != "GHSA-packmon-osv-syncer-test" {
		t.Fatalf("AdvisoryID = %q, want GHSA-packmon-osv-syncer-test", finding.AdvisoryID)
	}
	if finding.Source != osv.FeedName {
		t.Fatalf("Source = %q, want %q", finding.Source, osv.FeedName)
	}
	if finding.Type != domain.FindingTypeVulnerability {
		t.Fatalf("Type = %q, want %q", finding.Type, domain.FindingTypeVulnerability)
	}

	status, err := store.GetFeedSyncStatus(ctx, osv.FeedName)
	if err != nil {
		t.Fatalf("GetFeedSyncStatus(%q) error = %v", osv.FeedName, err)
	}
	if status == nil {
		t.Fatalf("GetFeedSyncStatus(%q) = nil, want success status", osv.FeedName)
	}
	if status.LastSyncStatus != db.FeedSyncStatusSuccess {
		t.Fatalf("LastSyncStatus = %q, want %q", status.LastSyncStatus, db.FeedSyncStatusSuccess)
	}
	if status.EntriesSynced != 1 || status.EntriesTotal != 1 {
		t.Fatalf("feed sync status counts = synced %d total %d, want 1/1", status.EntriesSynced, status.EntriesTotal)
	}
}

func createOSVSyncerArchive(t *testing.T, name string, data []byte) []byte {
	t.Helper()

	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	f, err := w.Create(name)
	if err != nil {
		t.Fatalf("zip create %s: %v", name, err)
	}
	if _, err := f.Write(data); err != nil {
		t.Fatalf("zip write %s: %v", name, err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}
