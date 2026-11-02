//go:build integration

package postgres

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
)

func TestF133F138PostgresScanLogContracts(t *testing.T) {
	store, _ := startDockerPostgresStore(t)

	reset := func(t *testing.T) context.Context {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		t.Cleanup(cancel)
		if _, err := store.pool.Exec(ctx, `DELETE FROM scan_log; DELETE FROM admin_audit_log`); err != nil {
			t.Fatalf("reset scan-log contract fixture: %v", err)
		}
		return ctx
	}

	t.Run("decision_evidence_round_trip_exact", func(t *testing.T) {
		ctx := reset(t)
		want := db.ScanLogEntry{
			ScanID:                "f136-store-evidence",
			RepoName:              "org/f136-evidence",
			ScannedAt:             time.Date(2026, 6, 7, 8, 9, 10, 0, time.UTC),
			PackagesCount:         17,
			FindingsCount:         3,
			DurationMs:            456,
			ClientIP:              "198.51.100.36",
			ClientVersion:         "packmon/f136",
			CorrelationID:         "corr-f136-exact",
			ResultDigest:          "sha256:f136-result",
			FindingsBlocking:      true,
			BlockThreshold:        "MEDIUM",
			FeedStatus:            "degraded",
			FeedVersions:          map[string]string{"ghsa": "2026-06-01", "osv": "2026-06-02"},
			FindingIDs:            []string{"GHSA-F136-1", "OSV-F136-2"},
			FindingSeverities:     []string{"CRITICAL", "MEDIUM"},
			ManualAdvisoriesCount: 4,
		}
		if err := store.InsertScanLog(ctx, &want); err != nil {
			t.Fatalf("InsertScanLog() error = %v", err)
		}

		var blocking bool
		var threshold, correlationID, status string
		var versionsExact, idsExact, severitiesExact bool
		var manual int
		if err := store.pool.QueryRow(ctx, `
			SELECT findings_blocking,block_threshold,correlation_id,feed_status,
			       feed_versions=$2::jsonb,finding_ids=$3::jsonb,finding_severities=$4::jsonb,
			       manual_advisories_count
			FROM scan_log WHERE scan_id=$1`, want.ScanID,
			`{"ghsa":"2026-06-01","osv":"2026-06-02"}`,
			`["GHSA-F136-1","OSV-F136-2"]`,
			`["CRITICAL","MEDIUM"]`,
		).Scan(&blocking, &threshold, &correlationID, &status, &versionsExact, &idsExact, &severitiesExact, &manual); err != nil {
			t.Fatalf("read raw decision evidence: %v", err)
		}
		if !blocking || threshold != want.BlockThreshold || correlationID != want.CorrelationID || status != want.FeedStatus || !versionsExact || !idsExact || !severitiesExact || manual != want.ManualAdvisoriesCount {
			t.Fatalf("raw decision evidence = blocking:%t threshold:%q correlation:%q status:%q versions:%t ids:%t severities:%t manual:%d", blocking, threshold, correlationID, status, versionsExact, idsExact, severitiesExact, manual)
		}

		got, err := store.ListRecentScans(ctx, 10, 0)
		if err != nil {
			t.Fatalf("ListRecentScans() error = %v", err)
		}
		if len(got) != 1 {
			t.Fatalf("ListRecentScans() length = %d, want 1: %+v", len(got), got)
		}
		entry := got[0]
		if entry.FindingsBlocking != want.FindingsBlocking || entry.BlockThreshold != want.BlockThreshold || entry.CorrelationID != want.CorrelationID || entry.FeedStatus != want.FeedStatus || !reflect.DeepEqual(entry.FeedVersions, want.FeedVersions) || !reflect.DeepEqual(entry.FindingIDs, want.FindingIDs) || !reflect.DeepEqual(entry.FindingSeverities, want.FindingSeverities) || entry.ManualAdvisoriesCount != want.ManualAdvisoriesCount {
			t.Fatalf("ListRecentScans() decision evidence = blocking:%t threshold:%q correlation:%q status:%q versions:%v ids:%v severities:%v manual:%d", entry.FindingsBlocking, entry.BlockThreshold, entry.CorrelationID, entry.FeedStatus, entry.FeedVersions, entry.FindingIDs, entry.FindingSeverities, entry.ManualAdvisoriesCount)
		}
	})

	t.Run("privacy_export_preserves_exact_result_digest", func(t *testing.T) {
		ctx := reset(t)
		intended := db.ScanLogEntry{
			ScanID:            "f138-privacy-intended",
			RepoName:          "org/f138-privacy-unique",
			ScannedAt:         time.Date(2026, 7, 8, 9, 10, 11, 0, time.UTC),
			PackagesCount:     2,
			FindingsCount:     1,
			DurationMs:        23,
			ResultDigest:      "sha256:f138-exact-intended-result-digest",
			BlockThreshold:    "HIGH",
			FeedStatus:        "healthy",
			FeedVersions:      map[string]string{"osv": "2026-07-08"},
			FindingIDs:        []string{"OSV-F138"},
			FindingSeverities: []string{"HIGH"},
		}
		decoy := db.ScanLogEntry{
			ScanID:            "f138-privacy-decoy",
			RepoName:          "org/f138-decoy",
			ScannedAt:         intended.ScannedAt.Add(time.Second),
			ResultDigest:      "sha256:f138-decoy-must-not-export",
			BlockThreshold:    "NONE",
			FeedStatus:        "healthy",
			FeedVersions:      map[string]string{},
			FindingIDs:        []string{},
			FindingSeverities: []string{},
		}
		for _, entry := range []*db.ScanLogEntry{&intended, &decoy} {
			if err := store.InsertScanLog(ctx, entry); err != nil {
				t.Fatalf("InsertScanLog(%s) error = %v", entry.ScanID, err)
			}
		}

		rows, err := store.pool.Query(ctx, `SELECT scan_id,result_digest FROM scan_log ORDER BY scan_id`)
		if err != nil {
			t.Fatalf("read raw result digests: %v", err)
		}
		raw := make(map[string]string)
		for rows.Next() {
			var scanID, digest string
			if err := rows.Scan(&scanID, &digest); err != nil {
				rows.Close()
				t.Fatalf("scan raw result digest: %v", err)
			}
			raw[scanID] = digest
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			t.Fatalf("iterate raw result digests: %v", err)
		}
		rows.Close()
		wantRaw := map[string]string{intended.ScanID: intended.ResultDigest, decoy.ScanID: decoy.ResultDigest}
		if !reflect.DeepEqual(raw, wantRaw) {
			t.Fatalf("raw result digests = %v, want %v", raw, wantRaw)
		}

		selector := db.PrivacyExportSelector{Type: db.PrivacySelectorRepoName, Value: intended.RepoName}
		export, err := store.ExportPrivacyMetadata(ctx, selector, &db.AdminAuditEntry{
			Action:  "privacy_export",
			Details: json.RawMessage(`{"operator":"f138-contract"}`),
		})
		if err != nil {
			t.Fatalf("ExportPrivacyMetadata() error = %v", err)
		}
		if export.ScanLogCount != 1 || len(export.ScanLogs) != 1 {
			t.Fatalf("privacy export scan logs = count:%d rows:%+v, want exactly one", export.ScanLogCount, export.ScanLogs)
		}
		if export.ScanLogs[0].ScanID != intended.ScanID || export.ScanLogs[0].ResultDigest != intended.ResultDigest {
			t.Fatalf("privacy export scan = id:%q digest:%q, want id:%q digest:%q", export.ScanLogs[0].ScanID, export.ScanLogs[0].ResultDigest, intended.ScanID, intended.ResultDigest)
		}
		encoded, err := json.Marshal(export)
		if err != nil {
			t.Fatalf("marshal privacy export: %v", err)
		}
		if strings.Contains(string(encoded), decoy.ResultDigest) {
			t.Fatalf("privacy export contains decoy result digest: %s", encoded)
		}
	})
}
