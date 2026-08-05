package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db/sqlite"
	"github.com/8linkz-sec/packmon/internal/domain"
)

func TestDBWarnAfterDays(t *testing.T) {
	tests := []struct {
		name    string
		env     string
		want    int
		wantErr bool
	}{
		{name: "default", want: defaultDBWarnAfterDays},
		{name: "valid", env: "14", want: 14},
		{name: "negative rejected", env: "-1", wantErr: true},
		{name: "invalid rejected", env: "soon", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.env != "" {
				t.Setenv("PACKMON_DB_WARN_AFTER_DAYS", tt.env)
			}
			got, err := dbWarnAfterDays()
			if tt.wantErr {
				if err == nil || !strings.Contains(err.Error(), "PACKMON_DB_WARN_AFTER_DAYS") {
					t.Fatalf("dbWarnAfterDays() error = %v, want PACKMON_DB_WARN_AFTER_DAYS rejection", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("dbWarnAfterDays() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("dbWarnAfterDays() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestParseTimestampAcceptsRFC3339Layouts(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{
		"2026-05-30T12:13:14Z",
		"2026-05-30T12:13:14.123456789Z",
	} {
		ts, err := parseTimestamp(raw)
		if err != nil {
			t.Fatalf("parseTimestamp(%q): %v", raw, err)
		}
		if ts.Location() != time.UTC {
			t.Fatalf("parseTimestamp(%q) location = %v, want UTC", raw, ts.Location())
		}
	}

	if _, err := parseTimestamp("2026-05-30"); err == nil {
		t.Fatal("parseTimestamp(invalid) error = nil")
	}
}

func TestLoadLocalDBInfoMarksStaleBySyncAge(t *testing.T) {
	t.Setenv("PACKMON_DB_WARN_AFTER_DAYS", "7")
	store, _ := newTestSQLiteStore(t, t.TempDir())

	lastSync := time.Now().UTC().Add(-8 * 24 * time.Hour)
	if err := store.SetSyncMeta(context.Background(), "last_sync_at", lastSync.Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("set sync meta: %v", err)
	}

	info, err := loadLocalDBInfo(context.Background(), store)
	if err != nil {
		t.Fatalf("load local db info: %v", err)
	}
	if info.LastSyncAt == nil {
		t.Fatal("LastSyncAt = nil, want timestamp")
	}
	if info.DBAgeDays == nil || *info.DBAgeDays < 7 {
		t.Fatalf("DBAgeDays = %v, want at least 7", info.DBAgeDays)
	}
	if !info.DBStale {
		t.Fatal("DBStale = false, want true")
	}
}

func TestReadLocalSyncAgeClampsFutureTimestamps(t *testing.T) {
	store, _ := newTestSQLiteStore(t, t.TempDir())
	future := time.Now().UTC().Add(24 * time.Hour)
	if err := store.SetSyncMeta(context.Background(), "last_sync_at", future.Format(time.RFC3339)); err != nil {
		t.Fatalf("set sync meta: %v", err)
	}

	_, ageDays, err := readLocalSyncAge(context.Background(), store)
	if err != nil {
		t.Fatalf("readLocalSyncAge() error = %v", err)
	}
	if ageDays == nil || *ageDays != 0 {
		t.Fatalf("ageDays = %v, want clamped zero", ageDays)
	}
}

func TestApplyLocalDBFreshnessOnlyAnnotatesLocalResults(t *testing.T) {
	t.Setenv("PACKMON_DB_WARN_AFTER_DAYS", "1")
	store, _ := newTestSQLiteStore(t, t.TempDir())

	if err := store.SetSyncMeta(context.Background(), "last_sync_at", time.Now().UTC().Add(-2*24*time.Hour).Format(time.RFC3339)); err != nil {
		t.Fatalf("set sync meta: %v", err)
	}

	localResult := &domain.ScanResult{Mode: "local"}
	if err := applyLocalDBFreshness(context.Background(), store, localResult); err != nil {
		t.Fatalf("apply local freshness: %v", err)
	}
	if localResult.DBAgeDays == nil || !localResult.DBStale {
		t.Fatalf("local freshness not applied: age=%v stale=%v", localResult.DBAgeDays, localResult.DBStale)
	}

	remoteResult := &domain.ScanResult{Mode: "remote"}
	if err := applyLocalDBFreshness(context.Background(), store, remoteResult); err != nil {
		t.Fatalf("apply remote freshness: %v", err)
	}
	if remoteResult.DBAgeDays != nil || remoteResult.DBStale {
		t.Fatalf("remote result changed: age=%v stale=%v", remoteResult.DBAgeDays, remoteResult.DBStale)
	}

	if err := applyLocalDBFreshness(context.Background(), nil, localResult); err != nil {
		t.Fatalf("apply nil store freshness: %v", err)
	}
	if err := applyLocalDBFreshness(context.Background(), store, nil); err != nil {
		t.Fatalf("apply nil result freshness: %v", err)
	}
}

func TestApplyLocalDBFreshnessMarksUnknownFreshnessAsStale(t *testing.T) {
	store, _ := newTestSQLiteStore(t, t.TempDir())

	if err := store.SetSyncMeta(context.Background(), "last_sync_at", "not-a-timestamp"); err != nil {
		t.Fatalf("set sync meta: %v", err)
	}

	result := &domain.ScanResult{Mode: "local"}
	err := applyLocalDBFreshness(context.Background(), store, result)
	if err == nil {
		t.Fatal("applyLocalDBFreshness() error = nil, want timestamp parse error")
	}
	if !result.DBStale {
		t.Fatal("DBStale = false, want stale when freshness cannot be verified")
	}
	if result.DBAgeDays != nil {
		t.Fatalf("DBAgeDays = %v, want nil for unknown freshness", result.DBAgeDays)
	}
}

func TestApplyLocalDBFreshnessRejectsInvalidWarnAfterEnv(t *testing.T) {
	t.Setenv("PACKMON_DB_WARN_AFTER_DAYS", "soon")
	store, _ := newTestSQLiteStore(t, t.TempDir())

	if err := store.SetSyncMeta(context.Background(), "last_sync_at", time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatalf("set sync meta: %v", err)
	}

	result := &domain.ScanResult{Mode: "local"}
	err := applyLocalDBFreshness(context.Background(), store, result)
	if err == nil || !strings.Contains(err.Error(), "PACKMON_DB_WARN_AFTER_DAYS") {
		t.Fatalf("applyLocalDBFreshness() error = %v, want PACKMON_DB_WARN_AFTER_DAYS rejection", err)
	}
	if !result.DBStale {
		t.Fatal("DBStale = false, want stale when warn-after config is invalid")
	}
	if result.DBAgeDays != nil {
		t.Fatalf("DBAgeDays = %v, want nil for invalid warn-after config", result.DBAgeDays)
	}
}

func TestApplyLocalDBFreshnessAppliesSyncedFeedState(t *testing.T) {
	store, _ := newTestSQLiteStore(t, t.TempDir())

	if err := store.SetSyncMeta(context.Background(), "last_sync_at", time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatalf("set sync timestamp: %v", err)
	}
	if err := store.SetSyncMeta(context.Background(), "feed_status", "degraded"); err != nil {
		t.Fatalf("set feed status: %v", err)
	}
	if err := store.SetSyncMeta(context.Background(), "feed_versions", `{"osv":"2026-05-30T10:00:00Z"}`); err != nil {
		t.Fatalf("set feed versions: %v", err)
	}

	localResult := &domain.ScanResult{
		Mode:         "local",
		FeedStatus:   "healthy",
		FeedVersions: map[string]string{},
	}
	if err := applyLocalDBFreshness(context.Background(), store, localResult); err != nil {
		t.Fatalf("apply local freshness: %v", err)
	}
	if localResult.FeedStatus != "degraded" {
		t.Fatalf("feed status = %q, want degraded", localResult.FeedStatus)
	}
	if got := localResult.FeedVersions["osv"]; got != "2026-05-30T10:00:00Z" {
		t.Fatalf("feed versions[osv] = %q", got)
	}
}

func TestExportLocalDBIncludesVulnerabilityAndMaliciousEntries(t *testing.T) {
	store, _ := newTestSQLiteStore(t, t.TempDir())

	_, err := store.DB().ExecContext(context.Background(), `
		INSERT INTO vulnerabilities_local(row_key, id, ecosystem, name, version_ranges, severity, cvss_score, epss_score, epss_percentile, cisa_kev, summary, source)
		VALUES('GHSA-test|npm|left-pad', 'GHSA-test', 'npm', 'left-pad', '[{"events":[{"introduced":"0"},{"fixed":"1.1.0"}]}]', 'HIGH', 7.5, 0.42, 0.88, 1, 'left-pad issue', 'manual');
		INSERT INTO malicious_local(id, ecosystem, name, versions, risk_type, severity, summary, source)
		VALUES('MAL-test', 'pypi', 'badpkg', '["0.1.0"]', 'malware', 'CRITICAL', 'bad package', 'manual');
	`)
	if err != nil {
		t.Fatalf("seed local db: %v", err)
	}

	var buf bytes.Buffer
	if err := exportLocalDB(context.Background(), store, &buf); err != nil {
		t.Fatalf("export local db: %v", err)
	}

	var payload localDBExport
	if err := json.Unmarshal(buf.Bytes(), &payload); err != nil {
		t.Fatalf("decode export: %v\n%s", err, buf.String())
	}
	if payload.Info == nil || payload.Info.Vulnerabilities != 1 || payload.Info.Malicious != 1 {
		t.Fatalf("export info = %+v, want one vulnerability and one malicious entry", payload.Info)
	}
	if len(payload.Vulnerabilities) != 1 || payload.Vulnerabilities[0].ID != "GHSA-test" {
		t.Fatalf("vulnerabilities = %+v", payload.Vulnerabilities)
	}
	if !payload.Vulnerabilities[0].CISAKEV || payload.Vulnerabilities[0].CVSSScore == nil || payload.Vulnerabilities[0].EPSSScore == nil || payload.Vulnerabilities[0].EPSSPercentile == nil {
		t.Fatalf("vulnerability enrichment missing: %+v", payload.Vulnerabilities[0])
	}
	if *payload.Vulnerabilities[0].EPSSPercentile != 0.88 {
		t.Fatalf("EPSS percentile = %v, want 0.88", *payload.Vulnerabilities[0].EPSSPercentile)
	}
	if payload.Vulnerabilities[0].Source != "manual" {
		t.Fatalf("vulnerability source = %q, want manual", payload.Vulnerabilities[0].Source)
	}
	if len(payload.Malicious) != 1 || payload.Malicious[0].ID != "MAL-test" {
		t.Fatalf("malicious = %+v", payload.Malicious)
	}
	if !strings.Contains(string(payload.Malicious[0].Versions), "0.1.0") {
		t.Fatalf("malicious versions = %s", payload.Malicious[0].Versions)
	}
	if payload.Malicious[0].Source != "manual" {
		t.Fatalf("malicious source = %q, want manual", payload.Malicious[0].Source)
	}
}

func TestLocalDBInfoAndExportIncludeReputationAndLifecycle(t *testing.T) {
	store, _ := newTestSQLiteStore(t, t.TempDir())

	_, err := store.DB().ExecContext(context.Background(), `
		INSERT INTO reputation_findings_local(id, ecosystem, name, version, type, risk_type, severity, summary)
		VALUES('REP-test', 'npm', 'left-pad', '1.0.0', 'supply_chain_risk', 'malware_history', 'HIGH', 'reputation issue');
		INSERT INTO lifecycle_releases_local(
			id, ecosystem, name, product_slug, product_label, cycle, latest,
			release_date, is_lts, lts_from, is_eoas, eoas_from, is_eol, eol_from,
			is_discontinued, discontinued_from, is_eoes, eoes_from, is_maintained
		)
		VALUES(
			'LIFE-test', 'pypi', 'django', 'django', 'Django', '3.2', '3.2.25',
			'2021-04-06T00:00:00Z', 1, '2021-04-06T00:00:00Z', 1, '2023-12-31T00:00:00Z',
			1, '2024-04-01T00:00:00Z', 0, NULL, NULL, NULL, 0
		);
	`)
	if err != nil {
		t.Fatalf("seed local db: %v", err)
	}

	info, err := loadLocalDBInfo(context.Background(), store)
	if err != nil {
		t.Fatalf("load local db info: %v", err)
	}
	infoJSON, err := json.Marshal(info)
	if err != nil {
		t.Fatalf("marshal info: %v", err)
	}
	var infoPayload map[string]any
	if err := json.Unmarshal(infoJSON, &infoPayload); err != nil {
		t.Fatalf("decode marshaled info: %v", err)
	}
	if infoPayload["reputation"] != float64(1) || infoPayload["lifecycle"] != float64(1) {
		t.Fatalf("info payload = %s, want reputation and lifecycle counts", infoJSON)
	}

	var buf bytes.Buffer
	if err := exportLocalDB(context.Background(), store, &buf); err != nil {
		t.Fatalf("export local db: %v", err)
	}
	var exportPayload map[string]json.RawMessage
	if err := json.Unmarshal(buf.Bytes(), &exportPayload); err != nil {
		t.Fatalf("decode export: %v\n%s", err, buf.String())
	}

	var reputation []map[string]any
	if err := json.Unmarshal(exportPayload["reputation"], &reputation); err != nil {
		t.Fatalf("decode reputation export: %v\n%s", err, buf.String())
	}
	if len(reputation) != 1 || reputation[0]["id"] != "REP-test" || reputation[0]["risk_type"] != "malware_history" || reputation[0]["severity"] != "LOW" {
		t.Fatalf("reputation export = %+v", reputation)
	}

	var lifecycle []map[string]any
	if err := json.Unmarshal(exportPayload["lifecycle"], &lifecycle); err != nil {
		t.Fatalf("decode lifecycle export: %v\n%s", err, buf.String())
	}
	if len(lifecycle) != 1 || lifecycle[0]["id"] != "LIFE-test" || lifecycle[0]["product_label"] != "Django" || lifecycle[0]["is_eol"] != true {
		t.Fatalf("lifecycle export = %+v", lifecycle)
	}
}

func TestExportLocalDBIncludesCompleteScanHistory(t *testing.T) {
	store, _ := newTestSQLiteStore(t, t.TempDir())
	scannedAt := time.Date(2026, 5, 30, 10, 11, 12, 0, time.UTC)
	if err := store.InsertScan(context.Background(), sqlite.ScanEntry{
		RepoName:          "app",
		Branch:            "main",
		Commit:            "0123456789abcdef0123456789abcdef01234567",
		ScannedAt:         scannedAt,
		PackagesCount:     9,
		FindingsCount:     2,
		FindingIDs:        []string{"GHSA-one", "MAL-two"},
		FindingSeverities: []string{"HIGH", "CRITICAL"},
	}); err != nil {
		t.Fatalf("insert scan history: %v", err)
	}

	var buf bytes.Buffer
	if err := exportLocalDB(context.Background(), store, &buf); err != nil {
		t.Fatalf("export local db: %v", err)
	}

	var payload localDBExport
	if err := json.Unmarshal(buf.Bytes(), &payload); err != nil {
		t.Fatalf("decode export: %v\n%s", err, buf.String())
	}
	if len(payload.ScanHistory) != 1 {
		t.Fatalf("scan_history export len = %d, want 1", len(payload.ScanHistory))
	}
	got := payload.ScanHistory[0]
	if got.RepoName != "app" || got.Branch != "main" || got.Commit != "0123456789abcdef0123456789abcdef01234567" {
		t.Fatalf("scan_history repo metadata = %+v", got)
	}
	if !got.ScannedAt.Equal(scannedAt) || got.PackagesCount != 9 || got.FindingsCount != 2 {
		t.Fatalf("scan_history counts/time = %+v", got)
	}
	if len(got.FindingIDs) != 2 || got.FindingIDs[0] != "GHSA-one" || got.FindingSeverities[1] != "CRITICAL" {
		t.Fatalf("scan_history findings = %+v", got)
	}
}

func TestExportLocalDBStreamsRowsInsteadOfMaterializingStorePayload(t *testing.T) {
	t.Parallel()

	source, err := os.ReadFile("local_db.go")
	if err != nil {
		t.Fatalf("read local_db.go: %v", err)
	}
	if strings.Contains(string(source), "ExportLocalDatabase(ctx)") {
		t.Fatal("exportLocalDB still calls ExportLocalDatabase(ctx); want streaming row export")
	}
}
