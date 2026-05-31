package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/8linkz/packmon/internal/domain"
)

func TestDBWarnAfterDays(t *testing.T) {
	tests := []struct {
		name string
		env  string
		want int
	}{
		{name: "default", want: defaultDBWarnAfterDays},
		{name: "valid", env: "14", want: 14},
		{name: "negative falls back", env: "-1", want: defaultDBWarnAfterDays},
		{name: "invalid falls back", env: "soon", want: defaultDBWarnAfterDays},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.env != "" {
				t.Setenv("PACKMON_DB_WARN_AFTER_DAYS", tt.env)
			}
			if got := dbWarnAfterDays(); got != tt.want {
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

func TestExportLocalDBIncludesVulnerabilityAndMaliciousEntries(t *testing.T) {
	store, _ := newTestSQLiteStore(t, t.TempDir())

	_, err := store.DB().ExecContext(context.Background(), `
		INSERT INTO vulnerabilities_local(row_key, id, ecosystem, name, version_ranges, severity, cvss_score, epss_score, cisa_kev, summary)
		VALUES('GHSA-test|npm|left-pad', 'GHSA-test', 'npm', 'left-pad', '[{"events":[{"introduced":"0"},{"fixed":"1.1.0"}]}]', 'HIGH', 7.5, 0.42, 1, 'left-pad issue');
		INSERT INTO malicious_local(id, ecosystem, name, versions, risk_type, severity, summary)
		VALUES('MAL-test', 'pypi', 'badpkg', '["0.1.0"]', 'malware', 'CRITICAL', 'bad package');
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
	if !payload.Vulnerabilities[0].CISAKEV || payload.Vulnerabilities[0].CVSSScore == nil || payload.Vulnerabilities[0].EPSSScore == nil {
		t.Fatalf("vulnerability enrichment missing: %+v", payload.Vulnerabilities[0])
	}
	if len(payload.Malicious) != 1 || payload.Malicious[0].ID != "MAL-test" {
		t.Fatalf("malicious = %+v", payload.Malicious)
	}
	if !strings.Contains(string(payload.Malicious[0].Versions), "0.1.0") {
		t.Fatalf("malicious versions = %s", payload.Malicious[0].Versions)
	}
}
