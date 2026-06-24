package postgres

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
)

type postgresBareCloser struct {
	closed bool
}

func (c *postgresBareCloser) Close() {
	c.closed = true
}

func TestPostgresCloseSilentlyUsesSharedHelper(t *testing.T) {
	t.Parallel()

	closer := &postgresBareCloser{}
	closeSilently(closer)
	if !closer.closed {
		t.Fatal("closeSilently did not close bare closer")
	}
	closeSilently(nil)
}

func TestScanLogJSONAndDecodeScanLogJSON(t *testing.T) {
	t.Parallel()

	raw, err := scanLogJSON((map[string]string)(nil), map[string]string{"feed": "ok"})
	if err != nil {
		t.Fatalf("scanLogJSON(nil map) error = %v", err)
	}
	if string(raw) != `{"feed":"ok"}` {
		t.Fatalf("scanLogJSON(nil map) = %s", raw)
	}
	raw, err = scanLogJSON(([]string)(nil), []string{"GHSA-1"})
	if err != nil {
		t.Fatalf("scanLogJSON(nil slice) error = %v", err)
	}
	if string(raw) != `["GHSA-1"]` {
		t.Fatalf("scanLogJSON(nil slice) = %s", raw)
	}
	if _, err := scanLogJSON(make(chan int), nil); err == nil || !strings.Contains(err.Error(), "encode scan log json") {
		t.Fatalf("scanLogJSON(unmarshalable) error = %v", err)
	}

	var decoded map[string]string
	if err := decodeScanLogJSON("", &decoded); err != nil {
		t.Fatalf("decode empty JSON error = %v", err)
	}
	if decoded != nil {
		t.Fatalf("decode empty JSON = %+v, want nil map", decoded)
	}
	if err := decodeScanLogJSON(`{"feed":"ok"}`, &decoded); err != nil {
		t.Fatalf("decode object JSON error = %v", err)
	}
	if decoded["feed"] != "ok" {
		t.Fatalf("decoded JSON = %+v", decoded)
	}
	if err := decodeScanLogJSON(`{`, &decoded); err == nil {
		t.Fatal("decode invalid JSON error = nil")
	}
}

func TestPostgresSyncCursorHelpers(t *testing.T) {
	t.Parallel()

	if xid, err := parsePostgresSyncXID("42"); err != nil || xid != 42 {
		t.Fatalf("parsePostgresSyncXID = %d, %v", xid, err)
	}
	if _, err := parsePostgresSyncXID("not-xid"); err == nil {
		t.Fatal("parsePostgresSyncXID(invalid) error = nil")
	}

	opts := db.SyncExportOptions{Limit: 10}
	if got := syncOptionsWithOffset(opts, 25); got.Offset != 25 || got.Limit != 10 {
		t.Fatalf("syncOptionsWithOffset = %+v", got)
	}

	key := encodeSyncCursorKey("npm", "left-pad", "1.0.0")
	parts, err := decodeSyncCursorKey(key, 3)
	if err != nil {
		t.Fatalf("decodeSyncCursorKey() error = %v", err)
	}
	if want := []string{"npm", "left-pad", "1.0.0"}; !reflect.DeepEqual(parts, want) {
		t.Fatalf("decodeSyncCursorKey = %+v, want %+v", parts, want)
	}
	if _, err := decodeSyncCursorKey("not-base64", 3); err == nil {
		t.Fatal("decodeSyncCursorKey(invalid base64) error = nil")
	}
	if _, err := decodeSyncCursorKey(key, 2); err == nil {
		t.Fatal("decodeSyncCursorKey(wrong parts) error = nil")
	}

	var done, cursor bool
	next := db.SyncCursor{}
	setNextDatasetCursor(&next, true, 10, 10, func() { done = true }, func() { cursor = true })
	if !done || cursor {
		t.Fatalf("alreadyDone path done=%v cursor=%v", done, cursor)
	}
	done, cursor = false, false
	setNextDatasetCursor(&next, false, 10, 10, func() { done = true }, func() { cursor = true })
	if done || !cursor {
		t.Fatalf("full page path done=%v cursor=%v", done, cursor)
	}
	done, cursor = false, false
	setNextDatasetCursor(&next, false, 9, 10, func() { done = true }, func() { cursor = true })
	if !done || cursor {
		t.Fatalf("short page path done=%v cursor=%v", done, cursor)
	}
}

func TestAddSyncWindowFilters(t *testing.T) {
	t.Parallel()

	since := time.Date(2026, 6, 24, 12, 0, 0, 0, time.FixedZone("CEST", 2*60*60))
	query := "WHERE true"
	args := []any{"first"}
	addSyncWindowFilters(&query, &args, db.SyncExportOptions{Since: &since, SinceXID: 99}, 123, "updated_at", "xmin")
	for _, want := range []string{"xmin < $2::bigint", "(updated_at >= $3 OR xmin >= $4::bigint)"} {
		if !strings.Contains(query, want) {
			t.Fatalf("query = %q, missing %q", query, want)
		}
	}
	if len(args) != 4 || args[1] != "123" || args[3] != "99" {
		t.Fatalf("args = %#v", args)
	}
	if got := args[2].(time.Time); !got.Equal(since.UTC()) {
		t.Fatalf("since arg = %s, want UTC %s", got, since.UTC())
	}

	query = "WHERE true"
	args = nil
	addSyncWindowFilters(&query, &args, db.SyncExportOptions{Since: &since}, 0, "updated_at", "xmin")
	if !strings.Contains(query, "updated_at >= $1") || len(args) != 1 {
		t.Fatalf("since-only query=%q args=%#v", query, args)
	}
}

func TestManualAdvisoryHelpers(t *testing.T) {
	t.Parallel()

	if got := normalizeManualAdvisoryType(" vulnerability "); got != "vulnerability" {
		t.Fatalf("normalizeManualAdvisoryType(vulnerability) = %q", got)
	}
	if got := normalizeManualAdvisoryType("malware"); got != "malicious" {
		t.Fatalf("normalizeManualAdvisoryType(default) = %q", got)
	}

	advisory := &db.ManualAdvisory{
		ID:          " manual-1 ",
		Ecosystem:   " npm ",
		Name:        " left-pad ",
		Severity:    " high ",
		RiskType:    "",
		Summary:     " summary ",
		Description: " details ",
	}
	vuln := manualAdvisoryToVulnerability(advisory)
	if vuln.ID != "manual-1" || vuln.Severity != "HIGH" || vuln.Summary != "summary" || vuln.Details != "details" {
		t.Fatalf("manualAdvisoryToVulnerability = %+v", vuln)
	}
	if len(vuln.AffectedPackages) != 1 || vuln.AffectedPackages[0].Ecosystem != "npm" || vuln.AffectedPackages[0].Name != "left-pad" {
		t.Fatalf("affected packages = %+v", vuln.AffectedPackages)
	}
	var raw map[string]string
	if err := json.Unmarshal(vuln.Sources[0].RawJSON, &raw); err != nil || raw["finding_type"] != "vulnerability" {
		t.Fatalf("vulnerability raw JSON = %s, %v", vuln.Sources[0].RawJSON, err)
	}

	malicious := manualAdvisoryToMaliciousFinding(advisory)
	if malicious.ID != "manual-1" || malicious.Severity != "HIGH" || malicious.RiskType != "other" || malicious.CreatedBy != "admin" {
		t.Fatalf("manualAdvisoryToMaliciousFinding = %+v", malicious)
	}
	defaults := manualAdvisoryToMaliciousFinding(&db.ManualAdvisory{ID: "id"})
	if defaults.Severity != "CRITICAL" || defaults.RiskType != "other" {
		t.Fatalf("manual malicious defaults = %+v", defaults)
	}
}

func TestLifecycleHelpers(t *testing.T) {
	t.Parallel()

	slugs := lifecycleProductSlugs([]db.LifecycleProduct{
		{ProductSlug: " java "},
		{ProductSlug: ""},
		{ProductSlug: "java"},
		{ProductSlug: "tomcat"},
	})
	if want := []string{"java", "tomcat"}; !reflect.DeepEqual(slugs, want) {
		t.Fatalf("lifecycleProductSlugs = %+v, want %+v", slugs, want)
	}

	got := lifecyclePackageQuery(db.PackageQuery{Ecosystem: "maven", Name: "org.apache.tomcat.embed:tomcat-embed-core", Version: "9.0.80"})
	if got.Ecosystem != "maven" || got.Name != "org.apache.tomcat.embed:tomcat-embed-core" || got.Version != "9.0.80" {
		t.Fatalf("lifecyclePackageQuery = %+v", got)
	}
}

func TestPostgresCloseSilentlyIgnoresErrorCloser(t *testing.T) {
	t.Parallel()

	closeSilently(errorCloser{err: errors.New("ignored")})
}

type errorCloser struct {
	err error
}

func (c errorCloser) Close() error {
	return c.err
}
