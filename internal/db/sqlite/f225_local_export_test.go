package sqlite

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
)

var errF225Consumer = errors.New("f225 export consumer failed")

type f225ExportStream struct {
	name       string
	queryMatch string
	iterateErr string
	nilCall    func(*Store) error
	stream     func(*Store, func(any) error) error
}

func f225ExportStreams() []f225ExportStream {
	return []f225ExportStream{
		{
			name:       "vulnerabilities",
			queryMatch: "FROM vulnerabilities_local",
			iterateErr: "iterate local vulnerabilities",
			nilCall: func(store *Store) error {
				return store.StreamLocalVulnerabilities(context.Background(), nil)
			},
			stream: func(store *Store, emit func(any) error) error {
				return store.StreamLocalVulnerabilities(context.Background(), func(item LocalVulnerabilityEntry) error { return emit(item) })
			},
		},
		{
			name:       "malicious",
			queryMatch: "FROM malicious_local",
			iterateErr: "iterate local malicious findings",
			nilCall: func(store *Store) error {
				return store.StreamLocalMalicious(context.Background(), nil)
			},
			stream: func(store *Store, emit func(any) error) error {
				return store.StreamLocalMalicious(context.Background(), func(item LocalMaliciousEntry) error { return emit(item) })
			},
		},
		{
			name:       "reputation",
			queryMatch: "FROM reputation_findings_local",
			iterateErr: "iterate local reputation findings",
			nilCall: func(store *Store) error {
				return store.StreamLocalReputation(context.Background(), nil)
			},
			stream: func(store *Store, emit func(any) error) error {
				return store.StreamLocalReputation(context.Background(), func(item LocalReputationEntry) error { return emit(item) })
			},
		},
		{
			name:       "lifecycle",
			queryMatch: "FROM lifecycle_releases_local",
			iterateErr: "iterate local lifecycle releases",
			nilCall: func(store *Store) error {
				return store.StreamLocalLifecycle(context.Background(), nil)
			},
			stream: func(store *Store, emit func(any) error) error {
				return store.StreamLocalLifecycle(context.Background(), func(item LocalLifecycleEntry) error { return emit(item) })
			},
		},
		{
			name:       "scan history",
			queryMatch: "FROM scan_history",
			iterateErr: "iterate local scan history",
			nilCall: func(store *Store) error {
				return store.StreamLocalScanHistory(context.Background(), nil)
			},
			stream: func(store *Store, emit func(any) error) error {
				return store.StreamLocalScanHistory(context.Background(), func(item ScanEntry) error { return emit(item) })
			},
		},
	}
}

func TestF225StreamLocalExportsRejectNilEmittersBeforeQuerying(t *testing.T) {
	store := newClosedStore(t)
	for _, stream := range f225ExportStreams() {
		t.Run(stream.name, func(t *testing.T) {
			err := stream.nilCall(store)
			if err == nil || !strings.Contains(err.Error(), "export emitter is nil") {
				t.Fatalf("nil emitter error = %v, want the stream-specific nil-emitter error", err)
			}
		})
	}
}

func TestF225StreamLocalExportsConvertNullableValuesAndOrderRows(t *testing.T) {
	store := newSQLiteTestStore(t)
	f225SeedExportRows(t, store.db)
	ctx := context.Background()

	var vulnerabilities []LocalVulnerabilityEntry
	if err := store.StreamLocalVulnerabilities(ctx, func(item LocalVulnerabilityEntry) error {
		vulnerabilities = append(vulnerabilities, item)
		return nil
	}); err != nil {
		t.Fatalf("StreamLocalVulnerabilities() error = %v", err)
	}
	if len(vulnerabilities) != 4 {
		t.Fatalf("vulnerability count = %d, want 4", len(vulnerabilities))
	}
	if got := f225VulnerabilityIDs(vulnerabilities); !reflect.DeepEqual(got, []string{"vuln-z", "vuln-y", "vuln-a", "vuln-b"}) {
		t.Fatalf("vulnerability order = %v, want ecosystem, name, then ID ordering", got)
	}
	nullableVulnerability := vulnerabilities[0]
	if string(nullableVulnerability.VersionRanges) != "[]" || nullableVulnerability.Severity != "HIGH" ||
		nullableVulnerability.CVSSScore != nil || nullableVulnerability.EPSSScore != nil || nullableVulnerability.EPSSPercentile != nil ||
		nullableVulnerability.CISAKEV || nullableVulnerability.Summary != "" || nullableVulnerability.Source != "local" {
		t.Fatalf("nullable vulnerability = %+v", nullableVulnerability)
	}
	populatedVulnerability := vulnerabilities[1]
	if string(populatedVulnerability.VersionRanges) != `[{"fixed":"2.0.0"}]` || !populatedVulnerability.CISAKEV || populatedVulnerability.Source != "osv" {
		t.Fatalf("populated vulnerability = %+v", populatedVulnerability)
	}

	var malicious []LocalMaliciousEntry
	if err := store.StreamLocalMalicious(ctx, func(item LocalMaliciousEntry) error {
		malicious = append(malicious, item)
		return nil
	}); err != nil {
		t.Fatalf("StreamLocalMalicious() error = %v", err)
	}
	if len(malicious) != 4 {
		t.Fatalf("malicious count = %d, want 4", len(malicious))
	}
	if got := f225MaliciousIDs(malicious); !reflect.DeepEqual(got, []string{"mal-z", "mal-y", "mal-a", "mal-b"}) {
		t.Fatalf("malicious order = %v, want ecosystem, name, then ID ordering", got)
	}
	nullableMalicious := malicious[0]
	if nullableMalicious.VersionRanges != nil || nullableMalicious.Versions != nil || nullableMalicious.Severity != "CRITICAL" || nullableMalicious.Summary != "" || nullableMalicious.Source != "local" {
		t.Fatalf("nullable malicious row = %+v", nullableMalicious)
	}
	populatedMalicious := malicious[1]
	if string(populatedMalicious.VersionRanges) != `[{"introduced":"0"}]` || string(populatedMalicious.Versions) != `["1.0.0"]` {
		t.Fatalf("populated malicious row = %+v", populatedMalicious)
	}

	var reputation []LocalReputationEntry
	if err := store.StreamLocalReputation(ctx, func(item LocalReputationEntry) error {
		reputation = append(reputation, item)
		return nil
	}); err != nil {
		t.Fatalf("StreamLocalReputation() error = %v", err)
	}
	if len(reputation) != 4 {
		t.Fatalf("reputation count = %d, want 4", len(reputation))
	}
	if got := f225ReputationIDs(reputation); !reflect.DeepEqual(got, []string{"rep-z", "rep-y", "rep-a", "rep-b"}) {
		t.Fatalf("reputation order = %v, want ecosystem, name, then ID ordering", got)
	}
	if reputation[0].Severity != "HIGH" || reputation[0].Summary != "" || reputation[1].Severity != "LOW" {
		t.Fatalf("normalized reputation rows = %+v", reputation)
	}

	var lifecycle []LocalLifecycleEntry
	if err := store.StreamLocalLifecycle(ctx, func(item LocalLifecycleEntry) error {
		lifecycle = append(lifecycle, item)
		return nil
	}); err != nil {
		t.Fatalf("StreamLocalLifecycle() error = %v", err)
	}
	if len(lifecycle) != 6 {
		t.Fatalf("lifecycle count = %d, want 6", len(lifecycle))
	}
	if got := f225LifecycleIDs(lifecycle); !reflect.DeepEqual(got, []string{"life-z", "life-y", "life-x", "life-a", "life-b", "life-w"}) {
		t.Fatalf("lifecycle order = %v, want ecosystem, name, product, cycle, then ID ordering", got)
	}
	nullableLifecycle := lifecycle[0]
	if nullableLifecycle.ReleaseDate != nil || nullableLifecycle.IsLTS || nullableLifecycle.LTSFrom != nil || nullableLifecycle.IsEOAS || nullableLifecycle.EOASFrom != nil ||
		nullableLifecycle.IsEOL || nullableLifecycle.EOLFrom != nil || nullableLifecycle.IsDiscontinued || nullableLifecycle.DiscontinuedFrom != nil ||
		nullableLifecycle.IsEOES != nil || nullableLifecycle.EOESFrom != nil || nullableLifecycle.IsMaintained {
		t.Fatalf("nullable lifecycle row = %+v", nullableLifecycle)
	}
	populatedLifecycle := lifecycle[1]
	if populatedLifecycle.ReleaseDate == nil || *populatedLifecycle.ReleaseDate != "2026-01-01" ||
		!populatedLifecycle.IsLTS || populatedLifecycle.LTSFrom == nil || *populatedLifecycle.LTSFrom != "2026-01-02" ||
		!populatedLifecycle.IsEOAS || populatedLifecycle.EOASFrom == nil || *populatedLifecycle.EOASFrom != "2026-01-03" ||
		!populatedLifecycle.IsEOL || populatedLifecycle.EOLFrom == nil || *populatedLifecycle.EOLFrom != "2026-01-04" ||
		!populatedLifecycle.IsDiscontinued || populatedLifecycle.DiscontinuedFrom == nil || *populatedLifecycle.DiscontinuedFrom != "2026-01-05" ||
		populatedLifecycle.IsEOES == nil || *populatedLifecycle.IsEOES || populatedLifecycle.EOESFrom == nil || *populatedLifecycle.EOESFrom != "2026-01-06" ||
		!populatedLifecycle.IsMaintained {
		t.Fatalf("populated lifecycle row = %+v", populatedLifecycle)
	}

	var history []ScanEntry
	if err := store.StreamLocalScanHistory(ctx, func(item ScanEntry) error {
		history = append(history, item)
		return nil
	}); err != nil {
		t.Fatalf("StreamLocalScanHistory() error = %v", err)
	}
	if len(history) != 2 {
		t.Fatalf("scan-history count = %d, want 2", len(history))
	}
	if got := []int{history[0].ID, history[1].ID}; !reflect.DeepEqual(got, []int{10, 20}) {
		t.Fatalf("scan-history order = %v, want newest row first", got)
	}
	if history[0].RepoName != "" || history[0].Branch != "" || history[0].Commit != "" || history[0].FindingIDs != nil || history[0].FindingSeverities != nil {
		t.Fatalf("nullable scan-history row = %+v", history[0])
	}
	if !reflect.DeepEqual(history[1].FindingIDs, []string{"GHSA-1"}) || !reflect.DeepEqual(history[1].FindingSeverities, []string{"HIGH"}) {
		t.Fatalf("populated scan-history row = %+v", history[1])
	}
}

func TestF225StreamLocalExportsStopAfterConsumerFailure(t *testing.T) {
	store := newSQLiteTestStore(t)
	f225SeedExportRows(t, store.db)

	for _, stream := range f225ExportStreams() {
		t.Run(stream.name, func(t *testing.T) {
			emitted := 0
			err := stream.stream(store, func(any) error {
				emitted++
				return errF225Consumer
			})
			if err == nil || !errors.Is(err, errF225Consumer) || !strings.Contains(err.Error(), "write local") {
				t.Fatalf("stream error = %v, want wrapped consumer failure", err)
			}
			if emitted != 1 {
				t.Fatalf("emitted rows = %d, want exactly one before the consumer stopped the stream", emitted)
			}
		})
	}
}

func TestF225StreamLocalExportsReportScanFailuresBeforeEmission(t *testing.T) {
	tests := []struct {
		name    string
		seed    string
		wantErr string
		stream  func(*Store, func(any) error) error
	}{
		{
			name: "vulnerabilities",
			seed: `INSERT INTO vulnerabilities_local
				(row_key, id, ecosystem, name, severity, cisa_kev) VALUES ('scan-v', 'scan-v', 'npm', 'bad', 'HIGH', 'not-an-integer')`,
			wantErr: "scan local vulnerability row",
			stream:  f225ExportStreams()[0].stream,
		},
		{
			name: "malicious",
			seed: `INSERT INTO malicious_local
				(id, ecosystem, name, risk_type, severity) VALUES (NULL, 'npm', 'bad', 'malware', 'CRITICAL')`,
			wantErr: "scan local malicious row",
			stream:  f225ExportStreams()[1].stream,
		},
		{
			name: "reputation",
			seed: `INSERT INTO reputation_findings_local
				(id, ecosystem, name, version, type, risk_type, severity) VALUES (NULL, 'npm', 'bad', '1', 'malicious', 'malware', 'CRITICAL')`,
			wantErr: "scan local reputation row",
			stream:  f225ExportStreams()[2].stream,
		},
		{
			name: "lifecycle",
			seed: `INSERT INTO lifecycle_releases_local
				(id, ecosystem, name, product_slug, cycle, is_lts) VALUES ('scan-l', 'npm', 'bad', 'bad', '1', 'not-an-integer')`,
			wantErr: "scan local lifecycle row",
			stream:  f225ExportStreams()[3].stream,
		},
		{
			name: "scan history",
			seed: `INSERT INTO scan_history
				(scanned_at, packages_count) VALUES ('2026-01-01T00:00:00Z', 'not-an-integer')`,
			wantErr: "scan local scan-history row",
			stream:  f225ExportStreams()[4].stream,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store := newSQLiteTestStore(t)
			if _, err := store.db.Exec(tc.seed); err != nil {
				t.Fatalf("seed malformed row: %v", err)
			}
			emitted := 0
			err := tc.stream(store, func(any) error {
				emitted++
				return nil
			})
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("stream error = %v, want %q", err, tc.wantErr)
			}
			if emitted != 0 {
				t.Fatalf("emitted rows = %d before scan failure, want 0", emitted)
			}
		})
	}
}

func TestF225StreamLocalExportsReportIterationFailuresAfterLastCompleteEmission(t *testing.T) {
	for _, stream := range f225ExportStreams() {
		t.Run(stream.name, func(t *testing.T) {
			database, fired := f225OpenIterationFaultDB(t, stream.queryMatch)
			f225CreateSQLiteSchema(t, database)
			f225SeedExportRows(t, database)
			store := &Store{db: database}
			emitted := 0

			err := stream.stream(store, func(any) error {
				emitted++
				return nil
			})
			if err == nil || !errors.Is(err, errInjectedFault) || !strings.Contains(err.Error(), stream.iterateErr) {
				t.Fatalf("stream error = %v, want wrapped iteration fault containing %q", err, stream.iterateErr)
			}
			if !fired.Load() {
				t.Fatal("the injected iteration fault did not fire")
			}
			if emitted != 1 {
				t.Fatalf("emitted rows = %d, want the one complete row preceding the iteration fault", emitted)
			}
		})
	}
}

func TestF225StreamLocalScanHistoryRejectsMalformedStoredValues(t *testing.T) {
	tests := []struct {
		name      string
		scannedAt string
		idsJSON   any
		sevsJSON  any
		wantErr   string
	}{
		{name: "timestamp", scannedAt: "not-rfc3339", idsJSON: `[]`, sevsJSON: `[]`, wantErr: "decode local scan-history row 1 scanned_at"},
		{name: "finding IDs", scannedAt: "2026-01-01T00:00:00Z", idsJSON: `{`, sevsJSON: `[]`, wantErr: "decode local scan-history row 1 finding_ids"},
		{name: "finding severities", scannedAt: "2026-01-01T00:00:00Z", idsJSON: `[]`, sevsJSON: `{`, wantErr: "decode local scan-history row 1 finding_severities"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store := newSQLiteTestStore(t)
			if _, err := store.db.Exec(`INSERT INTO scan_history
				(scanned_at, packages_count, findings_count, finding_ids, finding_severities)
				VALUES (?, 0, 0, ?, ?)`, tc.scannedAt, tc.idsJSON, tc.sevsJSON); err != nil {
				t.Fatalf("seed malformed scan history: %v", err)
			}
			emitted := 0
			err := store.StreamLocalScanHistory(context.Background(), func(ScanEntry) error {
				emitted++
				return nil
			})
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("StreamLocalScanHistory() error = %v, want %q", err, tc.wantErr)
			}
			if emitted != 0 {
				t.Fatalf("emitted rows = %d before decode failure, want 0", emitted)
			}
		})
	}
}

func TestF225LocalExportHelperEdges(t *testing.T) {
	if got := localExportSource(" \t\r\n "); got != "local" {
		t.Fatalf("localExportSource(whitespace) = %q, want local", got)
	}
	if got := localDBStringPtr(sql.NullString{String: "ignored", Valid: false}); got != nil {
		t.Fatalf("localDBStringPtr(invalid nonempty value) = %q, want nil", *got)
	}
	if got := localDBBoolPtr(sql.NullInt64{Int64: -1, Valid: true}); got == nil || *got {
		t.Fatalf("localDBBoolPtr(negative) = %v, want false", got)
	}
}

func f225VulnerabilityIDs(items []LocalVulnerabilityEntry) []string {
	ids := make([]string, 0, len(items))
	for _, item := range items {
		ids = append(ids, item.ID)
	}
	return ids
}

func f225MaliciousIDs(items []LocalMaliciousEntry) []string {
	ids := make([]string, 0, len(items))
	for _, item := range items {
		ids = append(ids, item.ID)
	}
	return ids
}

func f225ReputationIDs(items []LocalReputationEntry) []string {
	ids := make([]string, 0, len(items))
	for _, item := range items {
		ids = append(ids, item.ID)
	}
	return ids
}

func f225LifecycleIDs(items []LocalLifecycleEntry) []string {
	ids := make([]string, 0, len(items))
	for _, item := range items {
		ids = append(ids, item.ID)
	}
	return ids
}

func f225SeedExportRows(t *testing.T, database *sql.DB) {
	t.Helper()
	statements := []string{
		`INSERT INTO vulnerabilities_local
			(row_key, id, ecosystem, name, version_ranges, severity, cvss_score, epss_score, epss_percentile, cisa_kev, summary, source)
		 VALUES
			('v-b', 'vuln-b', 'npm', 'same-package', NULL, 'MEDIUM', NULL, NULL, NULL, 0, NULL, 'local'),
			('v-y', 'vuln-y', 'npm', 'alpha-package', '[{"fixed":"2.0.0"}]', ' LOW ', 7.5, 0.5, 0.8, 2, 'y summary', ' osv '),
			('v-a', 'vuln-a', 'npm', 'same-package', NULL, 'MEDIUM', NULL, NULL, NULL, 0, NULL, 'local'),
			('v-z', 'vuln-z', 'go', 'omega-package', '  ', ' HIGH ', NULL, NULL, NULL, -1, NULL, '   ')`,
		`INSERT INTO malicious_local
			(id, ecosystem, name, version_ranges, versions, risk_type, severity, summary, source)
		 VALUES
			('mal-b', 'npm', 'same-package', NULL, NULL, 'malware', 'MEDIUM', NULL, 'local'),
			('mal-y', 'npm', 'alpha-package', '[{"introduced":"0"}]', '["1.0.0"]', 'malware', ' HIGH ', 'y summary', 'socket'),
			('mal-a', 'npm', 'same-package', NULL, NULL, 'malware', 'MEDIUM', NULL, 'local'),
			('mal-z', 'go', 'omega-package', NULL, '', 'malware', ' CRITICAL ', NULL, '  ')`,
		`INSERT INTO reputation_findings_local
			(id, ecosystem, name, version, type, risk_type, severity, summary)
		 VALUES
			('rep-b', 'npm', 'same-package', '1.0.0', 'malicious', 'malware', 'MEDIUM', NULL),
			('rep-y', 'npm', 'alpha-package', '1.0.0', 'supply_chain_risk', 'malware_history', ' HIGH ', 'history'),
			('rep-a', 'npm', 'same-package', '1.0.0', 'malicious', 'malware', 'MEDIUM', NULL),
			('rep-z', 'go', 'omega-package', '1.0.0', 'malicious', 'malware', ' HIGH ', NULL)`,
		`INSERT INTO lifecycle_releases_local
			(id, ecosystem, name, product_slug, product_label, cycle, latest, release_date,
			 is_lts, lts_from, is_eoas, eoas_from, is_eol, eol_from,
			 is_discontinued, discontinued_from, is_eoes, eoes_from, is_maintained)
		 VALUES
			('life-b', 'npm', 'same-package', 'same-product', 'B', '1', '1.0.0', NULL,
			 0, NULL, 0, NULL, 0, NULL, 0, NULL, NULL, NULL, 0),
			('life-x', 'npm', 'same-package', 'beta-product', 'X', '9', '9.0.0', NULL,
			 0, NULL, 0, NULL, 0, NULL, 0, NULL, NULL, NULL, 0),
			('life-w', 'npm', 'same-package', 'same-product', 'W', '2', '2.0.0', NULL,
			 0, NULL, 0, NULL, 0, NULL, 0, NULL, NULL, NULL, 0),
			('life-y', 'npm', 'alpha-package', 'q-product', 'Y', '9', '9.0.0', '2026-01-01',
			 2, '2026-01-02', 1, '2026-01-03', 1, '2026-01-04', 1, '2026-01-05', 0, '2026-01-06', 3),
			('life-a', 'npm', 'same-package', 'same-product', 'A', '1', '1.0.0', NULL,
			 0, NULL, 0, NULL, 0, NULL, 0, NULL, NULL, NULL, 0),
			('life-z', 'go', 'omega-package', 'q-product', 'Z', '9', '9.0.0', NULL,
			 -1, '  ', 0, NULL, 0, '', -2, NULL, NULL, ' ', 0)`,
		`INSERT INTO scan_history
			(id, repo_name, branch, "commit", scanned_at, packages_count, findings_count, finding_ids, finding_severities)
		 VALUES
			(20, 'repo', 'main', 'abc', '2026-01-01T00:00:00Z', 2, 1, '["GHSA-1"]', '["HIGH"]'),
			(10, NULL, NULL, NULL, '2026-01-02T00:00:00Z', 0, 0, '', NULL)`,
	}
	for _, statement := range statements {
		if _, err := database.Exec(statement); err != nil {
			t.Fatalf("seed local export rows: %v\n%s", err, statement)
		}
	}
}

func f225CreateSQLiteSchema(t *testing.T, database *sql.DB) {
	t.Helper()
	if _, err := database.Exec(schemaSQL); err != nil {
		t.Fatalf("create SQLite schema: %v", err)
	}
}

type f225IterationFaultDriver struct {
	inner    driver.Driver
	contains string
	fired    *atomic.Bool
}

func (d *f225IterationFaultDriver) Open(name string) (driver.Conn, error) {
	conn, err := d.inner.Open(name)
	if err != nil {
		return nil, err
	}
	return &f225IterationFaultConn{Conn: conn, contains: d.contains, fired: d.fired}, nil
}

type f225IterationFaultConn struct {
	driver.Conn
	contains string
	fired    *atomic.Bool
}

func (c *f225IterationFaultConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	execer, ok := c.Conn.(driver.ExecerContext)
	if !ok {
		return nil, driver.ErrSkip
	}
	return execer.ExecContext(ctx, query, args)
}

func (c *f225IterationFaultConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	queryer, ok := c.Conn.(driver.QueryerContext)
	if !ok {
		return nil, driver.ErrSkip
	}
	rows, err := queryer.QueryContext(ctx, query, args)
	if err != nil || !strings.Contains(strings.ToUpper(query), strings.ToUpper(c.contains)) {
		return rows, err
	}
	return &f225IterationFaultRows{Rows: rows, fired: c.fired}, nil
}

type f225IterationFaultRows struct {
	driver.Rows
	fired    *atomic.Bool
	returned bool
}

func (r *f225IterationFaultRows) Next(dest []driver.Value) error {
	if r.returned {
		r.fired.Store(true)
		return errInjectedFault
	}
	err := r.Rows.Next(dest)
	if err == nil {
		r.returned = true
	}
	return err
}

var f225IterationFaultDriverSequence atomic.Uint64

func f225OpenIterationFaultDB(t *testing.T, contains string) (*sql.DB, *atomic.Bool) {
	t.Helper()

	probe, err := sql.Open(realDriverName, ":memory:")
	if err != nil {
		t.Fatalf("open SQLite driver probe: %v", err)
	}
	inner := probe.Driver()
	if err := probe.Close(); err != nil {
		t.Fatalf("close SQLite driver probe: %v", err)
	}

	fired := &atomic.Bool{}
	driverName := fmt.Sprintf("sqlite-f225-iteration-%d", f225IterationFaultDriverSequence.Add(1))
	sql.Register(driverName, &f225IterationFaultDriver{inner: inner, contains: contains, fired: fired})
	database, err := sql.Open(driverName, filepath.Join(t.TempDir(), "iteration.db"))
	if err != nil {
		t.Fatalf("open local-export iteration-fault database: %v", err)
	}
	database.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = database.Close() })
	return database, fired
}

var (
	_ driver.ExecerContext  = (*f225IterationFaultConn)(nil)
	_ driver.QueryerContext = (*f225IterationFaultConn)(nil)
	_ driver.Rows           = (*f225IterationFaultRows)(nil)
)
