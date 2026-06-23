package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSplitCSVTrimsEmptyValues(t *testing.T) {
	t.Parallel()

	got := splitCSV(" npm, ,go,pypi ,, ")
	want := []string{"npm", "go", "pypi"}
	if len(got) != len(want) {
		t.Fatalf("splitCSV length = %d, want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("splitCSV[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestDBInfoCommandJSONReportsUninitializedDatabase(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	dbDir := t.TempDir()
	t.Setenv("PACKMON_DB_PATH", dbDir)

	cmd := newDBInfoCmd()
	cmd.SetArgs([]string{"--json"})

	output := captureStdout(t, func() {
		if err := cmd.Execute(); err != nil {
			t.Fatalf("db info: %v", err)
		}
	})

	var info localDBInfo
	if err := json.Unmarshal([]byte(output), &info); err != nil {
		t.Fatalf("decode db info: %v\n%s", err, output)
	}
	if info.Exists {
		t.Fatalf("info.Exists = true, want false")
	}
	if info.Path != filepath.Join(dbDir, "packmon.db") {
		t.Fatalf("info.Path = %q, want db path under env dir", info.Path)
	}
}

func TestDBInfoCommandTextReportsUninitializedDatabase(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	dbDir := t.TempDir()
	t.Setenv("PACKMON_DB_PATH", dbDir)

	cmd := newDBInfoCmd()
	output := captureStdout(t, func() {
		if err := cmd.Execute(); err != nil {
			t.Fatalf("db info: %v", err)
		}
	})

	if !strings.Contains(output, "local database not initialized") || !strings.Contains(output, "Initialized:     false") {
		t.Fatalf("db info text output = %q", output)
	}
}

func TestDBInfoAndExportCommandsUseLocalDatabase(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	dbDir := t.TempDir()
	t.Setenv("PACKMON_DB_PATH", dbDir)
	store, dbPath := newTestSQLiteStore(t, dbDir)

	_, err := store.DB().ExecContext(context.Background(), `
		INSERT INTO vulnerabilities_local(row_key, id, ecosystem, name, version_ranges, severity)
		VALUES('GHSA-cli|go|module', 'GHSA-cli', 'go', 'module', '[]', 'LOW');
		INSERT INTO malicious_local(id, ecosystem, name, risk_type, severity)
		VALUES('MAL-cli', 'npm', 'evil', 'malware', 'CRITICAL');
		INSERT INTO reputation_findings_local(id, ecosystem, name, version, type, risk_type, severity, summary)
		VALUES('REP-cli', 'npm', 'left-pad', '1.0.0', 'supply_chain_risk', 'removed_package', 'LOW', 'reputation issue');
		INSERT INTO lifecycle_releases_local(id, ecosystem, name, product_slug, product_label, cycle, is_eol, eol_from)
		VALUES('LIFE-cli', 'pypi', 'django', 'django', 'Django', '3.2', 1, '2024-04-01T00:00:00Z');
	`)
	if err != nil {
		t.Fatalf("seed local db: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close seed store: %v", err)
	}

	infoCmd := newDBInfoCmd()
	infoCmd.SetArgs([]string{"--json"})
	infoOutput := captureStdout(t, func() {
		if err := infoCmd.Execute(); err != nil {
			t.Fatalf("db info: %v", err)
		}
	})

	var info localDBInfo
	if err := json.Unmarshal([]byte(infoOutput), &info); err != nil {
		t.Fatalf("decode info: %v\n%s", err, infoOutput)
	}
	if !info.Exists || info.Path != dbPath || info.Vulnerabilities != 1 || info.Malicious != 1 {
		t.Fatalf("db info = %+v", info)
	}
	var rawInfo map[string]any
	if err := json.Unmarshal([]byte(infoOutput), &rawInfo); err != nil {
		t.Fatalf("decode raw info: %v\n%s", err, infoOutput)
	}
	if rawInfo["reputation"] != float64(1) || rawInfo["lifecycle"] != float64(1) {
		t.Fatalf("db info JSON = %s, want reputation and lifecycle counts", infoOutput)
	}

	textCmd := newDBInfoCmd()
	textOutput := captureStdout(t, func() {
		if err := textCmd.Execute(); err != nil {
			t.Fatalf("db info text: %v", err)
		}
	})
	for _, want := range []string{"Initialized:     true", "Vulnerabilities: 1", "Malicious:       1", "Reputation:      1", "Lifecycle:       1", "Last sync:       never", "DB stale:"} {
		if !strings.Contains(textOutput, want) {
			t.Fatalf("db info text missing %q:\n%s", want, textOutput)
		}
	}

	exportPath := filepath.Join(t.TempDir(), "export.json")
	if err := os.WriteFile(exportPath, []byte("old export"), 0o644); err != nil { // #nosec G306 -- test seeds an intentionally broad file to verify export tightens permissions.
		t.Fatalf("seed broad export file: %v", err)
	}
	if err := os.Chmod(exportPath, 0o644); err != nil { // #nosec G302 -- test seeds an intentionally broad file to verify export tightens permissions.
		t.Fatalf("chmod broad export file: %v", err)
	}
	exportCmd := newDBExportCmd()
	exportCmd.SetArgs([]string{"--output", exportPath})
	if err := exportCmd.Execute(); err != nil {
		t.Fatalf("db export: %v", err)
	}

	data, err := os.ReadFile(exportPath) // #nosec G304 -- test reads a generated temp-file path.
	if err != nil {
		t.Fatalf("read export: %v", err)
	}
	if !strings.Contains(string(data), `"GHSA-cli"`) ||
		!strings.Contains(string(data), `"MAL-cli"`) ||
		!strings.Contains(string(data), `"REP-cli"`) ||
		!strings.Contains(string(data), `"LIFE-cli"`) {
		t.Fatalf("export does not include seeded entries:\n%s", data)
	}
}

func TestDBExportCommandWritesPrivateOutputFile(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	dbDir := t.TempDir()
	t.Setenv("PACKMON_DB_PATH", dbDir)
	store, _ := newTestSQLiteStore(t, dbDir)
	if _, err := store.DB().ExecContext(context.Background(), `
		INSERT INTO vulnerabilities_local(row_key, id, ecosystem, name, version_ranges, severity)
		VALUES('GHSA-private|npm|pkg', 'GHSA-private', 'npm', 'pkg', '[]', 'LOW')`); err != nil {
		t.Fatalf("seed local db: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close seed store: %v", err)
	}

	exportDir := t.TempDir()
	exportPath := filepath.Join(exportDir, "export.json")
	if err := os.WriteFile(exportPath, []byte("old export"), 0o644); err != nil { // #nosec G306 -- test seeds an intentionally broad file to verify export tightens permissions.
		t.Fatalf("seed broad export file: %v", err)
	}
	if err := os.Chmod(exportPath, 0o644); err != nil { // #nosec G302 -- test seeds an intentionally broad file to verify export tightens permissions.
		t.Fatalf("chmod broad export file: %v", err)
	}

	cmd := newDBExportCmd()
	cmd.SetArgs([]string{"--output", exportPath})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("db export: %v", err)
	}

	skipIfPOSIXModesAreNotPreserved(t, exportDir)
	info, err := os.Stat(exportPath)
	if err != nil {
		t.Fatalf("stat export: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("export permissions = %o, want 0600", got)
	}

	data, err := os.ReadFile(exportPath) // #nosec G304 -- test reads a generated temp-file path.
	if err != nil {
		t.Fatalf("read export: %v", err)
	}
	var exported localDBExport
	if err := json.Unmarshal(data, &exported); err != nil {
		t.Fatalf("decode export: %v\n%s", err, data)
	}
	if exported.Info == nil {
		t.Fatal("export info is nil")
	}
	if filepath.IsAbs(exported.Info.Path) || strings.Contains(exported.Info.Path, dbDir) {
		t.Fatalf("export info.path = %q, want path-minimized basename", exported.Info.Path)
	}
	if exported.Info.Path != "packmon.db" {
		t.Fatalf("export info.path = %q, want packmon.db", exported.Info.Path)
	}
}

type failingCloseWriter struct {
	bytes.Buffer
	err error
}

func (w *failingCloseWriter) Close() error {
	return w.err
}

func TestWriteLocalDBExportReturnsCloseError(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	dbDir := t.TempDir()
	store, _ := newTestSQLiteStore(t, dbDir)
	defer closeSilently(store)

	writer := &failingCloseWriter{err: errors.New("delayed writeback failed")}
	err := writeLocalDBExport(context.Background(), store, writer, writer)
	if err == nil {
		t.Fatal("writeLocalDBExport() error = nil, want close error")
	}
	if !strings.Contains(err.Error(), "close export file") || !strings.Contains(err.Error(), "delayed writeback failed") {
		t.Fatalf("writeLocalDBExport() error = %v, want close context", err)
	}
}

func TestDBInfoReportsLastSyncAgeAndExportStdout(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	dbDir := t.TempDir()
	t.Setenv("PACKMON_DB_PATH", dbDir)
	store, _ := newTestSQLiteStore(t, dbDir)
	ctx := context.Background()
	lastSync := time.Now().UTC().Add(-25 * time.Hour).Truncate(time.Second)
	if err := store.SetSyncMeta(ctx, "last_sync_at", lastSync.Format(time.RFC3339)); err != nil {
		t.Fatalf("set last sync: %v", err)
	}
	if _, err := store.DB().ExecContext(ctx, `
		INSERT INTO vulnerabilities_local(row_key, id, ecosystem, name, version_ranges, severity)
		VALUES('GHSA-stdout|npm|pkg', 'GHSA-stdout', 'npm', 'pkg', '[]', 'LOW')`); err != nil {
		t.Fatalf("seed local db: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close seed store: %v", err)
	}

	infoOutput := captureStdout(t, func() {
		if err := newDBInfoCmd().Execute(); err != nil {
			t.Fatalf("db info text: %v", err)
		}
	})
	for _, want := range []string{"Last sync:", "DB age:          1 day", "DB stale:"} {
		if !strings.Contains(infoOutput, want) {
			t.Fatalf("db info output missing %q:\n%s", want, infoOutput)
		}
	}

	exportOutput := captureStdout(t, func() {
		if err := newDBExportCmd().Execute(); err != nil {
			t.Fatalf("db export stdout: %v", err)
		}
	})
	if !strings.Contains(exportOutput, `"GHSA-stdout"`) {
		t.Fatalf("db export stdout missing seeded advisory:\n%s", exportOutput)
	}
}

func TestDBExportCommandRejectsUninitializedDatabase(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	t.Setenv("PACKMON_DB_PATH", t.TempDir())

	err := newDBExportCmd().Execute()
	if err == nil || !strings.Contains(err.Error(), "local database does not exist yet") {
		t.Fatalf("db export uninitialized error = %v", err)
	}
}

func TestDBSyncCommandReturnsConfigLoadErrors(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	if err := os.WriteFile(".packmon.yaml", []byte("server: ["), 0o600); err != nil {
		t.Fatalf("write invalid config: %v", err)
	}

	err := newDBSyncCmd().Execute()
	if err == nil || !strings.Contains(err.Error(), "parse") {
		t.Fatalf("db sync config load error = %v", err)
	}
}

func TestDBSyncCommandRejectsUnsupportedSourceBeforeOpeningDatabase(t *testing.T) {
	isolateCLIConfigDiscovery(t)

	cmd := newDBSyncCmd()
	cmd.SetArgs([]string{"--source", "osv"})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "supported: server") {
		t.Fatalf("db sync unsupported source error = %v", err)
	}
}

func TestDBSyncCommandReadsConfigSource(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	if err := os.WriteFile(defaultCLIConfigFile, []byte("db:\n  sync_source: osv\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	err := newDBSyncCmd().Execute()
	if err == nil || !strings.Contains(err.Error(), `source "osv"`) {
		t.Fatalf("db sync config source error = %v, want unsupported osv source", err)
	}
}

func TestDBSyncCommandRequiresServerURL(t *testing.T) {
	isolateCLIConfigDiscovery(t)

	cmd := newDBSyncCmd()
	cmd.SetArgs([]string{})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "missing server URL") {
		t.Fatalf("db sync missing server error = %v", err)
	}
}

func TestDBSyncCommandFetchesFromServerAndPrintsSummary(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	dbDir := t.TempDir()
	t.Setenv("PACKMON_DB_PATH", dbDir)

	var gotAuth, gotEco, gotLimit string
	handlerErrors := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/sync" {
			reportHandlerError(w, handlerErrors, http.StatusNotFound, "path = %q, want /api/v1/sync", r.URL.Path)
			return
		}
		gotAuth = r.Header.Get("Authorization")
		gotEco = r.URL.Query().Get("ecosystem")
		gotLimit = r.URL.Query().Get("limit")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"synced_at":"` + time.Now().UTC().Format(time.RFC3339) + `",
			"vulnerabilities":[{"id":"GHSA-db-sync","ecosystem":"npm","name":"left-pad","version_ranges":"[]","severity":"LOW","summary":"synced"}],
			"malicious":[{"id":"MAL-db-sync","ecosystem":"npm","name":"evil","risk_type":"malware","severity":"CRITICAL","summary":"bad"}],
			"reputation":[{"id":"REP-db-sync","ecosystem":"npm","name":"left-pad","version":"1.0.0","type":"supply_chain_risk","risk_type":"removed_package","severity":"LOW","summary":"reputation"}],
			"lifecycle":[{"id":"LIFE-db-sync","ecosystem":"pypi","name":"django","product_slug":"django","product_label":"Django","cycle":"3.2","is_eol":true,"eol_from":"2024-04-01T00:00:00Z"}]
		}`))
	}))
	defer srv.Close()

	cmd := newDBSyncCmd()
	cmd.SetArgs([]string{"--server", srv.URL, "--api-key", "secret", "--ecosystems", " npm,go ", "--timeout", "3", "--insecure-allow-http"})
	output := captureStdout(t, func() {
		if err := cmd.Execute(); err != nil {
			t.Fatalf("db sync: %v", err)
		}
	})
	assertNoHandlerError(t, handlerErrors)

	if gotAuth != "Bearer secret" || gotEco != "npm,go" || gotLimit == "" {
		t.Fatalf("sync request auth=%q ecosystem=%q limit=%q", gotAuth, gotEco, gotLimit)
	}
	if !strings.Contains(output, "Local database synchronized") ||
		!strings.Contains(output, "Vulnerabilities: 1") ||
		!strings.Contains(output, "Malicious:       1") ||
		!strings.Contains(output, "Reputation:      1") ||
		!strings.Contains(output, "Lifecycle:       1") {
		t.Fatalf("db sync output = %q", output)
	}

	verify, _ := newTestSQLiteStore(t, dbDir)
	vulns, err := verify.FindVulnerabilities(context.Background(), "npm", "left-pad", "1.0.0")
	if err != nil {
		t.Fatalf("FindVulnerabilities() error = %v", err)
	}
	if len(vulns) != 1 || vulns[0].AdvisoryID != "GHSA-db-sync" {
		t.Fatalf("synced vulnerabilities = %+v", vulns)
	}
}

func TestDBSyncCommandPrintsRemovedRows(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	dbDir := t.TempDir()
	t.Setenv("PACKMON_DB_PATH", dbDir)
	store, _ := newTestSQLiteStore(t, dbDir)
	if _, err := store.DB().ExecContext(context.Background(), `
		INSERT INTO vulnerabilities_local(row_key, id, ecosystem, name, version_ranges, severity)
		VALUES('GHSA-remove|npm|left-pad', 'GHSA-remove', 'npm', 'left-pad', '[]', 'LOW');
		INSERT INTO malicious_local(id, ecosystem, name, risk_type, severity)
		VALUES('MAL-remove', 'npm', 'evil', 'malware', 'CRITICAL');
		INSERT INTO reputation_findings_local(id, ecosystem, name, version, type, risk_type, severity)
		VALUES('REP-remove', 'npm', 'removed', '1.0.0', 'supply_chain_risk', 'removed_package', 'LOW');
		INSERT INTO lifecycle_releases_local(id, ecosystem, name, product_slug, product_label, cycle, is_eol)
		VALUES('LIFE-remove', 'npm', 'oldlib', 'oldlib', 'oldlib', '1.0', 1);
	`); err != nil {
		t.Fatalf("seed local db: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close seed store: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"synced_at":"` + time.Now().UTC().Format(time.RFC3339) + `"}`))
	}))
	defer srv.Close()

	cmd := newDBSyncCmd()
	cmd.SetArgs([]string{"--server", srv.URL, "--full", "--insecure-allow-http"})
	output := captureStdout(t, func() {
		if err := cmd.Execute(); err != nil {
			t.Fatalf("db sync: %v", err)
		}
	})

	for _, want := range []string{
		"Removed cached rows:",
		"Full sync clear: vulnerabilities=1 malicious=1 reputation=1 lifecycle=1",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("db sync output missing %q:\n%s", want, output)
		}
	}
}

func TestDBSyncCommandRejectsFilteredFullSync(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	dbDir := t.TempDir()
	t.Setenv("PACKMON_DB_PATH", dbDir)

	handlerErrors := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reportHandlerError(w, handlerErrors, http.StatusBadRequest, "db sync sent filtered full sync request")
	}))
	defer srv.Close()

	cmd := newDBSyncCmd()
	cmd.SetArgs([]string{"--server", srv.URL, "--ecosystems", "npm", "--full", "--insecure-allow-http"})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "filtered full sync") {
		t.Fatalf("db sync filtered full error = %v", err)
	}
	assertNoHandlerError(t, handlerErrors)
}

func TestDBSyncCommandRejectsInsecureHTTPWithoutOptIn(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	dbDir := t.TempDir()
	t.Setenv("PACKMON_DB_PATH", dbDir)

	handlerErrors := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reportHandlerError(w, handlerErrors, http.StatusBadRequest, "db sync sent request over plain HTTP without opt-in")
	}))
	defer srv.Close()

	cmd := newDBSyncCmd()
	cmd.SetArgs([]string{"--server", srv.URL, "--api-key", "secret"})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "refusing to use insecure server URL") {
		t.Fatalf("db sync insecure HTTP error = %v", err)
	}
	assertNoHandlerError(t, handlerErrors)
}

func TestDBSyncCommandRedactsPACKMONServerURLFromErrors(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	dbDir := t.TempDir()
	t.Setenv("PACKMON_DB_PATH", dbDir)
	t.Setenv("PACKMON_SERVER", "http://user:server-secret@example.test/private?token=query-secret")

	cmd := newDBSyncCmd()
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "refusing to use insecure server URL") {
		t.Fatalf("db sync insecure secret server error = %v", err)
	}
	for _, leaked := range []string{"server-secret", "query-secret", "/private", "token=query-secret"} {
		if strings.Contains(err.Error(), leaked) {
			t.Fatalf("db sync error leaked %q in %q", leaked, err.Error())
		}
	}
}

func TestDBSyncCommandUsesConfiguredCABundle(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	dbDir := t.TempDir()
	t.Setenv("PACKMON_DB_PATH", dbDir)

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"synced_at":"` + time.Now().UTC().Format(time.RFC3339) + `"}`))
	}))
	defer srv.Close()

	caFile := filepath.Join(t.TempDir(), "server-ca.pem")
	writeServerCertPEM(t, srv, caFile)

	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("home: %v", err)
	}
	userCfgDir := filepath.Join(home, ".packmon", "config")
	if err := os.MkdirAll(userCfgDir, 0o750); err != nil {
		t.Fatalf("mkdir user config dir: %v", err)
	}
	config := "server: " + strconvQuoteForYAML(srv.URL) + "\n" +
		"cacert: " + strconvQuoteForYAML(caFile) + "\n" +
		"timeout: 3\n"
	if err := os.WriteFile(filepath.Join(userCfgDir, "packmon.yaml"), []byte(config), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	output := captureStdout(t, func() {
		if err := newDBSyncCmd().Execute(); err != nil {
			t.Fatalf("db sync with configured CA: %v", err)
		}
	})
	if !strings.Contains(output, "Local database synchronized") {
		t.Fatalf("db sync output = %q", output)
	}
}

func TestDBSyncCommandCACertFlagWinsOverEnvAndConfig(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	dbDir := t.TempDir()
	t.Setenv("PACKMON_DB_PATH", dbDir)

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"synced_at":"` + time.Now().UTC().Format(time.RFC3339) + `"}`))
	}))
	defer srv.Close()

	tempDir := t.TempDir()
	goodCA := filepath.Join(tempDir, "server-ca.pem")
	badCA := filepath.Join(tempDir, "bad-ca.pem")
	writeServerCertPEM(t, srv, goodCA)
	if err := os.WriteFile(badCA, []byte("not a certificate"), 0o600); err != nil {
		t.Fatalf("write bad CA: %v", err)
	}
	t.Setenv("PACKMON_CA_CERT", badCA)

	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("home: %v", err)
	}
	userCfgDir := filepath.Join(home, ".packmon", "config")
	if err := os.MkdirAll(userCfgDir, 0o750); err != nil {
		t.Fatalf("mkdir user config dir: %v", err)
	}
	config := "server: " + strconvQuoteForYAML(srv.URL) + "\n" +
		"cacert: " + strconvQuoteForYAML(badCA) + "\n" +
		"timeout: 3\n"
	if err := os.WriteFile(filepath.Join(userCfgDir, "packmon.yaml"), []byte(config), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cmd := newDBSyncCmd()
	cmd.SetArgs([]string{"--cacert", goodCA})
	output := captureStdout(t, func() {
		if err := cmd.Execute(); err != nil {
			t.Fatalf("db sync with flag CA: %v", err)
		}
	})
	if !strings.Contains(output, "Local database synchronized") {
		t.Fatalf("db sync output = %q", output)
	}
}

func TestDBSyncCommandRejectsInvalidBooleanEnv(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	t.Setenv("PACKMON_DB_PATH", t.TempDir())
	t.Setenv("PACKMON_INSECURE_ALLOW_HTTP", "maybe")

	cmd := newDBSyncCmd()
	cmd.SetArgs([]string{"--server", "http://127.0.0.1:1", "--api-key", "secret"})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "PACKMON_INSECURE_ALLOW_HTTP") {
		t.Fatalf("db sync error = %v, want invalid PACKMON_INSECURE_ALLOW_HTTP rejection", err)
	}
}

func TestDBSyncCommandRejectsInvalidTimeoutEnv(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	t.Setenv("PACKMON_DB_PATH", t.TempDir())
	t.Setenv("PACKMON_TIMEOUT", "later")
	t.Setenv("PACKMON_INSECURE_ALLOW_HTTP", "true")

	cmd := newDBSyncCmd()
	cmd.SetArgs([]string{"--server", "http://127.0.0.1:1", "--api-key", "secret"})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "PACKMON_TIMEOUT") {
		t.Fatalf("db sync error = %v, want invalid PACKMON_TIMEOUT rejection", err)
	}
}

func TestDBSyncCommandRejectsNonPositiveTimeout(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	t.Setenv("PACKMON_DB_PATH", t.TempDir())

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"synced_at":"` + time.Now().UTC().Format(time.RFC3339) + `"}`))
	}))
	defer srv.Close()

	cmd := newDBSyncCmd()
	cmd.SetArgs([]string{"--server", srv.URL, "--api-key", "secret", "--insecure-allow-http", "--timeout=-1"})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "timeout must be greater than zero") {
		t.Fatalf("db sync error = %v, want non-positive timeout rejection", err)
	}
}

func TestDBSyncCommandUsesConfigAndEnvironmentPrecedence(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	dbDir := t.TempDir()
	t.Setenv("PACKMON_DB_PATH", dbDir)
	t.Setenv("PACKMON_SYNC_KEY", "config-env-key")
	t.Setenv("PACKMON_INSECURE_ALLOW_HTTP", "true")
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("home: %v", err)
	}
	userCfgDir := filepath.Join(home, ".packmon", "config")
	if err := os.MkdirAll(userCfgDir, 0o750); err != nil {
		t.Fatalf("mkdir user config dir: %v", err)
	}

	var requests []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Header.Get("Authorization")+" "+r.URL.Query().Get("ecosystem"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"synced_at":"` + time.Now().UTC().Format(time.RFC3339) + `"}`))
	}))
	defer srv.Close()

	config := "server: " + strconvQuoteForYAML(srv.URL) + "\n" +
		"api_key_env: PACKMON_SYNC_KEY\n" +
		"ecosystems: [npm, go]\n" +
		"timeout: 4\n"
	if err := os.WriteFile(filepath.Join(userCfgDir, "packmon.yaml"), []byte(config), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cmd := newDBSyncCmd()
	if err := cmd.Execute(); err != nil {
		t.Fatalf("db sync config: %v", err)
	}

	t.Setenv("PACKMON_SERVER", srv.URL)
	t.Setenv("PACKMON_API_KEY", "env-key")
	t.Setenv("PACKMON_ECOSYSTEMS", "pypi")
	t.Setenv("PACKMON_TIMEOUT", "5")
	cmd = newDBSyncCmd()
	if err := cmd.Execute(); err != nil {
		t.Fatalf("db sync env: %v", err)
	}

	want := []string{"Bearer config-env-key npm,go", "Bearer env-key pypi"}
	if len(requests) != len(want) {
		t.Fatalf("requests = %v, want %v", requests, want)
	}
	for i := range want {
		if requests[i] != want[i] {
			t.Fatalf("request[%d] = %q, want %q", i, requests[i], want[i])
		}
	}
}
