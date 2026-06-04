package main

import (
	"context"
	"encoding/json"
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

	textCmd := newDBInfoCmd()
	textOutput := captureStdout(t, func() {
		if err := textCmd.Execute(); err != nil {
			t.Fatalf("db info text: %v", err)
		}
	})
	for _, want := range []string{"Initialized:     true", "Vulnerabilities: 1", "Malicious:       1", "Last sync:       never", "DB stale:"} {
		if !strings.Contains(textOutput, want) {
			t.Fatalf("db info text missing %q:\n%s", want, textOutput)
		}
	}

	exportPath := filepath.Join(t.TempDir(), "export.json")
	exportCmd := newDBExportCmd()
	exportCmd.SetArgs([]string{"--output", exportPath})
	if err := exportCmd.Execute(); err != nil {
		t.Fatalf("db export: %v", err)
	}

	data, err := os.ReadFile(exportPath) // #nosec G304 -- test reads a generated temp-file path.
	if err != nil {
		t.Fatalf("read export: %v", err)
	}
	if !strings.Contains(string(data), `"GHSA-cli"`) || !strings.Contains(string(data), `"MAL-cli"`) {
		t.Fatalf("export does not include seeded entries:\n%s", data)
	}
}

func TestDBInfoReportsLastSyncAgeAndExportStdout(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	dbDir := t.TempDir()
	t.Setenv("PACKMON_DB_PATH", dbDir)
	store, _ := newTestSQLiteStore(t, dbDir)
	ctx := context.Background()
	lastSync := time.Now().UTC().Add(-48 * time.Hour).Truncate(time.Second)
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
	for _, want := range []string{"Last sync:", "DB age:", "DB stale:"} {
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
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/sync" {
			t.Fatalf("path = %q, want /api/v1/sync", r.URL.Path)
		}
		gotAuth = r.Header.Get("Authorization")
		gotEco = r.URL.Query().Get("ecosystem")
		gotLimit = r.URL.Query().Get("limit")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"synced_at":"` + time.Now().UTC().Format(time.RFC3339) + `",
			"vulnerabilities":[{"id":"GHSA-db-sync","ecosystem":"npm","name":"left-pad","version_ranges":"[]","severity":"LOW","summary":"synced"}],
			"malicious":[{"id":"MAL-db-sync","ecosystem":"npm","name":"evil","risk_type":"malware","severity":"CRITICAL","summary":"bad"}]
		}`))
	}))
	defer srv.Close()

	cmd := newDBSyncCmd()
	cmd.SetArgs([]string{"--server", srv.URL, "--api-key", "secret", "--ecosystems", " npm,go ", "--full", "--timeout", "3", "--insecure-allow-http"})
	output := captureStdout(t, func() {
		if err := cmd.Execute(); err != nil {
			t.Fatalf("db sync: %v", err)
		}
	})

	if gotAuth != "Bearer secret" || gotEco != "npm,go" || gotLimit == "" {
		t.Fatalf("sync request auth=%q ecosystem=%q limit=%q", gotAuth, gotEco, gotLimit)
	}
	if !strings.Contains(output, "Local database synchronized") || !strings.Contains(output, "Vulnerabilities: 1") || !strings.Contains(output, "Malicious:       1") {
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

func TestDBSyncCommandRejectsInsecureHTTPWithoutOptIn(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	dbDir := t.TempDir()
	t.Setenv("PACKMON_DB_PATH", dbDir)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatal("db sync sent request over plain HTTP without opt-in")
	}))
	defer srv.Close()

	cmd := newDBSyncCmd()
	cmd.SetArgs([]string{"--server", srv.URL, "--api-key", "secret"})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "refusing to use insecure server URL") {
		t.Fatalf("db sync insecure HTTP error = %v", err)
	}
}

func TestDBSyncCommandUsesConfigAndEnvironmentPrecedence(t *testing.T) {
	isolateCLIConfigDiscovery(t)
	dbDir := t.TempDir()
	t.Setenv("PACKMON_DB_PATH", dbDir)
	t.Setenv("PACKMON_SYNC_KEY", "config-env-key")
	t.Setenv("PACKMON_INSECURE_ALLOW_HTTP", "true")

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
	if err := os.WriteFile(".packmon.yaml", []byte(config), 0o600); err != nil {
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
