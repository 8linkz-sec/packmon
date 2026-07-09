//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/domain"
	"github.com/8linkz-sec/packmon/internal/synccontract"
)

const postgresIntegrationImage = "cgr.dev/chainguard/postgres:18@sha256:891139a6d9036632791857fb7585425f1bf0c64516fc52bc39da94305ee92461"

func TestProductionServerWithPostgresAndAPIKey(t *testing.T) {
	t.Parallel()

	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatalf("docker not available; tagged integration tests require Docker: %v", err)
	}

	containerName, dbPort := startIntegrationPostgres(t, "packmon-it")

	serverBin := serverBinaryPath(t)
	feedImportSecret := "integration-import-secret"
	env := productionServerEnv(dbPort, feedImportSecret)

	runMigrateWithRetry(t, serverBin, env)

	cmd, cancelServer := integrationLongRunningCommand(t, serverBin)
	cmd.Env = env

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		t.Fatalf("stderr pipe: %v", err)
	}
	logs := &serverProcessLogs{}
	addrCh := make(chan serverBoundAddr, 4)
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start production server: %v", err)
	}
	go scanServerStdout(stdoutPipe, logs, addrCh)
	go scanServerStderr(stderrPipe, logs)
	defer func() {
		cancelServer()
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()

	addrs := waitForServerBoundAddrs(t, addrCh, logs, 15*time.Second)
	baseURL := loopbackHTTPURL(t, addrs.main)
	waitForHTTPStatus(t, baseURL+"/healthz", http.StatusOK, logs.String())

	publicResp, err := integrationHTTPGet(baseURL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	closeSilently(publicResp.Body)
	if publicResp.StatusCode != http.StatusOK {
		t.Fatalf("GET / status = %d, want 200", publicResp.StatusCode)
	}

	apiKey := "integration-key"
	if err := insertAPIKeyIntoContainer(containerName, hashSHA256(apiKey)); err != nil {
		t.Fatalf("insert api key: %v", err)
	}
	expiredAPIKey := "integration-expired-key"
	revokedAPIKey := "integration-revoked-key"
	deletedAPIKey := "integration-deleted-key"
	if err := insertInactiveAPIKeysIntoContainer(containerName, map[string]string{
		"expired": hashSHA256(expiredAPIKey),
		"revoked": hashSHA256(revokedAPIKey),
		"deleted": hashSHA256(deletedAPIKey),
	}); err != nil {
		t.Fatalf("insert inactive api keys: %v", err)
	}

	checkReqBody, err := json.Marshal(map[string]any{
		"packages": []map[string]string{
			{"name": "left-pad-evil", "version": "1.2.3", "ecosystem": "npm"},
		},
	})
	if err != nil {
		t.Fatalf("json.Marshal check body: %v", err)
	}

	reqNoAuth, err := http.NewRequest(http.MethodPost, baseURL+"/api/v1/check", bytes.NewReader(checkReqBody))
	if err != nil {
		t.Fatalf("NewRequest no auth: %v", err)
	}
	reqNoAuth.Header.Set("Content-Type", "application/json")
	reqNoAuth.Header.Set("User-Agent", "packmon-cli/integration")
	respNoAuth, err := integrationHTTPDo(reqNoAuth)
	if err != nil {
		t.Fatalf("POST /api/v1/check without auth: %v", err)
	}
	closeSilently(respNoAuth.Body)
	if respNoAuth.StatusCode != http.StatusUnauthorized {
		t.Fatalf("POST /api/v1/check without auth status = %d, want 401", respNoAuth.StatusCode)
	}

	assertProductionAPIStatus(t, http.MethodPost, baseURL+"/api/v1/check", apiKey, "", checkReqBody, http.StatusForbidden, "missing User-Agent")
	assertProductionAPIStatus(t, http.MethodPost, baseURL+"/api/v1/check", apiKey, "unknown-client/integration", checkReqBody, http.StatusForbidden, "unknown User-Agent")
	assertProductionAPIStatus(t, http.MethodPost, baseURL+"/api/v1/check", expiredAPIKey, "packmon-cli/integration", checkReqBody, http.StatusUnauthorized, "expired API key")
	assertProductionAPIStatus(t, http.MethodPost, baseURL+"/api/v1/check", revokedAPIKey, "packmon-cli/integration", checkReqBody, http.StatusUnauthorized, "revoked API key")
	assertProductionAPIStatus(t, http.MethodPost, baseURL+"/api/v1/check", deletedAPIKey, "packmon-cli/integration", checkReqBody, http.StatusUnauthorized, "deleted API key")
	assertProductionCheckIdempotency(t, baseURL, apiKey)

	importBody, err := json.Marshal(map[string]any{
		"malicious": []map[string]any{
			{
				"id":        "MAL-PROD-1",
				"ecosystem": "npm",
				"name":      "left-pad-evil",
				"risk_type": "malware",
				"severity":  "CRITICAL",
				"summary":   "malicious package",
			},
		},
		"status": map[string]any{
			"last_sync_status": "success",
			"entries_synced":   1,
			"entries_total":    1,
		},
	})
	if err != nil {
		t.Fatalf("json.Marshal import body: %v", err)
	}

	assertProductionAPIStatus(t, http.MethodPost, baseURL+"/api/v1/feeds/openssf/import", apiKey, "packmon-cli/integration", importBody, http.StatusForbidden, "missing feed import secret")
	importWrongSecretReq := newProductionAPIRequest(t, http.MethodPost, baseURL+"/api/v1/feeds/openssf/import", apiKey, "packmon-cli/integration", importBody)
	importWrongSecretReq.Header.Set("X-Packmon-Feed-Import-Secret", "wrong-secret")
	importWrongSecretResp, err := integrationHTTPDo(importWrongSecretReq)
	if err != nil {
		t.Fatalf("POST malicious import with wrong secret: %v", err)
	}
	closeSilently(importWrongSecretResp.Body)
	if importWrongSecretResp.StatusCode != http.StatusForbidden {
		t.Fatalf("POST malicious import with wrong secret status = %d, want 403", importWrongSecretResp.StatusCode)
	}

	importReq, err := http.NewRequest(http.MethodPost, baseURL+"/api/v1/feeds/openssf/import", bytes.NewReader(importBody))
	if err != nil {
		t.Fatalf("NewRequest import: %v", err)
	}
	importReq.Header.Set("Content-Type", "application/json")
	importReq.Header.Set("Authorization", "Bearer "+apiKey)
	importReq.Header.Set("X-Packmon-Feed-Import-Secret", feedImportSecret)
	importReq.Header.Set("User-Agent", "packmon-cli/integration")
	importResp, err := integrationHTTPDo(importReq)
	if err != nil {
		t.Fatalf("POST malicious import: %v", err)
	}
	closeSilently(importResp.Body)
	if importResp.StatusCode != http.StatusOK {
		t.Fatalf("POST malicious import status = %d, want 200", importResp.StatusCode)
	}

	vulnImportBody, err := json.Marshal(map[string]any{
		"vulnerabilities": []map[string]any{
			{
				"id":       "GHSA-PROD-0001",
				"summary":  "production vulnerability import",
				"severity": "HIGH",
				"affected_packages": []map[string]any{
					{
						"ecosystem": "npm",
						"name":      "left-pad-vuln-a",
						"version_ranges": []map[string]any{{
							"type":   "SEMVER",
							"events": []map[string]string{{"introduced": "0"}, {"fixed": "9.9.9"}},
						}},
					},
				},
			},
			{
				"id":       "GHSA-PROD-0002",
				"summary":  "production vulnerability import second row",
				"severity": "MEDIUM",
				"affected_packages": []map[string]any{
					{
						"ecosystem": "npm",
						"name":      "left-pad-vuln-b",
						"version_ranges": []map[string]any{{
							"type":   "SEMVER",
							"events": []map[string]string{{"introduced": "0"}, {"fixed": "9.9.9"}},
						}},
					},
				},
			},
		},
		"status": map[string]any{
			"last_sync_status": "success",
			"entries_synced":   2,
			"entries_total":    2,
		},
	})
	if err != nil {
		t.Fatalf("json.Marshal vulnerability import body: %v", err)
	}
	vulnImportReq := newProductionAPIRequest(t, http.MethodPost, baseURL+"/api/v1/feeds/osv/import", apiKey, "packmon-cli/integration", vulnImportBody)
	vulnImportReq.Header.Set("X-Packmon-Feed-Import-Secret", feedImportSecret)
	vulnImportResp, err := integrationHTTPDo(vulnImportReq)
	if err != nil {
		t.Fatalf("POST vulnerability import: %v", err)
	}
	closeSilently(vulnImportResp.Body)
	if vulnImportResp.StatusCode != http.StatusOK {
		t.Fatalf("POST vulnerability import status = %d, want 200", vulnImportResp.StatusCode)
	}

	vulnCheckReqBody, err := json.Marshal(map[string]any{
		"packages": []map[string]string{
			{"name": "left-pad-vuln-a", "version": "2.0.0", "ecosystem": "npm"},
		},
	})
	if err != nil {
		t.Fatalf("json.Marshal vulnerability check body: %v", err)
	}
	vulnCheckReq := newProductionAPIRequest(t, http.MethodPost, baseURL+"/api/v1/check", apiKey, "packmon-cli/integration", vulnCheckReqBody)
	vulnCheckResp, err := integrationHTTPDo(vulnCheckReq)
	if err != nil {
		t.Fatalf("POST /api/v1/check after vulnerability import: %v", err)
	}
	defer closeSilently(vulnCheckResp.Body)
	if vulnCheckResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(vulnCheckResp.Body)
		t.Fatalf("POST /api/v1/check after vulnerability import status = %d, body = %s", vulnCheckResp.StatusCode, string(body))
	}
	var vulnerabilityResult domain.ScanResult
	if err := json.NewDecoder(vulnCheckResp.Body).Decode(&vulnerabilityResult); err != nil {
		t.Fatalf("decode vulnerability scan result: %v", err)
	}
	assertProductionVulnerabilityScanResult(t, vulnerabilityResult)

	pagedSyncReq, err := http.NewRequest(http.MethodGet, baseURL+"/api/v1/sync?limit=1", nil)
	if err != nil {
		t.Fatalf("NewRequest paged sync: %v", err)
	}
	pagedSyncReq.Header.Set("Authorization", "Bearer "+apiKey)
	pagedSyncReq.Header.Set("User-Agent", "packmon-cli/integration")
	pagedSyncResp, err := integrationHTTPDo(pagedSyncReq)
	if err != nil {
		t.Fatalf("GET /api/v1/sync?limit=1: %v", err)
	}
	defer closeSilently(pagedSyncResp.Body)
	if pagedSyncResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(pagedSyncResp.Body)
		t.Fatalf("GET /api/v1/sync?limit=1 status = %d, body = %s", pagedSyncResp.StatusCode, string(body))
	}
	var firstSyncPage synccontract.Response
	if err := json.NewDecoder(pagedSyncResp.Body).Decode(&firstSyncPage); err != nil {
		t.Fatalf("decode first sync page: %v", err)
	}
	if !firstSyncPage.Truncated || firstSyncPage.NextCursor == nil {
		t.Fatalf("first sync page missing next cursor: %+v", firstSyncPage)
	}
	if len(firstSyncPage.Vulnerabilities) != 1 {
		t.Fatalf("first sync page vulnerabilities = %d, want 1: %+v", len(firstSyncPage.Vulnerabilities), firstSyncPage.Vulnerabilities)
	}
	secondSyncURL := baseURL + "/api/v1/sync?limit=1&" + syncCursorQuery(firstSyncPage.NextCursor)
	secondPagedSyncReq, err := http.NewRequest(http.MethodGet, secondSyncURL, nil)
	if err != nil {
		t.Fatalf("NewRequest second paged sync: %v", err)
	}
	secondPagedSyncReq.Header.Set("Authorization", "Bearer "+apiKey)
	secondPagedSyncReq.Header.Set("User-Agent", "packmon-cli/integration")
	secondPagedSyncResp, err := integrationHTTPDo(secondPagedSyncReq)
	if err != nil {
		t.Fatalf("GET second /api/v1/sync page: %v", err)
	}
	defer closeSilently(secondPagedSyncResp.Body)
	if secondPagedSyncResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(secondPagedSyncResp.Body)
		t.Fatalf("GET second /api/v1/sync page status = %d, body = %s", secondPagedSyncResp.StatusCode, string(body))
	}
	var secondSyncPage synccontract.Response
	if err := json.NewDecoder(secondPagedSyncResp.Body).Decode(&secondSyncPage); err != nil {
		t.Fatalf("decode second sync page: %v", err)
	}
	if len(secondSyncPage.Vulnerabilities) != 1 {
		t.Fatalf("second sync page vulnerabilities = %d, want 1: %+v", len(secondSyncPage.Vulnerabilities), secondSyncPage.Vulnerabilities)
	}
	if firstSyncPage.Vulnerabilities[0].ID == secondSyncPage.Vulnerabilities[0].ID {
		t.Fatalf("sync pagination duplicated vulnerability %q across pages", firstSyncPage.Vulnerabilities[0].ID)
	}

	syncReq, err := http.NewRequest(http.MethodGet, baseURL+"/api/v1/sync", nil)
	if err != nil {
		t.Fatalf("NewRequest sync: %v", err)
	}
	syncReq.Header.Set("Authorization", "Bearer "+apiKey)
	syncReq.Header.Set("User-Agent", "packmon-cli/integration")
	syncResp, err := integrationHTTPDo(syncReq)
	if err != nil {
		t.Fatalf("GET /api/v1/sync: %v", err)
	}
	defer closeSilently(syncResp.Body)
	if syncResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(syncResp.Body)
		t.Fatalf("GET /api/v1/sync status = %d, body = %s", syncResp.StatusCode, string(body))
	}

	projectDir := t.TempDir()
	dbDir := filepath.Join(t.TempDir(), "db")
	lockContent := `{
  "name": "prod-sync-test",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "prod-sync-test",
      "version": "1.0.0"
    },
    "node_modules/left-pad-evil": {
      "version": "1.2.3"
    }
  }
}`
	if err := os.WriteFile(filepath.Join(projectDir, "package-lock.json"), []byte(lockContent), 0o644); err != nil {
		t.Fatalf("write package-lock.json: %v", err)
	}

	jsonFile := filepath.Join(projectDir, "scan.json")
	stdout, stderr, exitCode := runPackmonWithEnv(t, map[string]string{
		"PACKMON_DB_PATH": dbDir,
		"PACKMON_API_KEY": apiKey,
	}, "scan", projectDir, "--mode", "remote", "--server", baseURL, "--insecure-allow-http", "--output-json", jsonFile)
	if exitCode != 1 {
		t.Fatalf("packmon remote scan exit=%d stdout=%s stderr=%s", exitCode, stdout, stderr)
	}
	remoteResult := readScanResultFile(t, jsonFile)
	assertProductionMaliciousScanResult(t, remoteResult, domain.ScanModeRemote)

	if stdout, stderr, exitCode := runPackmonWithEnv(t, map[string]string{
		"PACKMON_DB_PATH": dbDir,
		"PACKMON_API_KEY": apiKey,
	}, "db", "sync", "--server", baseURL, "--insecure-allow-http"); exitCode != 0 {
		t.Fatalf("packmon db sync against production server exit=%d stdout=%s stderr=%s", exitCode, stdout, stderr)
	}

	localJSONFile := filepath.Join(projectDir, "local-scan.json")
	stdout, stderr, exitCode = runPackmonWithEnv(t, map[string]string{
		"PACKMON_DB_PATH": dbDir,
	}, "scan", projectDir, "--mode", "local", "--output-json", localJSONFile)
	if exitCode != 1 {
		t.Fatalf("packmon local scan after production db sync exit=%d stdout=%s stderr=%s", exitCode, stdout, stderr)
	}
	localResult := readScanResultFile(t, localJSONFile)
	assertProductionMaliciousScanResult(t, localResult, domain.ScanModeLocal)
}

func TestProductionAdminRoutesExerciseCriticalWorkflows(t *testing.T) {
	t.Parallel()

	containerName, baseURL := startProductionServerWithPostgres(t, "packmon-admin-it", "integration-import-secret")
	adminClient := newAdminIntegrationClient(t)

	loginBody := adminGETBody(t, adminClient, baseURL+"/admin/login")
	csrf := extractInputValue(t, loginBody, "_csrf")
	adminPostForm(t, adminClient, baseURL+"/admin/login", url.Values{
		"_csrf":    {csrf},
		"username": {"admin"},
		"password": {"integration-admin"},
	}, "/admin/")

	settingsBody := adminGETBody(t, adminClient, baseURL+"/admin/settings")
	csrf = extractInputValue(t, settingsBody, "_csrf")
	rotatedPassword := "integration-admin-rotated-123"
	adminPostForm(t, adminClient, baseURL+"/admin/settings/password", url.Values{
		"_csrf":            {csrf},
		"current_password": {"integration-admin"},
		"new_password":     {rotatedPassword},
		"confirm_password": {rotatedPassword},
	}, "/admin/settings?")

	settingsBody = adminGETBody(t, adminClient, baseURL+"/admin/settings")
	csrf = extractInputValue(t, settingsBody, "_csrf")
	adminPostForm(t, adminClient, baseURL+"/admin/settings/system", url.Values{
		"_csrf":                    {csrf},
		"block_threshold":          {"NONE"},
		"ack_block_threshold_none": {"on"},
		"rate_limit_per_minute":    {"121"},
		"rate_limit_burst":         {"31"},
	}, "/admin/settings?")
	assertPostgresValue(t, containerName,
		`SELECT block_threshold || '|' || rate_limit_per_minute::text || '|' || rate_limit_burst::text FROM system_settings WHERE id = 1`,
		"NONE|121|31",
		"system settings")
	assertPostgresCountAtLeast(t, containerName, `SELECT COUNT(*) FROM admin_audit_log WHERE action = 'system_settings_save'`, 1, "system settings audit")

	feedsBody := adminGETBody(t, adminClient, baseURL+"/admin/feeds")
	csrf = extractInputValue(t, feedsBody, "_csrf")
	adminPostForm(t, adminClient, baseURL+"/admin/feeds/save", url.Values{
		"_csrf":         {csrf},
		"feed_name":     {"osv"},
		"enabled":       {"on"},
		"mode":          {"self"},
		"sync_interval": {"45m"},
	}, "/admin/feeds?")
	assertPostgresValue(t, containerName,
		`SELECT enabled::text || '|' || mode || '|' || COALESCE(EXTRACT(EPOCH FROM sync_interval)::int::text, '') FROM feed_configs WHERE feed_name = 'osv'`,
		"true|self|2700",
		"feed settings")
	assertPostgresCountAtLeast(t, containerName, `SELECT COUNT(*) FROM admin_audit_log WHERE action = 'feed_config_save'`, 1, "feed settings audit")

	queueJobID := queryPostgresValueInContainer(t, containerName,
		`INSERT INTO refresh_queue (ecosystem, name, source, priority, status) VALUES ('npm', 'admin-queue-prod', 'osv', 3, 'pending') RETURNING id`)
	queueBody := adminGETBody(t, adminClient, baseURL+"/admin/queue")
	csrf = extractInputValue(t, queueBody, "_csrf")
	adminPostForm(t, adminClient, baseURL+"/admin/queue/priority", url.Values{
		"_csrf":    {csrf},
		"job_id":   {queueJobID},
		"priority": {"0"},
	}, "/admin/queue?")
	assertPostgresValue(t, containerName,
		fmt.Sprintf(`SELECT priority::text FROM refresh_queue WHERE id = %s`, queueJobID),
		"0",
		"queue job priority")
	assertPostgresCountAtLeast(t, containerName, `SELECT COUNT(*) FROM admin_audit_log WHERE action = 'queue_priority_update'`, 1, "queue priority audit")

	keysBody := adminGETBody(t, adminClient, baseURL+"/admin/keys")
	csrf = extractInputValue(t, keysBody, "_csrf")
	createNonce := extractInputValue(t, keysBody, "create_nonce")
	keyName := "prod-admin-created"
	expiresAt := time.Now().UTC().Add(24 * time.Hour).Truncate(time.Second).Format(time.RFC3339)
	adminPostForm(t, adminClient, baseURL+"/admin/keys/create", url.Values{
		"_csrf":            {csrf},
		"create_nonce":     {createNonce},
		"name":             {keyName},
		"expires_at":       {expiresAt},
		"current_password": {rotatedPassword},
	}, "/admin/keys?")
	keysBody = adminGETBody(t, adminClient, baseURL+"/admin/keys?msg=API+key+created")
	adminAPIKey := extractInputValue(t, keysBody, "new_api_key")
	if adminAPIKey == "" {
		t.Fatal("admin-created API key was empty")
	}
	assertPostgresValue(t, containerName,
		fmt.Sprintf(`SELECT name || '|' || key_hash || '|' || (expires_at IS NOT NULL)::text || '|' || (revoked_at IS NULL)::text || '|' || (deleted_at IS NULL)::text FROM api_keys WHERE name = %s`, postgresLiteral(keyName)),
		keyName+"|"+hashSHA256(adminAPIKey)+"|true|true|true",
		"admin-created API key")
	assertPostgresCountAtLeast(t, containerName, `SELECT COUNT(*) FROM admin_audit_log WHERE action = 'api_key_create'`, 1, "api key create audit")

	advisoriesBody := adminGETBody(t, adminClient, baseURL+"/admin/advisories")
	csrf = extractInputValue(t, advisoriesBody, "_csrf")
	adminPostForm(t, adminClient, baseURL+"/admin/advisories/create", url.Values{
		"_csrf":        {csrf},
		"id":           {"manual:prod-admin-advisory"},
		"finding_type": {"vulnerability"},
		"ecosystem":    {"npm"},
		"name":         {"admin-manual-vuln"},
		"severity":     {"HIGH"},
		"summary":      {"admin-created vulnerability"},
		"description":  {"created through the production admin form"},
	}, "/admin/advisories?")
	assertPostgresValue(t, containerName,
		`SELECT COUNT(*)::text
		FROM vulnerabilities v
		INNER JOIN vulnerability_sources vs ON vs.vulnerability_id = v.id
		INNER JOIN affected_packages ap ON ap.vulnerability_id = v.id
		WHERE v.id = 'manual:prod-admin-advisory'
		  AND vs.source = 'manual'
		  AND ap.ecosystem = 'npm'
		  AND ap.name = 'admin-manual-vuln'
		  AND v.severity = 'HIGH'
		  AND v.withdrawn IS NULL`,
		"1",
		"manual advisory")
	assertPostgresCountAtLeast(t, containerName, `SELECT COUNT(*) FROM admin_audit_log WHERE action = 'advisory_create'`, 1, "manual advisory audit")

	checkBody, err := json.Marshal(map[string]any{
		"packages": []map[string]string{
			{"name": "admin-manual-vuln", "version": "1.0.0", "ecosystem": "npm"},
		},
	})
	if err != nil {
		t.Fatalf("json.Marshal admin manual check body: %v", err)
	}
	checkReq := newProductionAPIRequest(t, http.MethodPost, baseURL+"/api/v1/check", adminAPIKey, "packmon-cli/integration", checkBody)
	checkResp, err := integrationHTTPDo(checkReq)
	if err != nil {
		t.Fatalf("POST /api/v1/check with admin-created API key: %v", err)
	}
	defer closeSilently(checkResp.Body)
	if checkResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(checkResp.Body)
		t.Fatalf("POST /api/v1/check with admin-created API key status = %d, body = %s", checkResp.StatusCode, string(body))
	}
	var result domain.ScanResult
	if err := json.NewDecoder(checkResp.Body).Decode(&result); err != nil {
		t.Fatalf("decode admin manual advisory scan result: %v", err)
	}
	assertProductionAdminManualAdvisoryScanResult(t, result)
}

func TestProductionServerRefusesUnmigratedPostgres(t *testing.T) {
	t.Parallel()

	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatalf("docker not available; tagged integration tests require Docker: %v", err)
	}

	containerName, dbPort := startIntegrationPostgres(t, "packmon-unmigrated-it")
	serverBin := serverBinaryPath(t)
	env := productionServerEnv(dbPort, "integration-import-secret")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, serverBin)
	cmd.Env = env
	output, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		t.Fatalf("production server kept running against unmigrated database; output:\n%s", string(output))
	}
	if err == nil {
		t.Fatalf("production server started against unmigrated database; output:\n%s", string(output))
	}
	outputText := string(output)
	if !strings.Contains(outputText, "schema") && !strings.Contains(outputText, "migration") {
		t.Fatalf("startup refusal output should mention schema or migration; output:\n%s", outputText)
	}
	if got := postgresRegclass(t, containerName, "public.schema_migrations"); got != "" {
		t.Fatalf("normal production startup created schema_migrations = %q; startup must not migrate", got)
	}
}

func productionServerEnv(dbPort int, feedImportSecret string) []string {
	return []string{
		"PACKMON_SERVER_MODE=production",
		"PACKMON_SERVER_PORT=0",
		"PACKMON_SERVER_PUBLIC_HOST=127.0.0.1",
		"PACKMON_ALLOW_INSECURE_LOCAL_HTTP=true",
		"PACKMON_METRICS_PORT=0",
		"PACKMON_LOG_LEVEL=info",
		"PACKMON_LOG_FORMAT=json",
		"PACKMON_DB_HOST=127.0.0.1",
		fmt.Sprintf("PACKMON_DB_PORT=%d", dbPort),
		"PACKMON_DB_NAME=packmon",
		"PACKMON_DB_USER=packmon",
		"PACKMON_DB_PASSWORD=packmon",
		"PACKMON_DB_SSLMODE=disable",
		"PACKMON_ADMIN_INITIAL_PASSWORD=integration-admin",
		"PACKMON_ENCRYPTION_KEY=MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
		"PACKMON_ADMIN_AUDIT_HMAC_KEY=MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
		"PACKMON_FEED_IMPORT_SECRET=" + feedImportSecret,
		"PACKMON_FEED_OSV_ENABLED=false",
		"PACKMON_FEED_GHSA_ENABLED=false",
		"PACKMON_FEED_OPENSSF_ENABLED=false",
		"PACKMON_FEED_VULNCHECK_ENABLED=false",
		"PACKMON_FEED_SOCKET_ENABLED=false",
		"PACKMON_FEED_CISAKEV_ENABLED=false",
		"PACKMON_FEED_EPSS_ENABLED=false",
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
		"USERPROFILE=" + os.Getenv("USERPROFILE"),
		"TEMP=" + os.Getenv("TEMP"),
		"TMP=" + os.Getenv("TMP"),
	}
}

func startProductionServerWithPostgres(t *testing.T, namePrefix, feedImportSecret string) (containerName, baseURL string) {
	t.Helper()

	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatalf("docker not available; tagged integration tests require Docker: %v", err)
	}

	containerName, dbPort := startIntegrationPostgres(t, namePrefix)
	serverBin := serverBinaryPath(t)
	env := productionServerEnv(dbPort, feedImportSecret)

	runMigrateWithRetry(t, serverBin, env)

	cmd, cancelServer := integrationLongRunningCommand(t, serverBin)
	cmd.Env = env

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		t.Fatalf("stderr pipe: %v", err)
	}
	logs := &serverProcessLogs{}
	addrCh := make(chan serverBoundAddr, 4)
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start production server: %v", err)
	}
	go scanServerStdout(stdoutPipe, logs, addrCh)
	go scanServerStderr(stderrPipe, logs)
	t.Cleanup(func() {
		cancelServer()
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})

	addrs := waitForServerBoundAddrs(t, addrCh, logs, 15*time.Second)
	baseURL = loopbackHTTPURL(t, addrs.main)
	waitForHTTPStatus(t, baseURL+"/healthz", http.StatusOK, logs.String())
	return containerName, baseURL
}

func readScanResultFile(t *testing.T, path string) domain.ScanResult {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read scan result %s: %v", path, err)
	}
	var result domain.ScanResult
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("decode scan result %s: %v\n%s", path, err, string(data))
	}
	return result
}

func assertProductionMaliciousScanResult(t *testing.T, result domain.ScanResult, wantMode domain.ScanMode) {
	t.Helper()

	if result.Mode != wantMode {
		t.Fatalf("ScanResult.Mode = %q, want %q", result.Mode, wantMode)
	}
	if !result.FindingsBlocking {
		t.Fatalf("FindingsBlocking = false, want malicious finding to block: %+v", result)
	}
	if result.FindingsCount < 1 || result.Summary.ByType[string(domain.FindingTypeMalicious)] < 1 {
		t.Fatalf("malicious finding count missing: count=%d summary=%+v findings=%+v", result.FindingsCount, result.Summary, result.Findings)
	}

	for _, finding := range result.Findings {
		if finding.AdvisoryID != "MAL-PROD-1" {
			continue
		}
		if finding.Type != domain.FindingTypeMalicious {
			t.Fatalf("MAL-PROD-1 Type = %q, want malicious", finding.Type)
		}
		if finding.RiskType != "malware" {
			t.Fatalf("MAL-PROD-1 RiskType = %q, want malware", finding.RiskType)
		}
		if finding.Severity != domain.SeverityCritical {
			t.Fatalf("MAL-PROD-1 Severity = %q, want CRITICAL", finding.Severity)
		}
		if finding.Ecosystem != domain.EcosystemNPM || finding.Name != "left-pad-evil" || finding.Version != "1.2.3" {
			t.Fatalf("MAL-PROD-1 package = %s/%s@%s, want npm/left-pad-evil@1.2.3", finding.Ecosystem, finding.Name, finding.Version)
		}
		if finding.Source != "openssf" {
			t.Fatalf("MAL-PROD-1 Source = %q, want openssf", finding.Source)
		}
		return
	}
	t.Fatalf("scan result missing MAL-PROD-1 finding: %+v", result.Findings)
}

func assertProductionVulnerabilityScanResult(t *testing.T, result domain.ScanResult) {
	t.Helper()

	if result.Mode != domain.ScanModeRemote {
		t.Fatalf("vulnerability ScanResult.Mode = %q, want remote", result.Mode)
	}
	if result.FindingsCount < 1 || result.Summary.BySeverity[string(domain.SeverityHigh)] < 1 {
		t.Fatalf("vulnerability finding summary missing: count=%d summary=%+v findings=%+v", result.FindingsCount, result.Summary, result.Findings)
	}
	for _, finding := range result.Findings {
		if finding.AdvisoryID != "GHSA-PROD-0001" {
			continue
		}
		if finding.Type != domain.FindingTypeVulnerability {
			t.Fatalf("GHSA-PROD-0001 Type = %q, want vulnerability", finding.Type)
		}
		if finding.Severity != domain.SeverityHigh {
			t.Fatalf("GHSA-PROD-0001 Severity = %q, want HIGH", finding.Severity)
		}
		if finding.Ecosystem != domain.EcosystemNPM || finding.Name != "left-pad-vuln-a" || finding.Version != "2.0.0" {
			t.Fatalf("GHSA-PROD-0001 package = %s/%s@%s, want npm/left-pad-vuln-a@2.0.0", finding.Ecosystem, finding.Name, finding.Version)
		}
		if finding.Source != "osv" {
			t.Fatalf("GHSA-PROD-0001 Source = %q, want osv", finding.Source)
		}
		return
	}
	t.Fatalf("scan result missing GHSA-PROD-0001 finding: %+v", result.Findings)
}

func assertProductionAdminManualAdvisoryScanResult(t *testing.T, result domain.ScanResult) {
	t.Helper()

	if result.Mode != domain.ScanModeRemote {
		t.Fatalf("admin manual advisory ScanResult.Mode = %q, want remote", result.Mode)
	}
	if result.BlockThreshold != domain.SeverityNone {
		t.Fatalf("admin manual advisory BlockThreshold = %q, want NONE", result.BlockThreshold)
	}
	if result.FindingsBlocking {
		t.Fatalf("admin manual advisory FindingsBlocking = true, want false for vulnerability with threshold NONE: %+v", result)
	}
	for _, finding := range result.Findings {
		if finding.AdvisoryID != "manual:prod-admin-advisory" {
			continue
		}
		if finding.Type != domain.FindingTypeVulnerability {
			t.Fatalf("manual:prod-admin-advisory Type = %q, want vulnerability", finding.Type)
		}
		if finding.Severity != domain.SeverityHigh {
			t.Fatalf("manual:prod-admin-advisory Severity = %q, want HIGH", finding.Severity)
		}
		if finding.Ecosystem != domain.EcosystemNPM || finding.Name != "admin-manual-vuln" || finding.Version != "1.0.0" {
			t.Fatalf("manual:prod-admin-advisory package = %s/%s@%s, want npm/admin-manual-vuln@1.0.0", finding.Ecosystem, finding.Name, finding.Version)
		}
		if finding.Source != domain.ManualAdvisorySource {
			t.Fatalf("manual:prod-admin-advisory Source = %q, want %q", finding.Source, domain.ManualAdvisorySource)
		}
		return
	}
	t.Fatalf("scan result missing manual:prod-admin-advisory finding: %+v", result.Findings)
}

func startIntegrationPostgres(t *testing.T, namePrefix string) (containerName string, hostPort int) {
	t.Helper()

	containerName = fmt.Sprintf("%s-%d", namePrefix, time.Now().UnixNano())
	run, ctx, cancel := integrationCommandWithTimeout(t, 30*time.Second, "docker", "run", "-d", "--rm",
		"--name", containerName,
		"-e", "POSTGRES_DB=packmon",
		"-e", "POSTGRES_USER=packmon",
		"-e", "POSTGRES_PASSWORD=packmon",
		"-p", "127.0.0.1::5432",
		postgresIntegrationImage,
	)
	defer cancel()
	out, err := run.Output()
	failIfIntegrationCommandTimedOut(t, ctx, 30*time.Second, "docker run postgres", out)
	if err != nil {
		t.Fatalf("docker run postgres: %v", err)
	}
	containerID := strings.TrimSpace(string(out))

	t.Cleanup(func() {
		removeDockerContainer(t, containerName)
		removeDockerContainer(t, containerID)
	})

	hostPort = dockerPublishedPort(t, containerName, "5432/tcp")
	waitForDockerPostgres(t, containerName)
	return containerName, hostPort
}

func dockerPublishedPort(t *testing.T, containerName, containerPort string) int {
	t.Helper()

	cmd, ctx, cancel := integrationCommandWithTimeout(t, 10*time.Second, "docker", "port", containerName, containerPort)
	defer cancel()
	out, err := cmd.Output()
	failIfIntegrationCommandTimedOut(t, ctx, 10*time.Second, "docker port "+containerName, out)
	if err != nil {
		t.Fatalf("docker port %s %s: %v", containerName, containerPort, err)
	}
	lines := strings.Fields(strings.TrimSpace(string(out)))
	if len(lines) == 0 {
		t.Fatalf("docker port %s %s returned no mapping", containerName, containerPort)
	}
	_, port, err := net.SplitHostPort(lines[len(lines)-1])
	if err != nil {
		t.Fatalf("parse docker port mapping %q: %v", lines[len(lines)-1], err)
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		t.Fatalf("parse docker host port %q: %v", port, err)
	}
	return n
}

func waitForDockerPostgres(t *testing.T, containerName string) {
	t.Helper()

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		cmd, _, cancel := integrationCommandWithTimeout(t, 5*time.Second, "docker", "exec", containerName, "pg_isready", "-h", "127.0.0.1", "-p", "5432", "-U", "packmon", "-d", "packmon")
		if err := cmd.Run(); err == nil {
			cancel()
			return
		}
		cancel()
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("postgres container %s did not become ready", containerName)
}

func runMigrateWithRetry(t *testing.T, serverBin string, env []string) {
	t.Helper()

	var lastErr error
	var lastOutput []byte

	for attempt := 0; attempt < 3; attempt++ {
		migrate, ctx, cancel := integrationCommandWithTimeout(t, 20*time.Second, serverBin, "migrate")
		migrate.Env = env
		output, err := migrate.CombinedOutput()
		if ctx.Err() == context.DeadlineExceeded {
			err = ctx.Err()
		}
		cancel()
		if err == nil {
			return
		}
		lastErr = err
		lastOutput = output
		time.Sleep(500 * time.Millisecond)
	}

	t.Fatalf("packmon-server migrate failed: %v\n%s", lastErr, string(lastOutput))
}

func waitForHTTPStatus(t *testing.T, url string, want int, stderr string) {
	t.Helper()

	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := integrationHTTPGet(url)
		if err == nil {
			closeSilently(resp.Body)
			if resp.StatusCode == want {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("endpoint %s did not return %d; server stderr: %s", url, want, stderr)
}

func removeDockerContainer(t *testing.T, id string) {
	t.Helper()
	if strings.TrimSpace(id) == "" {
		return
	}

	cmd, _, cancel := integrationCommandWithTimeout(t, 10*time.Second, "docker", "rm", "-f", id)
	defer cancel()
	_ = cmd.Run()
}

func insertAPIKeyIntoContainer(containerName, keyHash string) error {
	return execPostgresSQLInContainer(containerName, fmt.Sprintf("INSERT INTO api_keys(name, key_hash) VALUES ('integration', '%s');", keyHash))
}

func insertInactiveAPIKeysIntoContainer(containerName string, keyHashes map[string]string) error {
	sql := strings.Join([]string{
		fmt.Sprintf("INSERT INTO api_keys(name, key_hash, expires_at) VALUES ('expired', '%s', NOW() - INTERVAL '1 hour');", keyHashes["expired"]),
		fmt.Sprintf("INSERT INTO api_keys(name, key_hash, revoked_at) VALUES ('revoked', '%s', NOW());", keyHashes["revoked"]),
		fmt.Sprintf("INSERT INTO api_keys(name, key_hash, revoked_at, deleted_at) VALUES ('deleted', '%s', NOW(), NOW());", keyHashes["deleted"]),
	}, "\n")
	return execPostgresSQLInContainer(containerName, sql)
}

func execPostgresSQLInContainer(containerName, sql string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", "exec", containerName, // #nosec G204 -- tagged integration test executes fixed docker command with test-controlled arguments.
		"psql", "-h", "127.0.0.1", "-p", "5432", "-U", "packmon", "-d", "packmon",
		"-c", sql,
	)
	output, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return fmt.Errorf("docker exec psql timed out after 10s: %s", string(output))
	}
	if err != nil {
		return fmt.Errorf("%w: %s", err, string(output))
	}
	return nil
}

func queryPostgresValueInContainer(t *testing.T, containerName, sql string) string {
	t.Helper()

	cmd, ctx, cancel := integrationCommandWithTimeout(t, 10*time.Second, "docker", "exec", containerName,
		"psql", "-h", "127.0.0.1", "-p", "5432", "-U", "packmon", "-d", "packmon",
		"-q", "-A", "-t", "-c", sql,
	)
	defer cancel()
	output, err := cmd.CombinedOutput()
	failIfIntegrationCommandTimedOut(t, ctx, 10*time.Second, "docker exec psql query", output)
	if err != nil {
		t.Fatalf("docker exec psql query failed: %v\n%s", err, string(output))
	}
	return strings.TrimSpace(string(output))
}

func assertPostgresValue(t *testing.T, containerName, sql, want, label string) {
	t.Helper()

	if got := queryPostgresValueInContainer(t, containerName, sql); got != want {
		t.Fatalf("%s query = %q, want %q", label, got, want)
	}
}

func assertPostgresCountAtLeast(t *testing.T, containerName, sql string, wantMin int, label string) {
	t.Helper()

	raw := queryPostgresValueInContainer(t, containerName, sql)
	got, err := strconv.Atoi(raw)
	if err != nil {
		t.Fatalf("%s count query returned %q: %v", label, raw, err)
	}
	if got < wantMin {
		t.Fatalf("%s count = %d, want at least %d", label, got, wantMin)
	}
}

func postgresLiteral(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

func newAdminIntegrationClient(t *testing.T) *http.Client {
	t.Helper()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("create cookie jar: %v", err)
	}
	return &http.Client{
		Timeout: integrationHTTPTimeout,
		Jar:     jar,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func adminGETBody(t *testing.T, client *http.Client, endpoint string) string {
	t.Helper()

	resp, err := client.Get(endpoint)
	if err != nil {
		t.Fatalf("GET %s: %v", endpoint, err)
	}
	defer closeSilently(resp.Body)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read GET %s body: %v", endpoint, err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s status = %d, want 200; body = %s", endpoint, resp.StatusCode, string(body))
	}
	return string(body)
}

func adminPostForm(t *testing.T, client *http.Client, endpoint string, values url.Values, wantLocationPrefix string) {
	t.Helper()

	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(values.Encode()))
	if err != nil {
		t.Fatalf("NewRequest POST %s: %v", endpoint, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", endpoint, err)
	}
	defer closeSilently(resp.Body)
	if resp.StatusCode != http.StatusSeeOther {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("POST %s status = %d, want 303; body = %s", endpoint, resp.StatusCode, string(body))
	}
	if got := resp.Header.Get("Location"); wantLocationPrefix != "" && !strings.HasPrefix(got, wantLocationPrefix) {
		t.Fatalf("POST %s Location = %q, want prefix %q", endpoint, got, wantLocationPrefix)
	}
}

func extractInputValue(t *testing.T, body, name string) string {
	t.Helper()

	pattern := regexp.MustCompile(`<input\b[^>]*\bname="` + regexp.QuoteMeta(name) + `"[^>]*\bvalue="([^"]*)"`)
	matches := pattern.FindStringSubmatch(body)
	if len(matches) != 2 {
		t.Fatalf("input %q with value not found in response body", name)
	}
	return html.UnescapeString(matches[1])
}

func newProductionAPIRequest(t *testing.T, method, endpoint, apiKey, userAgent string, body []byte) *http.Request {
	t.Helper()

	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, endpoint, reader)
	if err != nil {
		t.Fatalf("NewRequest %s %s: %v", method, endpoint, err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
	if userAgent != "" {
		req.Header.Set("User-Agent", userAgent)
	}
	return req
}

func assertProductionAPIStatus(t *testing.T, method, endpoint, apiKey, userAgent string, body []byte, want int, label string) {
	t.Helper()

	resp, err := integrationHTTPDo(newProductionAPIRequest(t, method, endpoint, apiKey, userAgent, body))
	if err != nil {
		t.Fatalf("%s: %s %s: %v", label, method, endpoint, err)
	}
	closeSilently(resp.Body)
	if resp.StatusCode != want {
		t.Fatalf("%s: %s %s status = %d, want %d", label, method, endpoint, resp.StatusCode, want)
	}
}

func assertProductionCheckIdempotency(t *testing.T, baseURL, apiKey string) {
	t.Helper()

	checkBody, err := json.Marshal(map[string]any{
		"packages": []map[string]string{
			{"name": "left-pad-idempotent", "version": "1.0.0", "ecosystem": "npm"},
		},
	})
	if err != nil {
		t.Fatalf("json.Marshal idempotency check body: %v", err)
	}
	key := "prod-idempotency-1"
	first := newProductionAPIRequest(t, http.MethodPost, baseURL+"/api/v1/check", apiKey, "packmon-cli/integration", checkBody)
	first.Header.Set("Idempotency-Key", key)
	firstResp, err := integrationHTTPDo(first)
	if err != nil {
		t.Fatalf("first idempotent check: %v", err)
	}
	defer closeSilently(firstResp.Body)
	if firstResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(firstResp.Body)
		t.Fatalf("first idempotent check status = %d, body = %s", firstResp.StatusCode, string(body))
	}
	var firstResult domain.ScanResult
	if err := json.NewDecoder(firstResp.Body).Decode(&firstResult); err != nil {
		t.Fatalf("decode first idempotent check: %v", err)
	}
	if got := firstResp.Header.Get("Idempotency-Key"); got != key {
		t.Fatalf("first Idempotency-Key header = %q, want %q", got, key)
	}

	second := newProductionAPIRequest(t, http.MethodPost, baseURL+"/api/v1/check", apiKey, "packmon-cli/integration", checkBody)
	second.Header.Set("Idempotency-Key", key)
	secondResp, err := integrationHTTPDo(second)
	if err != nil {
		t.Fatalf("second idempotent check: %v", err)
	}
	defer closeSilently(secondResp.Body)
	if secondResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(secondResp.Body)
		t.Fatalf("second idempotent check status = %d, body = %s", secondResp.StatusCode, string(body))
	}
	var secondResult domain.ScanResult
	if err := json.NewDecoder(secondResp.Body).Decode(&secondResult); err != nil {
		t.Fatalf("decode second idempotent check: %v", err)
	}
	if firstResult.ScanID != secondResult.ScanID {
		t.Fatalf("idempotent replay scan_id = %q, want %q", secondResult.ScanID, firstResult.ScanID)
	}
	if got := secondResp.Header.Get("Idempotency-Key"); got != key {
		t.Fatalf("second Idempotency-Key header = %q, want %q", got, key)
	}

	conflictBody, err := json.Marshal(map[string]any{
		"packages": []map[string]string{
			{"name": "left-pad-idempotent-conflict", "version": "1.0.0", "ecosystem": "npm"},
		},
	})
	if err != nil {
		t.Fatalf("json.Marshal idempotency conflict body: %v", err)
	}
	conflict := newProductionAPIRequest(t, http.MethodPost, baseURL+"/api/v1/check", apiKey, "packmon-cli/integration", conflictBody)
	conflict.Header.Set("Idempotency-Key", key)
	conflictResp, err := integrationHTTPDo(conflict)
	if err != nil {
		t.Fatalf("conflicting idempotent check: %v", err)
	}
	closeSilently(conflictResp.Body)
	if conflictResp.StatusCode != http.StatusConflict {
		t.Fatalf("conflicting idempotent check status = %d, want 409", conflictResp.StatusCode)
	}
}

func syncCursorQuery(cursor *synccontract.Cursor) string {
	values := url.Values{}
	values.Set("vulnerabilities_offset", strconv.Itoa(cursor.Vulnerabilities))
	values.Set("malicious_offset", strconv.Itoa(cursor.Malicious))
	values.Set("reputation_offset", strconv.Itoa(cursor.Reputation))
	values.Set("lifecycle_offset", strconv.Itoa(cursor.Lifecycle))
	if cursor.VulnerabilitiesCursor != "" {
		values.Set("vulnerabilities_cursor", cursor.VulnerabilitiesCursor)
	}
	if cursor.MaliciousCursor != "" {
		values.Set("malicious_cursor", cursor.MaliciousCursor)
	}
	if cursor.ReputationCursor != "" {
		values.Set("reputation_cursor", cursor.ReputationCursor)
	}
	if cursor.LifecycleCursor != "" {
		values.Set("lifecycle_cursor", cursor.LifecycleCursor)
	}
	if cursor.VulnerabilitiesDone {
		values.Set("vulnerabilities_done", "true")
	}
	if cursor.MaliciousDone {
		values.Set("malicious_done", "true")
	}
	if cursor.ReputationDone {
		values.Set("reputation_done", "true")
	}
	if cursor.LifecycleDone {
		values.Set("lifecycle_done", "true")
	}
	return values.Encode()
}

func postgresRegclass(t *testing.T, containerName, relation string) string {
	t.Helper()

	cmd, ctx, cancel := integrationCommandWithTimeout(t, 10*time.Second, "docker", "exec", containerName,
		"psql", "-h", "127.0.0.1", "-p", "5432", "-U", "packmon", "-d", "packmon", "-tAc",
		fmt.Sprintf("SELECT COALESCE(to_regclass('%s')::text, '')", relation),
	)
	defer cancel()
	output, err := cmd.CombinedOutput()
	failIfIntegrationCommandTimedOut(t, ctx, 10*time.Second, "docker exec query regclass", output)
	if err != nil {
		t.Fatalf("query regclass %s: %v\n%s", relation, err, string(output))
	}
	return strings.TrimSpace(string(output))
}

func hashSHA256(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}
