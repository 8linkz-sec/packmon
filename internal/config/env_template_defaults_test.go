package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestEnvExampleQueueAndIdentityDefaultsMatchRuntime keeps the two metadata
// retention controls that are easy to omit from deployment templates aligned
// with the package-private runtime defaults.
func TestEnvExampleQueueAndIdentityDefaultsMatchRuntime(t *testing.T) {
	clearPackmonEnv(t)

	data, err := os.ReadFile(filepath.Join("..", "..", ".env.example"))
	if err != nil {
		t.Fatalf("read .env.example: %v", err)
	}
	values := make(map[string]string)
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if ok {
			values[strings.TrimSpace(key)] = strings.TrimSpace(value)
		}
	}

	retention, err := loadRetentionConfig()
	if err != nil {
		t.Fatalf("load runtime retention defaults: %v", err)
	}
	templateQueue, err := time.ParseDuration(values["PACKMON_REFRESH_QUEUE_RETENTION"])
	if err != nil {
		t.Fatalf("parse template PACKMON_REFRESH_QUEUE_RETENTION: %v", err)
	}
	if templateQueue != retention.RefreshQueue {
		t.Fatalf("template refresh-queue retention = %s, runtime default = %s", templateQueue, retention.RefreshQueue)
	}

	runtimeIdentity, err := ScanLogIdentityModeFromEnv()
	if err != nil {
		t.Fatalf("load runtime scan-log identity default: %v", err)
	}
	templateIdentity, err := ParseScanLogIdentityMode(values["PACKMON_SCAN_LOG_IDENTITY_MODE"])
	if err != nil {
		t.Fatalf("parse template PACKMON_SCAN_LOG_IDENTITY_MODE: %v", err)
	}
	if templateIdentity != runtimeIdentity {
		t.Fatalf("template scan-log identity mode = %q, runtime default = %q", templateIdentity, runtimeIdentity)
	}
}
