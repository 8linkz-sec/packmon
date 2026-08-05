package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
	migrations "github.com/8linkz-sec/packmon/internal/db/postgres/migrations"
)

type privacyExportStoreStub struct {
	export   *db.PrivacyExport
	err      error
	selector db.PrivacyExportSelector
	audit    *db.AdminAuditEntry
	closed   bool
}

func (s *privacyExportStoreStub) ExportPrivacyMetadata(_ context.Context, selector db.PrivacyExportSelector, audit *db.AdminAuditEntry) (*db.PrivacyExport, error) {
	s.selector = selector
	s.audit = audit
	if s.err != nil {
		return nil, s.err
	}
	return s.export, nil
}

func (s *privacyExportStoreStub) Close() error {
	s.closed = true
	return nil
}

func TestParsePrivacySelector(t *testing.T) {
	t.Parallel()

	tests := []struct {
		raw     string
		want    db.PrivacyExportSelector
		wantErr string
	}{
		{raw: "client-ip=203.0.113.10", want: db.PrivacyExportSelector{Type: db.PrivacySelectorClientIP, Value: "203.0.113.10"}},
		{raw: "api-key-id=42", want: db.PrivacyExportSelector{Type: db.PrivacySelectorAPIKeyID, Value: "42"}},
		{raw: "repo-name=org/repo", want: db.PrivacyExportSelector{Type: db.PrivacySelectorRepoName, Value: "org/repo"}},
		{raw: "api-key-name=ci runner", want: db.PrivacyExportSelector{Type: db.PrivacySelectorAPIKeyName, Value: "ci runner"}},
		{raw: "correlation-id=corr-1", want: db.PrivacyExportSelector{Type: db.PrivacySelectorCorrelationID, Value: "corr-1"}},
		{raw: "client-ip=not-ip", wantErr: "invalid client-ip"},
		{raw: "api-key-id=0", wantErr: "invalid api-key-id"},
		{raw: "package=left-pad", wantErr: "unsupported privacy export selector type"},
		{raw: "missing-separator", wantErr: "type=value"},
	}
	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			got, err := parsePrivacySelector(tt.raw)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("parsePrivacySelector(%q) error = %v, want containing %q", tt.raw, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parsePrivacySelector(%q) error = %v", tt.raw, err)
			}
			if got != tt.want {
				t.Fatalf("parsePrivacySelector(%q) = %+v, want %+v", tt.raw, got, tt.want)
			}
		})
	}
}

func TestPrivacyExportAuditEntryDoesNotStoreRawSelectorValue(t *testing.T) {
	t.Parallel()

	selector := db.PrivacyExportSelector{Type: db.PrivacySelectorClientIP, Value: "203.0.113.10"}
	audit := privacyExportAuditEntry(selector)
	if audit.Action != "privacy_export" {
		t.Fatalf("audit action = %q, want privacy_export", audit.Action)
	}
	if strings.Contains(string(audit.Details), selector.Value) {
		t.Fatalf("audit details leaked raw selector value: %s", audit.Details)
	}
	var details map[string]string
	if err := json.Unmarshal(audit.Details, &details); err != nil {
		t.Fatalf("audit details JSON error = %v", err)
	}
	if details["selector_type"] != selector.Type {
		t.Fatalf("selector_type detail = %q, want %q", details["selector_type"], selector.Type)
	}
	if details["selector_digest"] != selector.Digest() {
		t.Fatalf("selector_digest detail = %q, want %q", details["selector_digest"], selector.Digest())
	}
}

func TestRunPrivacyExportWritesJSONAfterAuditedStoreSuccess(t *testing.T) {
	store := &privacyExportStoreStub{
		export: &db.PrivacyExport{
			GeneratedAt: time.Date(2026, 6, 28, 12, 0, 0, 0, time.UTC),
			Selector:    db.PrivacyExportSelector{Type: db.PrivacySelectorClientIP, Value: "203.0.113.10"},
			ScanLogs: []db.PrivacyExportScanLog{{
				ScanID:   "scan-1",
				ClientIP: "203.0.113.10",
			}},
			ScanLogCount: 1,
		},
	}
	out := runPrivacyExportWithStub(t, store, "--selector", "client-ip=203.0.113.10")

	if !store.closed {
		t.Fatal("privacy export store was not closed")
	}
	if store.selector.Type != db.PrivacySelectorClientIP || store.selector.Value != "203.0.113.10" {
		t.Fatalf("store selector = %+v, want client IP selector", store.selector)
	}
	if store.audit == nil || strings.Contains(string(store.audit.Details), "203.0.113.10") {
		t.Fatalf("store audit = %+v, want audit without raw selector value", store.audit)
	}
	if !strings.Contains(out, `"scan_id": "scan-1"`) {
		t.Fatalf("privacy export output = %s, want scan row", out)
	}
}

func TestRunPrivacyExportDoesNotWriteJSONWhenStoreFails(t *testing.T) {
	store := &privacyExportStoreStub{err: errors.Join(db.ErrAdminAuditLog, errors.New("audit failed"))}
	out := runPrivacyExportWithStubExpectError(t, store, "admin audit log write failed", "--selector", "client-ip=203.0.113.10")
	if out != "" {
		t.Fatalf("privacy export output after failure = %q, want empty", out)
	}
}

func runPrivacyExportWithStub(t *testing.T, store *privacyExportStoreStub, args ...string) string {
	t.Helper()
	return runPrivacyExportWithStubExpectError(t, store, "", args...)
}

func runPrivacyExportWithStubExpectError(t *testing.T, store *privacyExportStoreStub, wantErr string, args ...string) string {
	t.Helper()

	originalOutput := privacyExportOutput
	originalOpen := openPrivacyExportStore
	originalVersion := readDatabaseMigrationVersionContext
	t.Cleanup(func() {
		privacyExportOutput = originalOutput
		openPrivacyExportStore = originalOpen
		readDatabaseMigrationVersionContext = originalVersion
	})

	for _, key := range []string{
		"PACKMON_DB_HOST",
		"PACKMON_DB_PORT",
		"PACKMON_DB_USER",
		"PACKMON_DB_PASSWORD",
		"PACKMON_DB_NAME",
	} {
		t.Setenv(key, "")
	}
	t.Setenv("PACKMON_ADMIN_AUDIT_HMAC_KEY", base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef")))
	t.Cleanup(db.ClearAdminAuditDigestHMACKey)
	readDatabaseMigrationVersionContext = func(ctx context.Context, dsn string) (uint, bool, error) {
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("privacy export schema context has no deadline")
		}
		if dsn == "" {
			t.Fatal("privacy export DSN is empty")
		}
		return uint(migrations.ExpectedVersion), false, nil
	}
	openPrivacyExportStore = func(ctx context.Context, dsn string, timeout time.Duration) (privacyExportStore, error) {
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("privacy export open context has no deadline")
		}
		if dsn == "" || timeout <= 0 {
			t.Fatalf("openPrivacyExportStore dsn=%q timeout=%s, want configured values", dsn, timeout)
		}
		return store, nil
	}
	var output bytes.Buffer
	privacyExportOutput = &output

	err := runPrivacyExport(args)
	if wantErr == "" {
		if err != nil {
			t.Fatalf("runPrivacyExport() error = %v", err)
		}
	} else if err == nil || !strings.Contains(err.Error(), wantErr) {
		t.Fatalf("runPrivacyExport() error = %v, want containing %q", err, wantErr)
	}
	return output.String()
}
