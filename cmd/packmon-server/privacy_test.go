package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
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
	closes   int
	order    *[]string
}

func (s *privacyExportStoreStub) ExportPrivacyMetadata(_ context.Context, selector db.PrivacyExportSelector, audit *db.AdminAuditEntry) (*db.PrivacyExport, error) {
	if s.order != nil {
		*s.order = append(*s.order, "export")
	}
	s.selector = selector
	s.audit = audit
	if s.err != nil {
		return nil, s.err
	}
	return s.export, nil
}

func (s *privacyExportStoreStub) Close() error {
	if s.order != nil {
		*s.order = append(*s.order, "close")
	}
	s.closed = true
	s.closes++
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
		{raw: " client-ip = 2001:db8::1 ", want: db.PrivacyExportSelector{Type: db.PrivacySelectorClientIP, Value: "2001:db8::1"}},
		{raw: "repo-name=org/repo=component", want: db.PrivacyExportSelector{Type: db.PrivacySelectorRepoName, Value: "org/repo=component"}},
		{raw: "client-ip=not-ip", wantErr: "invalid client-ip"},
		{raw: "api-key-id=0", wantErr: "invalid api-key-id"},
		{raw: "api-key-id=-1", wantErr: "invalid api-key-id"},
		{raw: "api-key-id=abc", wantErr: "invalid api-key-id"},
		{raw: "api-key-id=999999999999999999999999999999999999999", wantErr: "invalid api-key-id"},
		{raw: "package=left-pad", wantErr: "unsupported privacy export selector type"},
		{raw: "missing-separator", wantErr: "type=value"},
		{raw: "=value", wantErr: "type and value are required"},
		{raw: "repo-name=", wantErr: "type and value are required"},
		{raw: "   =   ", wantErr: "type and value are required"},
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
	var order []string
	generatedAt := time.Date(2026, 6, 28, 12, 0, 0, 0, time.UTC)
	store := &privacyExportStoreStub{
		order: &order,
		export: &db.PrivacyExport{
			GeneratedAt: generatedAt,
			Selector:    db.PrivacyExportSelector{Type: db.PrivacySelectorClientIP, Value: "203.0.113.10"},
			ScanLogs: []db.PrivacyExportScanLog{{
				ScanID:   "scan-1",
				ClientIP: "203.0.113.10",
			}},
			AdminAuditLogs:  []db.PrivacyExportAdminAudit{{ID: 7, Action: "admin_login"}},
			ScanLogCount:    1,
			AdminAuditCount: 1,
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
	var decoded db.PrivacyExport
	if err := json.Unmarshal([]byte(out), &decoded); err != nil {
		t.Fatalf("decode privacy export: %v; output=%s", err, out)
	}
	if !decoded.GeneratedAt.Equal(generatedAt) || decoded.Selector != store.export.Selector || decoded.ScanLogCount != 1 || decoded.AdminAuditCount != 1 {
		t.Fatalf("decoded export metadata = %+v, want %+v", decoded, store.export)
	}
	if len(decoded.ScanLogs) != 1 || decoded.ScanLogs[0].ScanID != "scan-1" || decoded.ScanLogs[0].ClientIP != "203.0.113.10" {
		t.Fatalf("decoded scan rows = %+v, want exact fixture", decoded.ScanLogs)
	}
	if len(decoded.AdminAuditLogs) != 1 || decoded.AdminAuditLogs[0].ID != 7 || decoded.AdminAuditLogs[0].Action != "admin_login" {
		t.Fatalf("decoded audit rows = %+v, want exact fixture", decoded.AdminAuditLogs)
	}
	if strings.Join(order, ",") != "version,open,export,close" {
		t.Fatalf("privacy export order = %v, want version/open/export/close", order)
	}
}

func TestRunPrivacyExportDoesNotWriteJSONWhenStoreFails(t *testing.T) {
	store := &privacyExportStoreStub{err: errors.Join(db.ErrAdminAuditLog, errors.New("audit failed"))}
	out := runPrivacyExportWithStubExpectError(t, store, "admin audit log write failed", "--selector", "client-ip=203.0.113.10")
	if out != "" {
		t.Fatalf("privacy export output after failure = %q, want empty", out)
	}
}

func TestRunPrivacyDispatch(t *testing.T) {
	if err := runPrivacy(nil); err == nil || !strings.Contains(err.Error(), "usage:") {
		t.Fatalf("runPrivacy(nil) error = %v, want usage", err)
	}
	if err := runPrivacy([]string{"erase"}); err == nil || !strings.Contains(err.Error(), `unknown privacy command "erase"`) {
		t.Fatalf("runPrivacy(unknown) error = %v", err)
	}

	store := &privacyExportStoreStub{export: &db.PrivacyExport{}}
	out := runPrivacyWithStubExpectError(t, store, "", true, "--selector", "correlation-id=corr=42", "--format", "json")
	if store.selector != (db.PrivacyExportSelector{Type: db.PrivacySelectorCorrelationID, Value: "corr=42"}) {
		t.Fatalf("dispatch selector = %+v, want exact forwarded export args", store.selector)
	}
	if strings.TrimSpace(out) == "" {
		t.Fatal("dispatch produced no JSON")
	}
}

func TestRunPrivacyExportRejectsArgumentsBeforeDatabaseAccess(t *testing.T) {
	originalVersion := readDatabaseMigrationVersionContext
	originalOpen := openPrivacyExportStore
	originalOutput := privacyExportOutput
	t.Cleanup(func() {
		readDatabaseMigrationVersionContext = originalVersion
		openPrivacyExportStore = originalOpen
		privacyExportOutput = originalOutput
		db.ClearAdminAuditDigestHMACKey()
	})

	var schemaCalls, openCalls int
	readDatabaseMigrationVersionContext = func(context.Context, string) (uint, bool, error) {
		schemaCalls++
		return uint(migrations.ExpectedVersion), false, nil
	}
	openPrivacyExportStore = func(context.Context, string, time.Duration) (privacyExportStore, error) {
		openCalls++
		return &privacyExportStoreStub{}, nil
	}

	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "invalid flag", args: []string{"--invalid"}, want: "flag provided but not defined"},
		{name: "positional argument", args: []string{"--selector", "repo-name=org/repo", "extra"}, want: "unexpected privacy export argument"},
		{name: "unsupported format", args: []string{"--selector", "repo-name=org/repo", "--format", "xml"}, want: "unsupported privacy export format"},
		{name: "missing selector", args: nil, want: "type=value"},
		{name: "invalid selector", args: []string{"--selector", "client-ip=invalid"}, want: "invalid client-ip"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var output bytes.Buffer
			privacyExportOutput = &output
			err := runPrivacyExport(tt.args)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("runPrivacyExport() error = %v, want containing %q", err, tt.want)
			}
			if output.Len() != 0 {
				t.Fatalf("output = %q, want empty", output.String())
			}
		})
	}
	if schemaCalls != 0 || openCalls != 0 {
		t.Fatalf("database calls after argument rejection = schema:%d open:%d, want zero", schemaCalls, openCalls)
	}
}

func TestRunPrivacyExportPreDatabaseFailureMatrix(t *testing.T) {
	originalVersion := readDatabaseMigrationVersionContext
	originalOpen := openPrivacyExportStore
	originalOutput := privacyExportOutput
	t.Cleanup(func() {
		readDatabaseMigrationVersionContext = originalVersion
		openPrivacyExportStore = originalOpen
		privacyExportOutput = originalOutput
		db.ClearAdminAuditDigestHMACKey()
	})

	var schemaCalls, openCalls int
	readDatabaseMigrationVersionContext = func(context.Context, string) (uint, bool, error) {
		schemaCalls++
		return uint(migrations.ExpectedVersion), false, nil
	}
	openPrivacyExportStore = func(context.Context, string, time.Duration) (privacyExportStore, error) {
		openCalls++
		return &privacyExportStoreStub{}, nil
	}

	tests := []struct {
		name    string
		dbPort  string
		hmac    string
		wantErr string
	}{
		{name: "configuration", dbPort: "invalid", hmac: f018EncodedSecret(), wantErr: "PACKMON_DB_PORT"},
		{name: "missing production HMAC", dbPort: "5432", hmac: "", wantErr: "PACKMON_ADMIN_AUDIT_HMAC_KEY is required"},
		{name: "invalid production HMAC", dbPort: "5432", hmac: "%%%", wantErr: "PACKMON_ADMIN_AUDIT_HMAC_KEY"},
		{name: "wrong-length production HMAC", dbPort: "5432", hmac: base64.StdEncoding.EncodeToString([]byte("short")), wantErr: "PACKMON_ADMIN_AUDIT_HMAC_KEY"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("PACKMON_SERVER_MODE", "production")
			t.Setenv("PACKMON_DB_PORT", tt.dbPort)
			t.Setenv("PACKMON_ADMIN_AUDIT_HMAC_KEY", tt.hmac)
			var output bytes.Buffer
			privacyExportOutput = &output
			err := runPrivacyExport([]string{"--selector", "repo-name=org/repo"})
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("runPrivacyExport() error = %v, want containing %q", err, tt.wantErr)
			}
			if output.Len() != 0 {
				t.Fatalf("output = %q, want empty", output.String())
			}
		})
	}
	if schemaCalls != 0 || openCalls != 0 {
		t.Fatalf("database calls after pre-database failure = schema:%d open:%d, want zero", schemaCalls, openCalls)
	}
}

func TestRunPrivacyExportSchemaRefusalMatrix(t *testing.T) {
	originalVersion := readDatabaseMigrationVersionContext
	originalOpen := openPrivacyExportStore
	originalOutput := privacyExportOutput
	t.Cleanup(func() {
		readDatabaseMigrationVersionContext = originalVersion
		openPrivacyExportStore = originalOpen
		privacyExportOutput = originalOutput
		db.ClearAdminAuditDigestHMACKey()
	})
	f019SetValidProductionEnvironment(t)

	versionErr := errors.New("version unavailable")
	tests := []struct {
		name    string
		version uint
		dirty   bool
		err     error
		want    string
	}{
		{name: "read error", err: versionErr, want: "read schema version for privacy export"},
		{name: "dirty", version: 12, dirty: true, want: "schema is dirty at version 12"},
		{name: "mismatch", version: uint(migrations.ExpectedVersion) - 1, want: "schema version"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var order []string
			readDatabaseMigrationVersionContext = func(context.Context, string) (uint, bool, error) {
				order = append(order, "version")
				return tt.version, tt.dirty, tt.err
			}
			openPrivacyExportStore = func(context.Context, string, time.Duration) (privacyExportStore, error) {
				order = append(order, "open")
				return &privacyExportStoreStub{}, nil
			}
			var output bytes.Buffer
			privacyExportOutput = &output
			err := runPrivacyExport([]string{"--selector", "repo-name=org/repo"})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("runPrivacyExport() error = %v, want containing %q", err, tt.want)
			}
			if strings.Join(order, ",") != "version" {
				t.Fatalf("call order = %v, want version only", order)
			}
			if output.Len() != 0 {
				t.Fatalf("output = %q, want empty", output.String())
			}
		})
	}
}

func TestRunPrivacyExportStoreFailureMatrix(t *testing.T) {
	originalVersion := readDatabaseMigrationVersionContext
	originalOpen := openPrivacyExportStore
	originalOutput := privacyExportOutput
	t.Cleanup(func() {
		readDatabaseMigrationVersionContext = originalVersion
		openPrivacyExportStore = originalOpen
		privacyExportOutput = originalOutput
		db.ClearAdminAuditDigestHMACKey()
	})
	f019SetValidProductionEnvironment(t)
	readDatabaseMigrationVersionContext = func(context.Context, string) (uint, bool, error) {
		return uint(migrations.ExpectedVersion), false, nil
	}

	t.Run("open", func(t *testing.T) {
		openErr := errors.New("open failed")
		openPrivacyExportStore = func(context.Context, string, time.Duration) (privacyExportStore, error) {
			return nil, openErr
		}
		var output bytes.Buffer
		privacyExportOutput = &output
		err := runPrivacyExport([]string{"--selector", "repo-name=org/repo"})
		if !errors.Is(err, openErr) || output.Len() != 0 {
			t.Fatalf("runPrivacyExport() = %v, output %q; want open error and no JSON", err, output.String())
		}
	})

	t.Run("audited export", func(t *testing.T) {
		exportErr := errors.Join(db.ErrAdminAuditLog, errors.New("audit failed"))
		store := &privacyExportStoreStub{err: exportErr}
		openPrivacyExportStore = func(context.Context, string, time.Duration) (privacyExportStore, error) {
			return store, nil
		}
		var output bytes.Buffer
		privacyExportOutput = &output
		err := runPrivacyExport([]string{"--selector", "repo-name=org/repo"})
		if !errors.Is(err, db.ErrAdminAuditLog) || output.Len() != 0 {
			t.Fatalf("runPrivacyExport() = %v, output %q; want audit error and no JSON", err, output.String())
		}
		if store.closes != 1 {
			t.Fatalf("store closes = %d, want 1", store.closes)
		}
	})
}

func TestRunPrivacyDefaultStoreOpenerRejectsUnavailableDatabase(t *testing.T) {
	originalOpen := openPrivacyExportStore
	t.Cleanup(func() { openPrivacyExportStore = originalOpen })

	port := f018ClosedLoopbackPort(t)
	timeout := 50 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	dsn := fmt.Sprintf("postgres://packmon:packmon@127.0.0.1:%d/packmon?sslmode=disable", port)

	store, err := originalOpen(ctx, dsn, timeout)
	if err == nil {
		if store != nil {
			_ = store.Close()
		}
		t.Fatal("openPrivacyExportStore() error = nil, want bounded PostgreSQL connection failure")
	}
	if !strings.Contains(err.Error(), "postgres: ping") {
		t.Fatalf("openPrivacyExportStore() error = %v, want PostgreSQL ping failure", err)
	}
}

func TestRunPrivacyExportEncoderFailureClosesStore(t *testing.T) {
	originalVersion := readDatabaseMigrationVersionContext
	originalOpen := openPrivacyExportStore
	originalOutput := privacyExportOutput
	t.Cleanup(func() {
		readDatabaseMigrationVersionContext = originalVersion
		openPrivacyExportStore = originalOpen
		privacyExportOutput = originalOutput
		db.ClearAdminAuditDigestHMACKey()
	})
	f019SetValidProductionEnvironment(t)
	readDatabaseMigrationVersionContext = func(context.Context, string) (uint, bool, error) {
		return uint(migrations.ExpectedVersion), false, nil
	}
	store := &privacyExportStoreStub{export: &db.PrivacyExport{}}
	openPrivacyExportStore = func(context.Context, string, time.Duration) (privacyExportStore, error) {
		return store, nil
	}
	writeErr := errors.New("writer failed")
	privacyExportOutput = f019ErrorWriter{err: writeErr}
	err := runPrivacyExport([]string{"--selector", "repo-name=org/repo"})
	if !errors.Is(err, writeErr) || !strings.Contains(err.Error(), "write privacy export JSON") {
		t.Fatalf("runPrivacyExport() error = %v, want wrapped writer error", err)
	}
	if store.closes != 1 {
		t.Fatalf("store closes = %d, want 1", store.closes)
	}
}

func runPrivacyExportWithStub(t *testing.T, store *privacyExportStoreStub, args ...string) string {
	t.Helper()
	return runPrivacyExportWithStubExpectError(t, store, "", args...)
}

func runPrivacyExportWithStubExpectError(t *testing.T, store *privacyExportStoreStub, wantErr string, args ...string) string {
	return runPrivacyWithStubExpectError(t, store, wantErr, false, args...)
}

func runPrivacyWithStubExpectError(t *testing.T, store *privacyExportStoreStub, wantErr string, throughDispatch bool, args ...string) string {
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
		if store.order != nil {
			*store.order = append(*store.order, "version")
		}
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("privacy export schema context has no deadline")
		}
		if dsn == "" {
			t.Fatal("privacy export DSN is empty")
		}
		return uint(migrations.ExpectedVersion), false, nil
	}
	openPrivacyExportStore = func(ctx context.Context, dsn string, timeout time.Duration) (privacyExportStore, error) {
		if store.order != nil {
			*store.order = append(*store.order, "open")
		}
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

	var err error
	if throughDispatch {
		err = runPrivacy(append([]string{"export"}, args...))
	} else {
		err = runPrivacyExport(args)
	}
	if wantErr == "" {
		if err != nil {
			t.Fatalf("runPrivacyExport() error = %v", err)
		}
	} else if err == nil || !strings.Contains(err.Error(), wantErr) {
		t.Fatalf("runPrivacyExport() error = %v, want containing %q", err, wantErr)
	}
	return output.String()
}

type f019ErrorWriter struct {
	err error
}

func (w f019ErrorWriter) Write([]byte) (int, error) {
	return 0, w.err
}

func f019SetValidProductionEnvironment(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		"PACKMON_DB_HOST",
		"PACKMON_DB_PORT",
		"PACKMON_DB_USER",
		"PACKMON_DB_PASSWORD",
		"PACKMON_DB_NAME",
	} {
		t.Setenv(key, "")
	}
	t.Setenv("PACKMON_SERVER_MODE", "production")
	t.Setenv("PACKMON_ADMIN_AUDIT_HMAC_KEY", f018EncodedSecret())
}
