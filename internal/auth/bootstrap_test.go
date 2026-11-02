package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

type bootstrapStoreStub struct {
	auth             *AdminBootstrapAuth
	getErr           error
	upsertErr        error
	auditErr         error
	upserts          int
	legacyUpserts    int
	auditedUpserts   int
	audits           int
	lastAudit        *AdminBootstrapAuditEntry
	getCalls         int
	auditedAttempts  int
	lastHashAttempt  string
	lastFlagAttempt  bool
	lastAuditAttempt *AdminBootstrapAuditEntry
}

func (s *bootstrapStoreStub) GetAdminBootstrapAuth(context.Context) (*AdminBootstrapAuth, error) {
	s.getCalls++
	if s.getErr != nil {
		return nil, s.getErr
	}
	return s.auth, nil
}

func (s *bootstrapStoreStub) UpsertAdminAuth(_ context.Context, passwordHash string, isBootstrap bool) error {
	if s.upsertErr != nil {
		return s.upsertErr
	}
	s.upserts++
	s.legacyUpserts++
	s.auth = &AdminBootstrapAuth{PasswordHash: passwordHash, PasswordIsBootstrap: isBootstrap}
	return nil
}

func (s *bootstrapStoreStub) InsertAdminAuditLog(_ context.Context, entry *AdminBootstrapAuditEntry) error {
	if s.auditErr != nil {
		return s.auditErr
	}
	s.audits++
	s.lastAudit = cloneAdminBootstrapAuditEntry(entry)
	return nil
}

func (s *bootstrapStoreStub) UpsertAdminBootstrapAuthWithAudit(_ context.Context, passwordHash string, isBootstrap bool, audit *AdminBootstrapAuditEntry) error {
	s.auditedAttempts++
	s.lastHashAttempt = passwordHash
	s.lastFlagAttempt = isBootstrap
	s.lastAuditAttempt = cloneAdminBootstrapAuditEntry(audit)
	if s.auditErr != nil {
		return s.auditErr
	}
	if s.upsertErr != nil {
		return s.upsertErr
	}
	s.upserts++
	s.auditedUpserts++
	s.auth = &AdminBootstrapAuth{PasswordHash: passwordHash, PasswordIsBootstrap: isBootstrap}
	s.audits++
	s.lastAudit = cloneAdminBootstrapAuditEntry(audit)
	return nil
}

func cloneAdminBootstrapAuditEntry(entry *AdminBootstrapAuditEntry) *AdminBootstrapAuditEntry {
	if entry == nil {
		return nil
	}
	copyEntry := *entry
	copyEntry.Details = append(json.RawMessage(nil), entry.Details...)
	return &copyEntry
}

func TestAdminBootstrapStoreDoesNotExposeDatabaseRecords(t *testing.T) {
	t.Parallel()

	source, err := os.ReadFile("auth.go")
	if err != nil {
		t.Fatalf("ReadFile(auth.go) error = %v", err)
	}
	text := string(source)
	dbPackage := "db"
	for _, forbidden := range []string{
		`"github.com/8linkz-sec/packmon/internal/` + dbPackage + `"`,
		"*" + dbPackage + ".AdminAuth",
		"*" + dbPackage + ".AdminAuditEntry",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("auth.go contains %q, want bootstrap port free of database-owned records", forbidden)
		}
	}
}

func TestBootstrapAdminBranches(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	existing := &bootstrapStoreStub{auth: &AdminBootstrapAuth{PasswordHash: "hash"}}
	if err := BootstrapAdmin(context.Background(), existing, "ignored", logger); err != nil {
		t.Fatalf("BootstrapAdmin(existing) error = %v", err)
	}
	if existing.upserts != 0 {
		t.Fatalf("existing upserts = %d, want 0", existing.upserts)
	}

	emptyPassword := &bootstrapStoreStub{}
	if err := BootstrapAdmin(context.Background(), emptyPassword, "", logger); err != nil {
		t.Fatalf("BootstrapAdmin(empty password) error = %v", err)
	}
	if emptyPassword.upserts != 0 {
		t.Fatalf("empty password upserts = %d, want 0", emptyPassword.upserts)
	}

	created := &bootstrapStoreStub{}
	if err := BootstrapAdmin(context.Background(), created, "initial-password", logger); err != nil {
		t.Fatalf("BootstrapAdmin(create) error = %v", err)
	}
	if created.upserts != 1 || created.audits != 1 || created.auth == nil || !created.auth.PasswordIsBootstrap {
		t.Fatalf("created store = %+v", created)
	}
	if created.lastAudit == nil || created.lastAudit.IP != "" || !strings.Contains(string(created.lastAudit.Details), `"actor":"system"`) {
		t.Fatalf("bootstrap audit = %+v, want null IP with system actor details", created.lastAudit)
	}
	if !CheckPassword(created.auth.PasswordHash, "initial-password") {
		t.Fatal("created password hash does not validate")
	}

	weakPassword := &bootstrapStoreStub{}
	if err := BootstrapAdmin(context.Background(), weakPassword, "short", logger); err == nil || !strings.Contains(err.Error(), "at least 12") {
		t.Fatalf("BootstrapAdmin(weak password) error = %v", err)
	}
	if weakPassword.upserts != 0 || weakPassword.audits != 0 {
		t.Fatalf("weak password store = %+v, want no writes", weakPassword)
	}

	getErr := &bootstrapStoreStub{getErr: errors.New("db down")}
	if err := BootstrapAdmin(context.Background(), getErr, "password", logger); err == nil || !strings.Contains(err.Error(), "check existing admin") {
		t.Fatalf("BootstrapAdmin(get error) error = %v", err)
	}

	upsertErr := &bootstrapStoreStub{upsertErr: errors.New("write failed")}
	if err := BootstrapAdmin(context.Background(), upsertErr, "valid-password-123", logger); err == nil || !strings.Contains(err.Error(), "bootstrap admin") {
		t.Fatalf("BootstrapAdmin(upsert error) error = %v", err)
	}

	auditErr := &bootstrapStoreStub{auditErr: errors.New("audit failed")}
	if err := BootstrapAdmin(context.Background(), auditErr, "valid-password-123", logger); err == nil || !strings.Contains(err.Error(), "bootstrap admin") {
		t.Fatalf("BootstrapAdmin(audit error) error = %v", err)
	}
	if auditErr.auth != nil || auditErr.upserts != 0 || auditErr.audits != 0 {
		t.Fatalf("audit failure store = %+v, want no persisted auth or audit", auditErr)
	}
}

func TestBootstrapAdminUsesAuditedWriteWhenAvailable(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store := &bootstrapStoreStub{}

	if err := BootstrapAdmin(context.Background(), store, "initial-password", logger); err != nil {
		t.Fatalf("BootstrapAdmin() error = %v", err)
	}

	if store.auditedUpserts != 1 {
		t.Fatalf("audited upserts = %d, want 1", store.auditedUpserts)
	}
	if store.legacyUpserts != 0 {
		t.Fatalf("legacy upserts = %d, want 0", store.legacyUpserts)
	}
	if store.audits != 1 || store.lastAudit == nil || store.lastAudit.Action != "admin_bootstrap" {
		t.Fatalf("audit = (%d, %+v), want one admin_bootstrap entry", store.audits, store.lastAudit)
	}
	if store.auth == nil || !store.auth.PasswordIsBootstrap || !CheckPassword(store.auth.PasswordHash, "initial-password") {
		t.Fatalf("auth = %+v, want bootstrap password hash", store.auth)
	}
}

// TestBootstrapAdminRejectsPasswordOverBcryptLimitWithoutWrites reports an
// over-long PACKMON_ADMIN_INITIAL_PASSWORD as the password policy violation it
// is, not as a bcrypt hash failure, and writes nothing.
func TestBootstrapAdminRejectsPasswordOverBcryptLimitWithoutWrites(t *testing.T) {
	t.Parallel()

	store := &bootstrapStoreStub{}
	err := BootstrapAdmin(
		context.Background(),
		store,
		strings.Repeat("p", MaxAdminPasswordBytes+1),
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
	if !errors.Is(err, ErrAdminPasswordTooLong) {
		t.Fatalf("BootstrapAdmin(73-byte password) error = %v, want ErrAdminPasswordTooLong", err)
	}
	if errors.Is(err, bcrypt.ErrPasswordTooLong) || strings.Contains(err.Error(), "hash") {
		t.Fatalf("BootstrapAdmin(73-byte password) error = %v, want a policy error rather than a hash error", err)
	}
	if store.auth != nil || store.upserts != 0 || store.audits != 0 {
		t.Fatalf("store after policy error = %+v, want no bootstrap writes or audit", store)
	}
}

func TestBootstrapAdminAuditSchemaAndDiagnosticsExcludeCredentials(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name                string
		password            string
		store               *bootstrapStoreStub
		wantErr             error
		wantErrText         string
		wantAttempt         bool
		wantSuccessfulWrite bool
	}

	tests := []testCase{
		{
			name:     "existing",
			password: "incoming-existing-password",
			store: &bootstrapStoreStub{auth: &AdminBootstrapAuth{
				PasswordHash:        "stored-existing-password-hash",
				PasswordIsBootstrap: true,
			}},
		},
		{
			name:  "missing",
			store: &bootstrapStoreStub{},
		},
		{
			name:        "short",
			password:    strings.Repeat("s", MinAdminPasswordLength-1),
			store:       &bootstrapStoreStub{},
			wantErr:     ErrAdminPasswordTooShort,
			wantErrText: ErrAdminPasswordTooShort.Error(),
		},
		{
			name:        "over_72",
			password:    strings.Repeat("l", MaxAdminPasswordBytes+1),
			store:       &bootstrapStoreStub{},
			wantErr:     ErrAdminPasswordTooLong,
			wantErrText: ErrAdminPasswordTooLong.Error(),
		},
		{
			name:        "lookup",
			password:    "lookup-password-secret",
			store:       &bootstrapStoreStub{getErr: errors.New("lookup unavailable")},
			wantErrText: "auth: check existing admin: lookup unavailable",
		},
		{
			name:        "upsert",
			password:    "upsert-password-secret",
			store:       &bootstrapStoreStub{upsertErr: errors.New("upsert unavailable")},
			wantErrText: "auth: bootstrap admin: upsert unavailable",
			wantAttempt: true,
		},
		{
			name:        "audit",
			password:    "audit-password-secret",
			store:       &bootstrapStoreStub{auditErr: errors.New("audit unavailable")},
			wantErrText: "auth: bootstrap admin: audit unavailable",
			wantAttempt: true,
		},
		{
			name:                "success",
			password:            "success-password-secret",
			store:               &bootstrapStoreStub{},
			wantAttempt:         true,
			wantSuccessfulWrite: true,
		},
	}

	wantDetails := map[string]string{
		"actor": "system",
		"event": "admin_bootstrap",
		"note":  "initial admin password set from environment variable",
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var logs bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&logs, nil))

			err := BootstrapAdmin(context.Background(), tc.store, tc.password, logger)
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("BootstrapAdmin() error = %v, want errors.Is(_, %v)", err, tc.wantErr)
			}
			if tc.wantErrText == "" {
				if err != nil {
					t.Fatalf("BootstrapAdmin() error = %v, want nil", err)
				}
			} else if err == nil || err.Error() != tc.wantErrText {
				t.Fatalf("BootstrapAdmin() error = %v, want %q", err, tc.wantErrText)
			}

			if tc.store.getCalls != 1 {
				t.Fatalf("GetAdminBootstrapAuth calls = %d, want 1", tc.store.getCalls)
			}
			wantAttempts := 0
			if tc.wantAttempt {
				wantAttempts = 1
			}
			if tc.store.auditedAttempts != wantAttempts {
				t.Fatalf("audited write attempts = %d, want %d", tc.store.auditedAttempts, wantAttempts)
			}
			wantSuccessfulWrites := 0
			if tc.wantSuccessfulWrite {
				wantSuccessfulWrites = 1
			}
			if tc.store.upserts != wantSuccessfulWrites || tc.store.auditedUpserts != wantSuccessfulWrites || tc.store.audits != wantSuccessfulWrites {
				t.Fatalf(
					"successful writes = (upserts %d, audited %d, audits %d), want (%d, %d, %d)",
					tc.store.upserts,
					tc.store.auditedUpserts,
					tc.store.audits,
					wantSuccessfulWrites,
					wantSuccessfulWrites,
					wantSuccessfulWrites,
				)
			}
			if tc.store.legacyUpserts != 0 {
				t.Fatalf("legacy upserts = %d, want 0", tc.store.legacyUpserts)
			}

			if tc.wantAttempt {
				if tc.store.lastHashAttempt == "" {
					t.Fatal("attempted password hash is empty")
				}
				if err := bcrypt.CompareHashAndPassword([]byte(tc.store.lastHashAttempt), []byte(tc.password)); err != nil {
					t.Fatalf("attempted bcrypt hash does not match supplied password: %v", err)
				}
				if !tc.store.lastFlagAttempt {
					t.Fatal("attempted bootstrap flag = false, want true")
				}
				assertBootstrapAuditEntry(t, tc.store.lastAuditAttempt, wantDetails)
			} else if tc.store.lastHashAttempt != "" || tc.store.lastFlagAttempt || tc.store.lastAuditAttempt != nil {
				t.Fatalf(
					"unexpected attempted write = (hash %q, bootstrap %t, audit %+v)",
					tc.store.lastHashAttempt,
					tc.store.lastFlagAttempt,
					tc.store.lastAuditAttempt,
				)
			}

			if tc.wantSuccessfulWrite {
				if tc.store.auth == nil || tc.store.auth.PasswordHash != tc.store.lastHashAttempt || !tc.store.auth.PasswordIsBootstrap {
					t.Fatalf("persisted auth = %+v, want observed bootstrap hash", tc.store.auth)
				}
				assertBootstrapAuditEntry(t, tc.store.lastAudit, wantDetails)
			} else if tc.name != "existing" && tc.store.auth != nil {
				t.Fatalf("persisted auth = %+v, want nil", tc.store.auth)
			}

			diagnostics := logs.String()
			if err != nil {
				diagnostics += err.Error()
			}
			if tc.store.lastAuditAttempt != nil {
				diagnostics += tc.store.lastAuditAttempt.Action + string(tc.store.lastAuditAttempt.Details) + tc.store.lastAuditAttempt.IP + tc.store.lastAuditAttempt.CorrelationID
			}
			for _, credential := range []string{tc.password, tc.store.lastHashAttempt} {
				if credential != "" && strings.Contains(diagnostics, credential) {
					t.Fatalf("diagnostics expose credential %q: %q", credential, diagnostics)
				}
			}
			if tc.name == "existing" && strings.Contains(diagnostics, tc.store.auth.PasswordHash) {
				t.Fatalf("diagnostics expose stored password hash: %q", diagnostics)
			}
		})
	}
}

func assertBootstrapAuditEntry(t *testing.T, entry *AdminBootstrapAuditEntry, wantDetails map[string]string) {
	t.Helper()
	if entry == nil {
		t.Fatal("bootstrap audit entry is nil")
	}
	if entry.Action != "admin_bootstrap" {
		t.Fatalf("audit action = %q, want admin_bootstrap", entry.Action)
	}
	if entry.IP != "" || entry.CorrelationID != "" {
		t.Fatalf("audit attribution = (IP %q, correlation %q), want blank", entry.IP, entry.CorrelationID)
	}
	var details map[string]string
	if err := json.Unmarshal(entry.Details, &details); err != nil {
		t.Fatalf("decode audit details: %v", err)
	}
	if !reflect.DeepEqual(details, wantDetails) {
		t.Fatalf("audit details = %#v, want %#v", details, wantDetails)
	}
}
