package auth

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/8linkz/packmon/internal/db"
)

type bootstrapStoreStub struct {
	db.Store
	auth      *db.AdminAuth
	getErr    error
	upsertErr error
	upserts   int
	audits    int
}

func (s *bootstrapStoreStub) GetAdminAuth(context.Context) (*db.AdminAuth, error) {
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
	s.auth = &db.AdminAuth{PasswordHash: passwordHash, PasswordIsBootstrap: isBootstrap}
	return nil
}

func (s *bootstrapStoreStub) InsertAdminAuditLog(context.Context, *db.AdminAuditEntry) error {
	s.audits++
	return nil
}

func TestBootstrapAdminBranches(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	existing := &bootstrapStoreStub{auth: &db.AdminAuth{PasswordHash: "hash"}}
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
	if !CheckPassword(created.auth.PasswordHash, "initial-password") {
		t.Fatal("created password hash does not validate")
	}

	getErr := &bootstrapStoreStub{getErr: errors.New("db down")}
	if err := BootstrapAdmin(context.Background(), getErr, "password", logger); err == nil || !strings.Contains(err.Error(), "check existing admin") {
		t.Fatalf("BootstrapAdmin(get error) error = %v", err)
	}

	upsertErr := &bootstrapStoreStub{upsertErr: errors.New("write failed")}
	if err := BootstrapAdmin(context.Background(), upsertErr, "password", logger); err == nil || !strings.Contains(err.Error(), "bootstrap admin") {
		t.Fatalf("BootstrapAdmin(upsert error) error = %v", err)
	}
}
