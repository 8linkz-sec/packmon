package main

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/8linkz-sec/packmon/internal/auth"
	"github.com/8linkz-sec/packmon/internal/db"
)

// testAdminPasswordHash is a fixture stand-in for a stored password hash. It is
// not a credential -- the adapter never verifies it, it only carries it across
// the boundary -- but a literal here trips the hardcoded-credentials scanner.
const testAdminPasswordHash = "argon2id$fixture"

// recordingBootstrapStore captures what the adapter forwarded to the database.
type recordingBootstrapStore struct {
	record       *db.AdminAuth
	getErr       error
	upsertErr    error
	passwordHash string
	isBootstrap  bool
	audit        *db.AdminAuditEntry
	upserts      int
}

func (s *recordingBootstrapStore) GetAdminAuth(context.Context) (*db.AdminAuth, error) {
	if s.getErr != nil {
		return nil, s.getErr
	}
	return s.record, nil
}

func (s *recordingBootstrapStore) UpsertAdminAuthWithAudit(_ context.Context, passwordHash string, isBootstrap bool, audit *db.AdminAuditEntry) error {
	s.upserts++
	s.passwordHash, s.isBootstrap, s.audit = passwordHash, isBootstrap, audit
	return s.upsertErr
}

// TestAdminBootstrapStoreAdapterReportsTheBootstrapFlag covers the read side.
// The flag decides whether the admin UI forces a password change, so carrying it
// across the adapter is what keeps a still-default password gated.
func TestAdminBootstrapStoreAdapterReportsTheBootstrapFlag(t *testing.T) {
	t.Parallel()

	store := &recordingBootstrapStore{record: &db.AdminAuth{
		PasswordHash:        testAdminPasswordHash,
		PasswordIsBootstrap: true,
	}}

	got, err := newAdminBootstrapStore(store).GetAdminBootstrapAuth(context.Background())
	if err != nil {
		t.Fatalf("GetAdminBootstrapAuth: %v", err)
	}
	if got == nil {
		t.Fatal("GetAdminBootstrapAuth returned no record")
	}
	if got.PasswordHash != testAdminPasswordHash {
		t.Errorf("PasswordHash = %q, want the stored hash", got.PasswordHash)
	}
	if !got.PasswordIsBootstrap {
		t.Error("PasswordIsBootstrap = false, want the bootstrap gate to stay active")
	}
}

// TestAdminBootstrapStoreAdapterDistinguishesMissingFromFailed covers the two
// non-record outcomes. A database with no admin row yet is not an error -- that
// is exactly the state bootstrapping exists for -- while a read failure must not
// be reported as "no admin configured", which would re-run the bootstrap.
func TestAdminBootstrapStoreAdapterDistinguishesMissingFromFailed(t *testing.T) {
	t.Parallel()

	missing, err := newAdminBootstrapStore(&recordingBootstrapStore{}).
		GetAdminBootstrapAuth(context.Background())
	if err != nil {
		t.Fatalf("GetAdminBootstrapAuth(no row) = %v, want no error", err)
	}
	if missing != nil {
		t.Fatalf("GetAdminBootstrapAuth(no row) = %+v, want nil", missing)
	}

	readErr := errors.New("admin auth read failed")
	got, err := newAdminBootstrapStore(&recordingBootstrapStore{getErr: readErr}).
		GetAdminBootstrapAuth(context.Background())
	if !errors.Is(err, readErr) {
		t.Fatalf("error = %v, want the read failure", err)
	}
	if got != nil {
		t.Fatalf("a failed read still returned %+v, want nil", got)
	}
}

// TestAdminBootstrapStoreAdapterForwardsTheAuditEntry covers the write side. The
// bootstrap password write is audited, so every field of the entry has to reach
// the database unchanged -- an audit row missing its correlation ID cannot be
// tied back to the request that caused it.
func TestAdminBootstrapStoreAdapterForwardsTheAuditEntry(t *testing.T) {
	t.Parallel()

	store := &recordingBootstrapStore{}
	audit := &auth.AdminBootstrapAuditEntry{
		Action:        "admin_bootstrap",
		Details:       json.RawMessage(`{"actor":"system"}`),
		IP:            "127.0.0.1",
		CorrelationID: "cid-1",
	}

	if err := newAdminBootstrapStore(store).
		UpsertAdminBootstrapAuthWithAudit(context.Background(), testAdminPasswordHash, true, audit); err != nil {
		t.Fatalf("UpsertAdminBootstrapAuthWithAudit: %v", err)
	}

	if store.passwordHash != testAdminPasswordHash || !store.isBootstrap {
		t.Errorf("forwarded (%q, %v), want the hash and the bootstrap flag",
			store.passwordHash, store.isBootstrap)
	}
	if store.audit == nil {
		t.Fatal("no audit entry reached the store")
	}
	if store.audit.Action != "admin_bootstrap" || store.audit.IP != "127.0.0.1" ||
		store.audit.CorrelationID != "cid-1" {
		t.Errorf("audit = %+v, want every field preserved", store.audit)
	}
	if string(store.audit.Details) != `{"actor":"system"}` {
		t.Errorf("audit details = %s, want the payload preserved", store.audit.Details)
	}
}

// TestDBAdminBootstrapAuditEntryClonesTheDetails guards against the auth-layer
// entry and the stored row sharing a buffer, which would let a later mutation
// rewrite a record that is supposed to be immutable.
func TestDBAdminBootstrapAuditEntryClonesTheDetails(t *testing.T) {
	t.Parallel()

	if got := dbAdminBootstrapAuditEntry(nil); got != nil {
		t.Fatalf("dbAdminBootstrapAuditEntry(nil) = %+v, want nil", got)
	}

	details := json.RawMessage(`{"a":1}`)
	converted := dbAdminBootstrapAuditEntry(&auth.AdminBootstrapAuditEntry{
		Action:  "admin_bootstrap",
		Details: details,
	})
	if converted == nil {
		t.Fatal("dbAdminBootstrapAuditEntry returned nil for a valid entry")
	}
	if string(converted.Details) != `{"a":1}` {
		t.Fatalf("details = %s, want the payload preserved", converted.Details)
	}

	details[2] = 'X'
	if string(converted.Details) == string(details) {
		t.Fatal("converted details still alias the source buffer")
	}
}

// TestAdminBootstrapStoreAdapterPropagatesWriteErrors keeps a failed bootstrap
// write visible: silently continuing would leave the server running with no
// admin password set.
func TestAdminBootstrapStoreAdapterPropagatesWriteErrors(t *testing.T) {
	t.Parallel()

	writeErr := errors.New("admin auth write failed")
	store := &recordingBootstrapStore{upsertErr: writeErr}

	err := newAdminBootstrapStore(store).UpsertAdminBootstrapAuthWithAudit(
		context.Background(), "hash", true, &auth.AdminBootstrapAuditEntry{Action: "admin_bootstrap"})
	if !errors.Is(err, writeErr) {
		t.Fatalf("error = %v, want the write failure", err)
	}
}

// TestConfiguredFatalErrorStaysTransparent covers the wrapper used to attach a
// logger to a startup failure. It must not hide the underlying error from
// errors.Is/As, or startup diagnostics would lose their cause.
func TestConfiguredFatalErrorStaysTransparent(t *testing.T) {
	t.Parallel()

	inner := errors.New("transport security is not configured")
	wrapped := &configuredFatalError{err: inner}

	if wrapped.Error() != inner.Error() {
		t.Errorf("Error() = %q, want the inner message", wrapped.Error())
	}
	if !errors.Is(wrapped, inner) {
		t.Error("errors.Is could not see through configuredFatalError")
	}
	if got := wrapped.Unwrap(); !errors.Is(got, inner) {
		t.Errorf("Unwrap() = %v, want the wrapped error", got)
	}
}
