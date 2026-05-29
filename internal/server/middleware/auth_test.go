package middleware

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/8linkz/packmon/internal/db"
)

type authStoreStub struct {
	db.Store
	apiKey *db.APIKey
}

func (s *authStoreStub) FindAPIKeyByHash(_ context.Context, keyHash string) (*db.APIKey, error) {
	if s.apiKey == nil {
		return nil, nil
	}
	if s.apiKey.KeyHash != keyHash {
		return nil, nil
	}
	return s.apiKey, nil
}

func (s *authStoreStub) TouchAPIKeyLastUsed(context.Context, int) error {
	return nil
}

func TestAuthRequiresBearerTokenInProduction(t *testing.T) {
	t.Parallel()

	store := &authStoreStub{}
	handler := Auth(slog.New(slog.NewTextHandler(io.Discard, nil)), store, false)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/check", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestAuthAcceptsValidBearerTokenInProduction(t *testing.T) {
	t.Parallel()

	store := &authStoreStub{
		apiKey: &db.APIKey{
			ID:      1,
			Name:    "test",
			KeyHash: hashToken("secret-key"),
		},
	}
	handler := Auth(slog.New(slog.NewTextHandler(io.Discard, nil)), store, false)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/check", nil)
	req.Header.Set("Authorization", "Bearer secret-key")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
}

func TestAuthAllowsPublicDashboardInProduction(t *testing.T) {
	t.Parallel()

	store := &authStoreStub{}
	handler := Auth(slog.New(slog.NewTextHandler(io.Discard, nil)), store, false)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestAuthSkipsAPIKeyForDevelopmentFeedImportFromLoopback(t *testing.T) {
	t.Parallel()

	store := &authStoreStub{}
	handler := Auth(slog.New(slog.NewTextHandler(io.Discard, nil)), store, true)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/feeds/openssf/import", nil)
	req.RemoteAddr = "127.0.0.1:54321"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
}

func TestAuthRequiresAPIKeyForDevelopmentFeedImportFromNonLoopback(t *testing.T) {
	t.Parallel()

	store := &authStoreStub{}
	handler := Auth(slog.New(slog.NewTextHandler(io.Discard, nil)), store, true)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	// A dev-mode server reachable from a non-loopback peer must still require
	// a valid API key for data-mutating write endpoints.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/feeds/openssf/import", nil)
	req.RemoteAddr = "203.0.113.10:44444"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}
