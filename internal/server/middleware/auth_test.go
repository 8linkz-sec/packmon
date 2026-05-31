package middleware

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/8linkz/packmon/internal/db"
)

type authStoreStub struct {
	db.Store
	apiKey *db.APIKey
	err    error
}

func (s *authStoreStub) FindAPIKeyByHash(_ context.Context, keyHash string) (*db.APIKey, error) {
	if s.err != nil {
		return nil, s.err
	}
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

func TestAuthRejectsExpiredBearerTokenInProduction(t *testing.T) {
	t.Parallel()

	expiredAt := time.Now().Add(-time.Minute)
	store := &authStoreStub{
		apiKey: &db.APIKey{
			ID:        1,
			Name:      "expired-ci",
			KeyHash:   hashToken("expired-key"),
			ExpiresAt: &expiredAt,
		},
	}
	handler := Auth(slog.New(slog.NewTextHandler(io.Discard, nil)), store, false)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/check", nil)
	req.Header.Set("Authorization", "Bearer expired-key")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
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

func TestAuthDevelopmentAllowsReadAPIWithoutKey(t *testing.T) {
	t.Parallel()

	handler := Auth(slog.New(slog.NewTextHandler(io.Discard, nil)), &authStoreStub{}, true)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/check", nil)
	req.RemoteAddr = "203.0.113.10:44444"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
}

func TestAuthRejectsInvalidAndLookupError(t *testing.T) {
	t.Parallel()

	t.Run("invalid token", func(t *testing.T) {
		t.Parallel()
		handler := Auth(slog.New(slog.NewTextHandler(io.Discard, nil)), &authStoreStub{}, false)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))
		req := httptest.NewRequest(http.MethodPost, "/api/v1/check", nil)
		req.Header.Set("Authorization", "Bearer wrong")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}
	})

	t.Run("lookup error", func(t *testing.T) {
		t.Parallel()
		handler := Auth(slog.New(slog.NewTextHandler(io.Discard, nil)), &authStoreStub{err: errors.New("db down")}, false)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))
		req := httptest.NewRequest(http.MethodPost, "/api/v1/check", nil)
		req.Header.Set("Authorization", "Bearer secret")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500", rec.Code)
		}
	})
}

func TestAuthHelpers(t *testing.T) {
	t.Parallel()

	if !requiresAuthInDev("/api/v1/feeds/osv/import") {
		t.Fatal("feeds import should require auth in dev from non-loopback peers")
	}
	if requiresAuthInDev("/api/v1/check") {
		t.Fatal("check endpoint should not require auth in dev")
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Basic abc")
	if got := extractBearerToken(req); got != "" {
		t.Fatalf("extractBearerToken(Basic) = %q, want empty", got)
	}
	req.Header.Set("Authorization", "Bearer   secret  ")
	if got := extractBearerToken(req); got != "secret" {
		t.Fatalf("extractBearerToken(Bearer) = %q, want secret", got)
	}
}
