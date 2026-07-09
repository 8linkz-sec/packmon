package middleware

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/auth"
)

type authStoreStub struct {
	apiKey  *auth.APIKeyCredential
	keyHash string
	err     error
}

func (s *authStoreStub) FindAPIKeyCredentialByHash(_ context.Context, keyHash string) (*auth.APIKeyCredential, error) {
	if s.err != nil {
		return nil, s.err
	}
	if s.apiKey == nil {
		return nil, nil
	}
	if s.keyHash != keyHash {
		return nil, nil
	}
	return s.apiKey, nil
}

func (s *authStoreStub) TouchAPIKeyLastUsed(context.Context, int) error {
	return nil
}

type blockingTouchStore struct {
	authStoreStub
	active        atomic.Int64
	maxActive     atomic.Int64
	started       atomic.Int64
	startedSignal chan struct{}
	release       chan struct{}
}

func newBlockingTouchStore() *blockingTouchStore {
	return &blockingTouchStore{
		startedSignal: make(chan struct{}, 1),
		release:       make(chan struct{}),
	}
}

func (s *blockingTouchStore) TouchAPIKeyLastUsed(ctx context.Context, _ int) error {
	s.started.Add(1)
	select {
	case s.startedSignal <- struct{}{}:
	default:
	}
	active := s.active.Add(1)
	for {
		maxActive := s.maxActive.Load()
		if active <= maxActive || s.maxActive.CompareAndSwap(maxActive, active) {
			break
		}
	}
	defer s.active.Add(-1)
	select {
	case <-s.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *blockingTouchStore) closeRelease() {
	close(s.release)
}

type controlledLastUsedStore struct {
	mu           sync.Mutex
	calls        []int
	callSignal   chan int
	firstStarted chan struct{}
	firstRelease chan struct{}
	blockFirst   bool
	failures     map[int]int
}

func newControlledLastUsedStore() *controlledLastUsedStore {
	return &controlledLastUsedStore{
		callSignal:   make(chan int, 16),
		firstStarted: make(chan struct{}),
		firstRelease: make(chan struct{}),
		failures:     make(map[int]int),
	}
}

func (s *controlledLastUsedStore) TouchAPIKeyLastUsed(ctx context.Context, keyID int) error {
	s.mu.Lock()
	s.calls = append(s.calls, keyID)
	callIndex := len(s.calls)
	if remaining := s.failures[keyID]; remaining > 0 {
		s.failures[keyID] = remaining - 1
		s.mu.Unlock()
		select {
		case s.callSignal <- keyID:
		default:
		}
		return errors.New("transient touch failure")
	}
	s.mu.Unlock()

	select {
	case s.callSignal <- keyID:
	default:
	}

	if s.blockFirst && callIndex == 1 {
		close(s.firstStarted)
		select {
		case <-s.firstRelease:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func (s *controlledLastUsedStore) failNext(keyID, count int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failures[keyID] = count
}

func (s *controlledLastUsedStore) callsSnapshot() []int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]int(nil), s.calls...)
}

func waitForLastUsedCall(t *testing.T, store *controlledLastUsedStore, want int) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case got := <-store.callSignal:
			if got == want {
				return
			}
		case <-deadline:
			t.Fatalf("timed out waiting for last-used touch of key %d; calls=%v", want, store.callsSnapshot())
		}
	}
}

func TestAuthRequiresBearerTokenInProduction(t *testing.T) {
	t.Parallel()

	store := &authStoreStub{}
	handler := Auth(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)), store, false)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/check", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	assertJSONErrorResponse(t, rec, http.StatusUnauthorized, "missing or invalid Authorization header")
	assertBearerChallenge(t, rec)
}

func TestAuthAcceptsValidBearerTokenInProduction(t *testing.T) {
	t.Parallel()

	store := &authStoreStub{
		keyHash: hashToken("secret-key"),
		apiKey: &auth.APIKeyCredential{
			ID:   1,
			Name: "test",
		},
	}
	handler := Auth(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)), store, false)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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

func TestAuthStoresAPIKeyIdentityInContext(t *testing.T) {
	t.Parallel()

	store := &authStoreStub{
		keyHash: hashToken("secret-key"),
		apiKey: &auth.APIKeyCredential{
			ID:   42,
			Name: "n8n-import",
		},
	}
	var seen APIKeyIdentity
	var ok bool
	handler := Auth(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)), store, false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen, ok = APIKeyIdentityFromContext(r.Context())
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/check", nil)
	req.Header.Set("Authorization", "Bearer secret-key")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
	if !ok {
		t.Fatal("APIKeyIdentityFromContext ok = false")
	}
	if seen.ID != 42 || seen.Name != "n8n-import" {
		t.Fatalf("API key identity = %+v, want id/name only", seen)
	}
}

func TestAuthBoundsAPIKeyLastUsedUpdates(t *testing.T) {
	store := newBlockingTouchStore()
	store.keyHash = hashToken("secret-key")
	store.apiKey = &auth.APIKeyCredential{
		ID:   1,
		Name: "ci",
	}
	defer store.closeRelease()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	handler := Auth(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)), store, false)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	for i := 0; i < 20; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/check", nil)
		req.Header.Set("Authorization", "Bearer secret-key")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("request %d status = %d, want %d", i, rec.Code, http.StatusNoContent)
		}
	}

	if store.started.Load() == 0 {
		select {
		case <-store.startedSignal:
		case <-time.After(5 * time.Second):
			t.Fatal("last-used updater did not start")
		}
	}

	if got := store.maxActive.Load(); got > 1 {
		t.Fatalf("concurrent TouchAPIKeyLastUsed calls = %d, want bounded worker concurrency <= 1", got)
	}
}

func TestAPIKeyLastUsedUpdaterThrottlesRepeatedKeys(t *testing.T) {
	now := time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)
	updater := &APIKeyLastUsedUpdater{
		logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		store:       &authStoreStub{},
		queue:       make(chan int, 4),
		lastQueued:  make(map[int]time.Time),
		minInterval: time.Hour,
		now: func() time.Time {
			return now
		},
	}

	if !updater.Enqueue(1) {
		t.Fatal("first Enqueue returned false, want queued")
	}
	if updater.Enqueue(1) {
		t.Fatal("second Enqueue returned true inside throttle window")
	}
	if !updater.Enqueue(2) {
		t.Fatal("different key Enqueue returned false")
	}
	if got := len(updater.queue); got != 2 {
		t.Fatalf("queued updates = %d, want 2", got)
	}

	if got := <-updater.queue; got != 1 {
		t.Fatalf("first queued key = %d, want 1", got)
	}
	if !updater.markDequeued(1) {
		t.Fatal("markDequeued(1) returned false")
	}
	updater.markSucceeded(context.Background(), 1)

	now = now.Add(time.Hour + time.Second)
	if !updater.Enqueue(1) {
		t.Fatal("Enqueue after throttle window returned false")
	}
	if got := len(updater.queue); got != 2 {
		t.Fatalf("queued updates after persisted window = %d, want 2", got)
	}
}

func TestAPIKeyLastUsedUpdaterRetainsUpdateWhenQueueIsFull(t *testing.T) {
	store := newControlledLastUsedStore()
	store.blockFirst = true

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	updater := newAPIKeyLastUsedUpdater(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)), store, 1, 1, time.Second)
	updater.minInterval = 0

	if !updater.Enqueue(1) {
		t.Fatal("Enqueue(1) returned false")
	}
	select {
	case <-store.firstStarted:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for first last-used touch to start; calls=%v", store.callsSnapshot())
	}

	if !updater.Enqueue(2) {
		t.Fatal("Enqueue(2) returned false")
	}
	if !updater.Enqueue(3) {
		t.Fatal("Enqueue(3) returned false after queue saturation; want retained pending update")
	}

	close(store.firstRelease)
	waitForLastUsedCall(t, store, 2)
	waitForLastUsedCall(t, store, 3)
}

func TestAPIKeyLastUsedUpdaterRetriesAfterTouchFailure(t *testing.T) {
	store := newControlledLastUsedStore()
	store.failNext(7, 1)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	updater := newAPIKeyLastUsedUpdater(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)), store, 1, 1, time.Second)
	updater.minInterval = 0
	updater.retryBackoff = time.Millisecond

	if !updater.Enqueue(7) {
		t.Fatal("Enqueue(7) returned false")
	}

	waitForLastUsedCall(t, store, 7)
	waitForLastUsedCall(t, store, 7)
}

func TestAPIKeyLastUsedUpdaterPrunesExpiredThrottleEntriesBeforeEnqueue(t *testing.T) {
	now := time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)
	updater := &APIKeyLastUsedUpdater{
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		store:  &authStoreStub{},
		queue:  make(chan int, 4),
		lastQueued: map[int]time.Time{
			1: now.Add(-2 * time.Hour),
			2: now.Add(-time.Hour),
			3: now.Add(-time.Hour + time.Nanosecond),
			4: now.Add(-30 * time.Minute),
		},
		minInterval: time.Hour,
		now: func() time.Time {
			return now
		},
	}

	if !updater.Enqueue(5) {
		t.Fatal("Enqueue returned false, want queued")
	}

	for _, keyID := range []int{1, 2} {
		if _, ok := updater.lastQueued[keyID]; ok {
			t.Fatalf("lastQueued retained expired key %d: %+v", keyID, updater.lastQueued)
		}
	}
	for _, keyID := range []int{3, 4, 5} {
		if _, ok := updater.lastQueued[keyID]; !ok {
			t.Fatalf("lastQueued missing retained key %d: %+v", keyID, updater.lastQueued)
		}
	}
	if got := len(updater.lastQueued); got != 3 {
		t.Fatalf("lastQueued len = %d, want 3 after pruning expired entries", got)
	}
}

func TestAuthRejectsExpiredBearerTokenInProduction(t *testing.T) {
	t.Parallel()

	expiredAt := time.Now().Add(-time.Minute)
	store := &authStoreStub{
		keyHash: hashToken("expired-key"),
		apiKey: &auth.APIKeyCredential{
			ID:        1,
			Name:      "expired-ci",
			ExpiresAt: &expiredAt,
		},
	}
	handler := Auth(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)), store, false)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/check", nil)
	req.Header.Set("Authorization", "Bearer expired-key")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	assertBearerChallenge(t, rec)
}

func TestAuthAllowsPublicDashboardInProduction(t *testing.T) {
	t.Parallel()

	store := &authStoreStub{}
	handler := Auth(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)), store, false)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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
	handler := Auth(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)), store, true)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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

func TestAuthRequiresAPIKeyForDevelopmentFeedImportFromForwardedNonLoopbackClient(t *testing.T) {
	t.Parallel()

	store := &authStoreStub{}
	handler := TrustedClientIP([]string{"127.0.0.1"})(Auth(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)), store, true)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/feeds/openssf/import", nil)
	req.RemoteAddr = "127.0.0.1:54321"
	req.Header.Set("X-Forwarded-For", "203.0.113.10")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	assertBearerChallenge(t, rec)
}

func TestAuthRequiresAPIKeyForDevelopmentFeedImportFromNonLoopback(t *testing.T) {
	t.Parallel()

	store := &authStoreStub{}
	handler := Auth(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)), store, true)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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
	assertBearerChallenge(t, rec)
}

func TestAuthRequiresAPIKeyForDevelopmentPackageRefreshFromNonLoopback(t *testing.T) {
	t.Parallel()

	store := &authStoreStub{}
	handler := Auth(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)), store, true)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/packages/npm/lodash/refresh", nil)
	req.RemoteAddr = "203.0.113.10:44444"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestAuthDevelopmentAllowsPackageDetailReadWithoutKey(t *testing.T) {
	t.Parallel()

	handler := Auth(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)), &authStoreStub{}, true)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/packages/npm/lodash", nil)
	req.RemoteAddr = "203.0.113.10:44444"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
}

func TestAuthRejectionLogUsesTrustedClientIPAndCorrelationID(t *testing.T) {
	t.Parallel()

	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	handler := TrustedClientIP([]string{"10.0.0.1"})(Correlation(Auth(context.Background(), logger, &authStoreStub{}, false)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))))

	rawPath := "/api/v1/packages/npm/C:%5CUsers%5CAdmin%5Csecret-token/refresh"
	req := httptest.NewRequest(http.MethodGet, rawPath, nil)
	req.RemoteAddr = "10.0.0.1:12345"
	req.Header.Set("X-Forwarded-For", "203.0.113.44, 10.0.0.1")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	logLine := logs.String()
	for _, want := range []string{`"level":"WARN"`, `"client_ip":"203.0.113.44"`, `"correlation_id":`, `"path":"/api/v1/packages/{ecosystem}/{name...}/refresh"`} {
		if !strings.Contains(logLine, want) {
			t.Fatalf("auth rejection log missing %s: %s", want, logLine)
		}
	}
	for _, leaked := range []string{`"remote_addr"`, "10.0.0.1:12345", "secret-token", "Users", "Admin"} {
		if strings.Contains(logLine, leaked) {
			t.Fatalf("auth rejection log leaked %q: %s", leaked, logLine)
		}
	}
}

func TestAuthRejectionLogIsVisibleAtDefaultLevel(t *testing.T) {
	t.Parallel()

	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	handler := TrustedClientIP([]string{"10.0.0.1"})(Correlation(Auth(context.Background(), logger, &authStoreStub{}, false)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/check", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	req.Header.Set("X-Forwarded-For", "203.0.113.44, 10.0.0.1")
	req.Header.Set("Authorization", "Bearer rejected-secret")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	logLine := logs.String()
	for _, want := range []string{`"level":"WARN"`, `"msg":"api key authentication failed"`, `"reason":"invalid"`, `"client_ip":"203.0.113.44"`, `"correlation_id":`, `"path":"/api/v1/check"`} {
		if !strings.Contains(logLine, want) {
			t.Fatalf("auth rejection log missing %s: %s", want, logLine)
		}
	}
	for _, leaked := range []string{"rejected-secret", `"remote_addr"`, "10.0.0.1:12345"} {
		if strings.Contains(logLine, leaked) {
			t.Fatalf("auth rejection log leaked %q: %s", leaked, logLine)
		}
	}
}

func TestAuthDevelopmentAllowsReadAPIWithoutKey(t *testing.T) {
	t.Parallel()

	handler := Auth(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)), &authStoreStub{}, true)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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
		handler := Auth(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)), &authStoreStub{}, false)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))
		req := httptest.NewRequest(http.MethodPost, "/api/v1/check", nil)
		req.Header.Set("Authorization", "Bearer wrong")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}
		assertBearerChallenge(t, rec)
	})

	t.Run("lookup error", func(t *testing.T) {
		t.Parallel()
		handler := Auth(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)), &authStoreStub{err: errors.New("db down")}, false)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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

func assertBearerChallenge(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	if got := rec.Header().Get("WWW-Authenticate"); got != `Bearer realm="packmon-api"` {
		t.Fatalf("WWW-Authenticate = %q, want Bearer challenge", got)
	}
}

func TestAuthHelpers(t *testing.T) {
	t.Parallel()

	if len(skipAuth) != 0 {
		t.Fatalf("skipAuth = %#v, want no placeholder paths inside /api/v1", skipAuth)
	}
	if !requiresAuthInDev(http.MethodPost, "/api/v1/feeds/osv/import") {
		t.Fatal("feeds import should require auth in dev from non-loopback peers")
	}
	if !requiresAuthInDev(http.MethodPost, "/api/v1/packages/npm/lodash/refresh") {
		t.Fatal("package refresh should require auth in dev from non-loopback peers")
	}
	if requiresAuthInDev(http.MethodGet, "/api/v1/packages/npm/lodash") {
		t.Fatal("package detail should not require auth in dev")
	}
	if requiresAuthInDev(http.MethodGet, "/api/v1/packages/npm/lodash/refresh") {
		t.Fatal("package refresh GET should not require dev write auth")
	}
	if requiresAuthInDev(http.MethodPost, "/api/v1/check") {
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
