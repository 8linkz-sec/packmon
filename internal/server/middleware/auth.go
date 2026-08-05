package middleware

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/8linkz-sec/packmon/internal/auth"
	"github.com/8linkz-sec/packmon/internal/logsafe"
	"github.com/8linkz-sec/packmon/internal/netutil"
	"github.com/8linkz-sec/packmon/internal/requestctx"
)

const (
	apiKeyLastUsedQueueSize    = 128
	apiKeyLastUsedWorkers      = 1
	apiKeyLastUsedTimeout      = 2 * time.Second
	apiKeyLastUsedInterval     = 5 * time.Minute
	apiKeyLastUsedBackoff      = time.Second
	apiKeyLastUsedPendingLimit = apiKeyLastUsedQueueSize * 8
)

// skipAuth lists API path prefixes that never require an API key. Public web,
// health, metrics, admin, and well-known routes are outside /api/v1/ and are
// handled before API-key auth reaches this middleware.
var skipAuth []string

// devAuthRule describes a data-mutating API route shape that must not be
// exposed unauthenticated to a network even in development mode.
type devAuthRule struct {
	method string
	prefix string
	suffix string
}

// requireAuthEvenInDev lists API paths that are data-mutating and must not be
// exposed unauthenticated to a network. In development mode they remain
// reachable without an API key, but only from a loopback peer (local
// integration tests); a non-loopback caller still needs a valid key.
var requireAuthEvenInDev = []devAuthRule{
	{prefix: "/api/v1/feeds/"},
	{method: http.MethodPost, prefix: "/api/v1/packages/", suffix: "/refresh"},
}

// APIKeyIdentity is the non-sensitive authenticated API-key metadata exposed
// to handlers for audit attribution.
type APIKeyIdentity = requestctx.APIKeyIdentity

// ContextWithAPIKeyIdentity stores non-sensitive API-key metadata in ctx.
var ContextWithAPIKeyIdentity = requestctx.ContextWithAPIKeyIdentity

// APIKeyIdentityFromContext returns authenticated API-key metadata when the
// request passed through API-key authentication.
var APIKeyIdentityFromContext = requestctx.APIKeyIdentityFromContext

// APIKeyLookupStore is the persistence surface needed to authenticate API
// keys.
type APIKeyLookupStore interface {
	FindAPIKeyCredentialByHash(ctx context.Context, keyHash string) (*auth.APIKeyCredential, error)
}

// APIKeyLastUsedStore is the persistence surface needed for best-effort
// last-used writes after successful authentication.
type APIKeyLastUsedStore interface {
	TouchAPIKeyLastUsed(ctx context.Context, keyID int) error
}

// APIKeyStore is the complete middleware-owned API-key auth persistence
// boundary.
type APIKeyStore interface {
	APIKeyLookupStore
	APIKeyLastUsedStore
}

// Auth validates the Bearer token in the Authorization header against hashed
// API keys stored in the database. Only /api/v1/* endpoints are protected.
// Public web pages and admin routes remain reachable without an API key.
//
// In development mode, auth is skipped for most /api/v1/* routes so local
// testing does not require key provisioning. Feed import and package refresh
// writes remain unauthenticated only from loopback peers; non-loopback callers
// still need a valid API key.
func Auth(ctx context.Context, logger *slog.Logger, store APIKeyStore, devMode bool) func(http.Handler) http.Handler {
	updater := NewAPIKeyLastUsedUpdater(ctx, logger, store)
	return AuthWithLastUsedUpdater(logger, store, devMode, updater)
}

type apiKeyLastUsedUpdater interface {
	Enqueue(keyID int) bool
}

// AuthWithLastUsedUpdater is Auth with an injected last-used updater. Tests use
// it to exercise auth behavior without starting background updater workers.
func AuthWithLastUsedUpdater(logger *slog.Logger, store APIKeyLookupStore, devMode bool, updater apiKeyLastUsedUpdater) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !strings.HasPrefix(r.URL.Path, "/api/v1/") {
				next.ServeHTTP(w, r)
				return
			}

			// Skip auth for exempt paths.
			for _, prefix := range skipAuth {
				if strings.HasPrefix(r.URL.Path, prefix) {
					next.ServeHTTP(w, r)
					return
				}
			}

			// Development mode is intentionally unauthenticated for most API
			// routes so local integration tests can run without provisioning
			// keys. Data-mutating feed import and package refresh endpoints are
			// allowed without a key only from a loopback peer, so a dev-mode
			// server accidentally exposed on a network does not offer
			// unauthenticated writes.
			if devMode {
				if !requiresAuthInDev(r.Method, r.URL.Path) || netutil.IsLoopbackHost(ClientIP(r)) {
					next.ServeHTTP(w, r)
					return
				}
			}

			token := extractBearerToken(r)
			if token == "" {
				logAPIKeyAuthFailure(logger, r, "missing")
				writeAuthJSONError(w, http.StatusUnauthorized, "missing or invalid Authorization header")
				return
			}

			keyHash := hashToken(token)
			apiKey, err := store.FindAPIKeyCredentialByHash(r.Context(), keyHash)
			if err != nil {
				logger.Error("api key lookup failed",
					append(authRejectionLogAttrs(r), slog.String("error", err.Error()))...,
				)
				writeJSONError(w, http.StatusInternalServerError, "internal server error")
				return
			}
			if apiKey == nil {
				logAPIKeyAuthFailure(logger, r, "invalid")
				writeAuthJSONError(w, http.StatusUnauthorized, "invalid api key")
				return
			}
			if apiKey.IsExpired(time.Now().UTC()) {
				logAPIKeyAuthFailure(logger, r, "expired")
				writeAuthJSONError(w, http.StatusUnauthorized, "invalid api key")
				return
			}

			if updater != nil {
				updater.Enqueue(apiKey.ID)
			}

			ctx := ContextWithAPIKeyIdentity(r.Context(), APIKeyIdentity{
				ID:   apiKey.ID,
				Name: apiKey.Name,
			})
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func logAPIKeyAuthFailure(logger *slog.Logger, r *http.Request, reason string) {
	logger.Warn("api key authentication failed",
		append(authRejectionLogAttrs(r), slog.String("reason", reason))...,
	)
}

func writeAuthJSONError(w http.ResponseWriter, status int, message string) {
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Bearer realm="packmon-api"`)
	}
	writeJSONError(w, status, message)
}

func authRejectionLogAttrs(r *http.Request) []any {
	return []any{
		slog.String("path", logsafe.RequestPathLabel(r.URL.Path)),
		slog.String("client_ip", ClientIP(r)),
		slog.String("correlation_id", CorrelationIDFromContext(r.Context())),
	}
}

// APIKeyLastUsedUpdater performs best-effort API-key last-used writes through
// a bounded worker queue and coalesced per-key pending state. It prevents
// authenticated request volume from spawning unbounded detached goroutines when
// the database stalls while keeping queue-saturated or transiently failed
// updates retryable.
type APIKeyLastUsedUpdater struct {
	logger       *slog.Logger
	store        APIKeyLastUsedStore
	queue        chan int
	mu           sync.Mutex
	lastQueued   map[int]time.Time
	pending      map[int]*apiKeyLastUsedPending
	minInterval  time.Duration
	retryBackoff time.Duration
	pendingLimit int
	now          func() time.Time
}

type apiKeyLastUsedPending struct {
	queued         bool
	inFlight       bool
	retryAfter     time.Time
	retryScheduled bool
}

// NewAPIKeyLastUsedUpdater starts the bounded updater workers.
func NewAPIKeyLastUsedUpdater(ctx context.Context, logger *slog.Logger, store APIKeyLastUsedStore) *APIKeyLastUsedUpdater {
	return newAPIKeyLastUsedUpdater(ctx, logger, store, apiKeyLastUsedQueueSize, apiKeyLastUsedWorkers, apiKeyLastUsedTimeout)
}

func newAPIKeyLastUsedUpdater(ctx context.Context, logger *slog.Logger, store APIKeyLastUsedStore, queueSize, workers int, timeout time.Duration) *APIKeyLastUsedUpdater {
	if ctx == nil {
		ctx = context.Background()
	}
	if logger == nil {
		logger = slog.Default()
	}
	if queueSize <= 0 {
		queueSize = 1
	}
	if workers <= 0 {
		workers = 1
	}
	if timeout <= 0 {
		timeout = apiKeyLastUsedTimeout
	}
	u := &APIKeyLastUsedUpdater{
		logger:       logger,
		store:        store,
		queue:        make(chan int, queueSize),
		lastQueued:   make(map[int]time.Time),
		pending:      make(map[int]*apiKeyLastUsedPending),
		minInterval:  apiKeyLastUsedInterval,
		retryBackoff: apiKeyLastUsedBackoff,
		pendingLimit: apiKeyLastUsedPendingLimit,
		now:          time.Now,
	}
	for range workers {
		go u.run(ctx, timeout)
	}
	return u
}

// Enqueue schedules or coalesces a best-effort last-used write. It returns
// false only when the update is invalid, throttled by the debounce window, or
// cannot be retained in bounded pending state.
func (u *APIKeyLastUsedUpdater) Enqueue(keyID int) bool {
	if u == nil || u.store == nil || keyID <= 0 {
		return false
	}
	now := u.currentTime()
	u.mu.Lock()
	defer u.mu.Unlock()
	u.ensureStateLocked()
	if u.lastQueued == nil {
		u.lastQueued = make(map[int]time.Time)
	}
	if u.minInterval > 0 {
		for queuedKeyID, queuedAt := range u.lastQueued {
			if now.Sub(queuedAt) >= u.minInterval {
				delete(u.lastQueued, queuedKeyID)
			}
		}
		if last, ok := u.lastQueued[keyID]; ok && now.Sub(last) < u.minInterval {
			return false
		}
	}
	pending, ok := u.pending[keyID]
	if !ok {
		if u.pendingLimit > 0 && len(u.pending) >= u.pendingLimit {
			u.logger.Warn("api key last-used pending buffer full; update not retained",
				slog.Int("api_key_id", keyID),
				slog.Int("pending_count", len(u.pending)),
				slog.Int("pending_limit", u.pendingLimit),
			)
			return false
		}
		pending = &apiKeyLastUsedPending{}
		u.pending[keyID] = pending
	}
	if u.minInterval > 0 {
		u.lastQueued[keyID] = now
	}
	u.schedulePendingLocked(keyID, pending, now)
	return true
}

func (u *APIKeyLastUsedUpdater) ensureStateLocked() {
	if u.queue == nil {
		u.queue = make(chan int, 1)
	}
	if u.lastQueued == nil {
		u.lastQueued = make(map[int]time.Time)
	}
	if u.pending == nil {
		u.pending = make(map[int]*apiKeyLastUsedPending)
	}
	if u.retryBackoff <= 0 {
		u.retryBackoff = apiKeyLastUsedBackoff
	}
	if u.pendingLimit <= 0 {
		u.pendingLimit = apiKeyLastUsedPendingLimit
	}
}

func (u *APIKeyLastUsedUpdater) schedulePendingLocked(keyID int, pending *apiKeyLastUsedPending, now time.Time) bool {
	if pending == nil || pending.queued || pending.inFlight {
		return true
	}
	if !pending.retryAfter.IsZero() {
		if now.Before(pending.retryAfter) {
			return false
		}
		pending.retryAfter = time.Time{}
	}
	select {
	case u.queue <- keyID:
		pending.queued = true
		pending.retryScheduled = false
		return true
	default:
		u.logger.Warn("api key last-used update queue saturated; retaining pending update",
			slog.Int("api_key_id", keyID),
			slog.Int("queue_depth", len(u.queue)),
			slog.Int("queue_capacity", cap(u.queue)),
			slog.Int("pending_count", len(u.pending)),
		)
		return false
	}
}

func (u *APIKeyLastUsedUpdater) currentTime() time.Time {
	if u.now == nil {
		return time.Now()
	}
	return u.now()
}

func (u *APIKeyLastUsedUpdater) run(ctx context.Context, timeout time.Duration) {
	for {
		select {
		case <-ctx.Done():
			return
		case keyID := <-u.queue:
			if !u.markDequeued(keyID) {
				continue
			}
			updateCtx, cancel := context.WithTimeout(ctx, timeout)
			err := u.store.TouchAPIKeyLastUsed(updateCtx, keyID)
			cancel()
			if err != nil {
				if errors.Is(err, context.Canceled) && ctx.Err() != nil {
					u.markSucceeded(ctx, keyID)
					continue
				}
				u.markFailed(ctx, keyID, err)
				continue
			}
			u.markSucceeded(ctx, keyID)
		}
	}
}

func (u *APIKeyLastUsedUpdater) markDequeued(keyID int) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.ensureStateLocked()
	pending := u.pending[keyID]
	if pending == nil {
		return false
	}
	pending.queued = false
	pending.inFlight = true
	return true
}

func (u *APIKeyLastUsedUpdater) markSucceeded(ctx context.Context, keyID int) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.ensureStateLocked()
	delete(u.pending, keyID)
	u.scheduleReadyPendingLocked(ctx, u.currentTime())
}

func (u *APIKeyLastUsedUpdater) markFailed(ctx context.Context, keyID int, err error) {
	now := u.currentTime()
	u.mu.Lock()
	defer u.mu.Unlock()
	u.ensureStateLocked()
	pending := u.pending[keyID]
	if pending == nil {
		if u.pendingLimit > 0 && len(u.pending) >= u.pendingLimit {
			u.logger.Warn("api key last-used retry state full; update not retained",
				slog.Int("api_key_id", keyID),
				slog.String("error", err.Error()),
				slog.Int("pending_count", len(u.pending)),
				slog.Int("pending_limit", u.pendingLimit),
			)
			return
		}
		pending = &apiKeyLastUsedPending{}
		u.pending[keyID] = pending
	}
	pending.retryAfter = now.Add(u.retryBackoff)
	pending.inFlight = false
	u.logger.Warn("api key last-used update failed; scheduled retry",
		slog.Int("api_key_id", keyID),
		slog.String("error", err.Error()),
		slog.Duration("retry_backoff", u.retryBackoff),
		slog.Int("pending_count", len(u.pending)),
	)
	u.scheduleRetryLocked(ctx, keyID, pending, u.retryBackoff)
	u.scheduleReadyPendingLocked(ctx, now)
}

func (u *APIKeyLastUsedUpdater) scheduleReadyPendingLocked(ctx context.Context, now time.Time) {
	for keyID, pending := range u.pending {
		if pending == nil || pending.queued {
			continue
		}
		if !pending.retryAfter.IsZero() && now.Before(pending.retryAfter) {
			u.scheduleRetryLocked(ctx, keyID, pending, pending.retryAfter.Sub(now))
			continue
		}
		if !u.schedulePendingLocked(keyID, pending, now) {
			return
		}
	}
}

func (u *APIKeyLastUsedUpdater) scheduleRetryLocked(ctx context.Context, keyID int, pending *apiKeyLastUsedPending, delay time.Duration) {
	if pending == nil || pending.retryScheduled {
		return
	}
	if delay < 0 {
		delay = 0
	}
	pending.retryScheduled = true
	time.AfterFunc(delay, func() {
		select {
		case <-ctx.Done():
			return
		default:
		}
		now := u.currentTime()
		u.mu.Lock()
		defer u.mu.Unlock()
		u.ensureStateLocked()
		pending := u.pending[keyID]
		if pending == nil {
			return
		}
		pending.retryScheduled = false
		if !pending.retryAfter.IsZero() && now.Before(pending.retryAfter) {
			u.scheduleRetryLocked(ctx, keyID, pending, pending.retryAfter.Sub(now))
			return
		}
		u.schedulePendingLocked(keyID, pending, now)
	})
}

// requiresAuthInDev reports whether the given path is a sensitive write
// endpoint that must not be served unauthenticated to a non-loopback peer
// even in development mode.
func requiresAuthInDev(method, path string) bool {
	for _, rule := range requireAuthEvenInDev {
		if rule.method != "" && method != rule.method {
			continue
		}
		if !strings.HasPrefix(path, rule.prefix) {
			continue
		}
		if rule.suffix != "" && !strings.HasSuffix(path, rule.suffix) {
			continue
		}
		if rule.prefix != "" {
			return true
		}
	}
	return false
}

// extractBearerToken pulls the token from "Authorization: Bearer <token>".
func extractBearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if h == "" {
		return ""
	}
	const prefix = "Bearer "
	if !strings.HasPrefix(h, prefix) {
		return ""
	}
	return strings.TrimSpace(h[len(prefix):])
}

// hashToken returns the hex-encoded SHA-256 hash of a raw API key.
// Keys are stored hashed in the database so that a DB leak does not
// expose usable credentials.
func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}
