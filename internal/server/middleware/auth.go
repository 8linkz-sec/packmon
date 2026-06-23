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

	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/logsafe"
	"github.com/8linkz-sec/packmon/internal/requestctx"
)

const (
	apiKeyLastUsedQueueSize = 128
	apiKeyLastUsedWorkers   = 1
	apiKeyLastUsedTimeout   = 2 * time.Second
	apiKeyLastUsedInterval  = 5 * time.Minute
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
	FindAPIKeyByHash(ctx context.Context, keyHash string) (*db.APIKey, error)
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
// In development mode, auth is skipped entirely so that local testing
// does not require key provisioning.
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

			// Development mode is intentionally unauthenticated so local
			// integration tests can run without provisioning API keys. Data-
			// mutating write endpoints (feed import) are an exception: in dev
			// mode they are allowed without a key only from a loopback peer,
			// so a dev-mode server accidentally exposed on a network does not
			// offer unauthenticated writes.
			if devMode {
				if !requiresAuthInDev(r.Method, r.URL.Path) || isLoopbackHost(r.RemoteAddr) {
					next.ServeHTTP(w, r)
					return
				}
				logger.Debug("dev-mode write endpoint requires auth from non-loopback peer", authRejectionLogAttrs(r)...)
			}

			token := extractBearerToken(r)
			if token == "" {
				logger.Debug("missing api key", authRejectionLogAttrs(r)...)
				writeAuthJSONError(w, http.StatusUnauthorized, "missing or invalid Authorization header")
				return
			}

			keyHash := hashToken(token)
			apiKey, err := store.FindAPIKeyByHash(r.Context(), keyHash)
			if err != nil {
				logger.Error("api key lookup failed",
					slog.String("error", err.Error()),
					slog.String("correlation_id", CorrelationIDFromContext(r.Context())),
				)
				writeJSONError(w, http.StatusInternalServerError, "internal server error")
				return
			}
			if apiKey == nil {
				logger.Debug("invalid api key", authRejectionLogAttrs(r)...)
				writeAuthJSONError(w, http.StatusUnauthorized, "invalid api key")
				return
			}
			if apiKey.IsExpired(time.Now().UTC()) {
				logger.Debug("expired api key", authRejectionLogAttrs(r)...)
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
// a bounded worker queue. It prevents authenticated request volume from
// spawning unbounded detached goroutines when the database stalls.
type APIKeyLastUsedUpdater struct {
	logger      *slog.Logger
	store       APIKeyLastUsedStore
	queue       chan int
	mu          sync.Mutex
	lastQueued  map[int]time.Time
	minInterval time.Duration
	now         func() time.Time
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
		logger:      logger,
		store:       store,
		queue:       make(chan int, queueSize),
		lastQueued:  make(map[int]time.Time),
		minInterval: apiKeyLastUsedInterval,
		now:         time.Now,
	}
	for range workers {
		go u.run(ctx, timeout)
	}
	return u
}

// Enqueue schedules a best-effort last-used write. It returns false when the
// bounded queue is full and the update was dropped.
func (u *APIKeyLastUsedUpdater) Enqueue(keyID int) bool {
	if u == nil || u.store == nil || keyID <= 0 {
		return false
	}
	now := u.currentTime()
	u.mu.Lock()
	if u.lastQueued == nil {
		u.lastQueued = make(map[int]time.Time)
	}
	if u.minInterval > 0 {
		if last, ok := u.lastQueued[keyID]; ok && now.Sub(last) < u.minInterval {
			u.mu.Unlock()
			return false
		}
	}
	select {
	case u.queue <- keyID:
		if u.minInterval > 0 {
			u.lastQueued[keyID] = now
		}
		u.mu.Unlock()
		return true
	default:
		u.mu.Unlock()
		u.logger.Warn("api key last-used update queue full; dropping update",
			slog.Int("api_key_id", keyID),
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
			updateCtx, cancel := context.WithTimeout(ctx, timeout)
			err := u.store.TouchAPIKeyLastUsed(updateCtx, keyID)
			cancel()
			if err != nil && !errorsIsContextDone(err) {
				u.logger.Warn("api key last-used update failed",
					slog.Int("api_key_id", keyID),
					slog.String("error", err.Error()),
				)
			}
		}
	}
}

func errorsIsContextDone(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
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
