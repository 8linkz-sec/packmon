// Package health provides liveness and readiness checks for the
// Packmon server. /healthz always returns 200 (process is alive).
// /readyz verifies that the database is reachable and returns 200
// or 503 accordingly.
package health

import (
	"context"
	"encoding/json"
	"net/http"
	"sync/atomic"
	"time"
)

// Pinger is satisfied by any database pool that supports Ping.
type Pinger interface {
	Ping(ctx context.Context) error
}

// Checker aggregates health signals.
type Checker struct {
	db           Pinger
	shuttingDown atomic.Bool
}

// NewChecker creates a Checker that probes the given database.
func NewChecker(db Pinger) *Checker {
	return &Checker{db: db}
}

// SetShuttingDown marks the server as shutting down. Once called,
// ReadyHandler will return 503 to stop receiving new traffic.
func (c *Checker) SetShuttingDown() {
	c.shuttingDown.Store(true)
}

// LiveHandler returns 200 with {"status":"ok"}. It indicates that the
// process is alive and able to serve HTTP.
func (c *Checker) LiveHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}

// ReadyHandler returns 200 when the database is reachable, or 503
// otherwise. Orchestrators and load balancers can use this to decide
// whether to route traffic to the server.
func (c *Checker) ReadyHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if c.shuttingDown.Load() {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{
				"status": "unavailable",
				"reason": "shutting down",
			})
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()

		if err := c.db.Ping(ctx); err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{
				"status": "unavailable",
				"reason": "database unreachable",
			})
			return
		}

		writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
